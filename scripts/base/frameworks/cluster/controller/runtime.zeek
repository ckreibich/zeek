@load base/frameworks/broker

@load base/frameworks/cluster/controller/api
@load base/frameworks/cluster/controller/log
@load base/frameworks/cluster/controller/request

@load base/frameworks/cluster/agent/config
@load base/frameworks/cluster/agent/api

redef ClusterController::role = ClusterController::Types::CONTROLLER;

global node_map: table[string] of ClusterController::Types::Node
    &broker_allow_complex_type &backend=Broker::SQLITE;

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	# See if we already know about this agent; if not, register
	# it.
	#
	# XXX protection against rogue agents?

	if ( instance in ClusterController::instances )
		{
		# Do nothing, unless this known agent checks in with a mismatching
		# API version, in which case we kick it out.
		if ( api_version != ClusterController::API::version )
			{
			local inst = ClusterController::instances[instance];
			if ( inst?$listen_port )
				{
				# We peered with this instance, unpeer.
				Broker::unpeer(cat(inst$host), inst$listen_port );
				# XXX what to do if they connected to us?
				}
			delete ClusterController::instances[instance];
			}

		return;
		}

	if ( api_version != ClusterController::API::version )
		{
		ClusterController::Log::warning(
		    fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s), unpeering",
		        instance, host, api_version, ClusterController::API::version));
		}

	ClusterController::instances[instance] = ClusterController::Types::Instance($name=instance, $host=host);
	ClusterController::Log::info(fmt("instance %s/%s has checked in", instance, host));

	print("WAHOO!");
	}


event ClusterAgent::API::notify_change(instance: string, n: ClusterController::Types::Node,
    old: ClusterController::Types::State, new: ClusterController::Types::State)
	{
	}

event ClusterAgent::notify_error(instance: string, msg: string,
    n: ClusterController::Types::Node)
	{
	}

event ClusterAgent::notify_log(instance: string, msg: string,
    n: ClusterController::Types::Node)
	{
	}

event ClusterAgent::API::set_nodes_response(reqid: string, results: ClusterController::Types::ResultVec)
	{
	local areq = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(areq) )
		return;

	areq$results = results;
	areq$finished = T;

	local req = ClusterController::Request::lookup(areq$parent_id);
	if ( ClusterController::Request::is_null(req) )
		return;

	for ( i in req$set_nodes_state$requests )
		if ( ! req$set_nodes_state$requests[i]$finished )
			return;

	# All set_nodes requests to instances are done, so respond
        # back to client. We need to compose the result, aggregating
        # the results we got from the requests to the agents. In the
        # end we have one Result per instance requested in the
        # original set_configuration_request.
	for ( i in req$set_nodes_state$requests )
		{
		local r = req$set_nodes_state$requests[i];

		local success = T;
		local errors: string_vec;
		local instance = "";

		for ( j in r$results )
			{
			local res = r$results[j];
			instance = res$instance;

			if ( res$success )
				next;

			success = F;
			errors += fmt("node %s failed: %s", res$node, res$error);
			}

		req$results += ClusterController::Types::Result(
		    $reqid = req$id,
		    $instance = instance,
		    $success = success,
		    $error = join_string_vec(errors, ", ")
		);

		ClusterController::Request::finish(r$id);
		}

	event ClusterController::API::set_configuration_response(req$id, req$results);
	ClusterController::Request::finish(req$id);
	}

event ClusterController::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	local req = ClusterController::Request::create(reqid);
	req$set_nodes_state = ClusterController::Request::SetNodesState();

	local node_map_new: table[string] of ClusterController::Types::Node;

	# Compare new configuration to the current one and send updates
	# to the instances as needed.
	for ( inst in config$instances )
		{
		if ( inst$name !in ClusterController::instances )
			{
			# We treat this as an error. The agent/
                        # controller relationships and identities are
                        # currently predefined, so an instance that's
                        # not known at this point cannot be reasoned
                        # about.
			local res = ClusterController::Types::Result($reqid=reqid, $instance=inst$name);
			res$error = fmt("instance %s is unknown, skipping", inst$name);
			req$results += res;
			next;
			}

		# All nodes that are part of the instance we're considering in this
		# loop iteration:
		local inst_nodes: set[ClusterController::Types::Node];

		for ( node in config$nodes )
			if ( node$instance == inst$name )
				add inst_nodes[node];

		# If the request sets any nodes for this instance,
		# send off the event to its agent.
		if ( |inst_nodes| == 0 )
			next;

		local areq = ClusterController::Request::create();
		areq$parent_id = reqid;
		req$set_nodes_state$requests += areq;

		local agent_topic = ClusterAgent::topic_prefix + "/" + inst$name;

		# Send set_nodes to this specific instance
		Broker::publish(agent_topic, ClusterAgent::API::set_nodes_request,
				areq$id, inst_nodes);

		for ( node in inst_nodes )
			node_map_new[node$name] = node;
		}

	# Update our persisted node map:
	node_map = node_map_new;
	}

event ClusterController::API::get_instances_request(reqid: string)
	{
	local insts: vector of ClusterController::Types::Instance;

	for ( i in ClusterController::instances )
		insts += ClusterController::instances[i];

	event ClusterController::API::get_instances_response(reqid, insts);
	}

event zeek_init()
	{
	# Controller always listens -- it needs to be able to respond
	# to the Zeek client. This port is also used by the agents
	# if they connect to the client.
	local cni = ClusterController::network_info();
	Broker::listen(cat(cni$address), cni$bound_port);

	Broker::subscribe(ClusterAgent::topic_prefix);
	Broker::subscribe(ClusterController::topic);

	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::get_instances_response);
	Broker::auto_publish(ClusterController::topic,
	    ClusterController::API::set_configuration_response);

	if ( |ClusterController::instances| > 0 )
		{
		# We peer with the agents.
		for ( i in ClusterController::instances )
			{
			local inst = ClusterController::instances[i];

			if ( ! inst?$listen_port )
				{
				# XXX config error -- this must be there
				next;
				}

			Broker::peer(cat(inst$host), inst$listen_port,
				     ClusterController::connect_retry);
			}
		}

	# If ClusterController::instances is empty, agents peer with
	# us and we do nothing. We'll build up state as the
	# notify_agent_hello() events come int.

	ClusterController::Log::info("controller is live");
	}
