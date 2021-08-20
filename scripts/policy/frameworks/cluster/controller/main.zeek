@load base/frameworks/broker

@load policy/frameworks/cluster/agent/config
@load policy/frameworks/cluster/agent/api

@load ./api
@load ./log
@load ./request

redef ClusterController::role = ClusterController::Types::CONTROLLER;

event ClusterAgent::API::notify_agent_hello(instance: string, address: addr, api_version: count)
	{
	if ( instance in ClusterController::instances )
		{
		# This is an instance we previously knew about in our local config.
		# Do nothing, unless this known agent checks in with a mismatching
		# API version, in which case we kick it out.
		if ( api_version != ClusterController::API::version )
			{
			ClusterController::Log::warning(
			    fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s), unpeering",
			        instance, address, api_version, ClusterController::API::version));

			local inst = ClusterController::instances[instance];
			if ( inst?$listen_port )
				{
				# We peered with this instance, unpeer.
				Broker::unpeer(inst$host, inst$listen_port );
				# XXX what to do if they connected to us?
				}

			delete ClusterController::instances[instance];
			}

		# Update the instance name in the pointed-to record, in case it
		# was previously named otherwise. Not being too picky here allows
		# the user some leeway in spelling out the original config.
		ClusterController::instances[instance]$name = instance;

		# Update the address, now that we've received one.
		# XXX can the agent reliably report a useful (i.e., reacheable) IP address?
		ClusterController::instances[instance]$address = address;

		return;
		}
	else
		{
		# This is a new instance we didn't yet know about.
		# XXX could optionally reject any instances unknown to us by name here.
		# XXX protection against rogue agents? Authentication?
		if ( api_version != ClusterController::API::version )
			{
			ClusterController::Log::warning(
			    fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s), ignoring",
			        instance, address, api_version, ClusterController::API::version));
			return;
			}
		}

	ClusterController::instances[instance] = [$name=instance, $host=cat(address), $address=address];
	ClusterController::Log::info(fmt("new instance %s/%s has checked in", instance, address));
	}


event ClusterAgent::API::notify_change(instance: string, n: ClusterController::Types::Node,
				       old: ClusterController::Types::State,
				       new: ClusterController::Types::State)
	{
	# XXX TODO
	}

event ClusterAgent::API::notify_error(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event ClusterAgent::API::notify_log(instance: string, msg: string, node: string)
	{
	# XXX TODO
	}

event ClusterAgent::API::set_configuration_response(reqid: string, result: ClusterController::Types::Result)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::set_configuration_response %s", reqid));

	# Retrieve state for the request we just got a response to
	local areq = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(areq) )
		return;

	# Record the result and mark the request as done. This also
	# marks the request as done in the parent-level request, since
	# these records are stored by reference.
	areq$results[0] = result; # We only have a single result here atm
	areq$finished = T;

	# Update the original request from the client:
	local req = ClusterController::Request::lookup(areq$parent_id);
	if ( ClusterController::Request::is_null(req) )
		return;

	# If there are any requests to the agents still unfinished,
	# we're not done yet.
	for ( i in req$set_configuration_state$requests )
		if ( ! req$set_configuration_state$requests[i]$finished )
			return;

	# All set_configuration requests to instances are done, so respond
        # back to client. We need to compose the result, aggregating
        # the results we got from the requests to the agents. In the
        # end we have one Result per instance requested in the
        # original set_configuration_request.
	#
	# XXX we can likely generalize result aggregation in the request module.
	for ( i in req$set_configuration_state$requests )
		{
		local r = req$set_configuration_state$requests[i];

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

	ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s", req$id));
	event ClusterController::API::set_configuration_response(req$id, req$results);
	ClusterController::Request::finish(req$id);
	}

function resolve_instances(instances: ClusterController::Types::InstanceVec): ClusterController::Types::InstanceVec
	{
	local pending_lookups = 0;

	# Establish IP addresses for each instance's agent. Several possibilities here:
	for ( i in instances )
		{
		local inst = instances[i];

		# - IP addresses are already resolved and provided by client: nothing to do.
		if ( inst?$address )
			{
			ClusterController::Log::info(fmt("Instance %s agent has address (%s)", inst$name, inst$address));
			next;
			}

		# - IP addresses provided in text form, so just transform to address:
		if ( is_valid_ip(inst$host) )
			{
			inst$address = to_addr(inst$host);
			ClusterController::Log::info(fmt("Instance %s agent hostname is address (%s)", inst$name, inst$address));
			next;
			}

		# - We need to look up the address, asynchronously.
		++pending_lookups;

		when ( local addrs = lookup_hostname(inst$host) )
			{
			for ( a in addrs ) # We'll use any returned address
				{
				inst$address = a;
				ClusterController::Log::info(fmt("Instance %s agent hostname %s resolved to %s",
				                                 inst$name, inst$host, inst$address));
				--pending_lookups;
				break;
				}
			}
		timeout 5sec
			{
			--pending_lookups;
			}
		}

	return when ( pending_lookups == 0 )
		{
		# We return the entirety of the modified config record to work around
		# pass-by-value issues for asynchronous functions.
		return instances;
		}
	}

function send_config_to_agents(req: ClusterController::Request::Request,
                               config: ClusterController::Types::Configuration)
	{
	for ( name in ClusterController::instances )
		{
		local agent_topic = ClusterAgent::topic_prefix + "/" + name;
		local areq = ClusterController::Request::create();
		areq$parent_id = req$id;

		# We track the requests sent off to each agent. As the
		# responses come in, we can check them off as completed,
		# and once all are, we respond back to the client.
		req$set_configuration_state$requests += areq;

		# XXX could also broadcast just once on the agent prefix, but
		# explicit request/response pairs for each agent seems cleaner.
		ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_request %s to %s", areq$id, name));
		Broker::publish(agent_topic, ClusterAgent::API::set_configuration_request, areq$id, config);
		}
	}

event ClusterController::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	local agent_topic: string;
	local req: ClusterController::Request::Request;
	local name: string;
	local inst: ClusterController::Types::Instance;
	local insts: ClusterController::Types::InstanceVec;

	ClusterController::Log::info(fmt("rx ClusterController::API::set_configuration_request %s", reqid));

	req = ClusterController::Request::create(reqid);
	req$set_configuration_state = ClusterController::Request::SetConfigurationState();

	if ( ! config?$instances )
		{
		# Without a new instance configuration, we fill in the instance knowledge
		# we have and send the new cluster layout on to the existing agents.
		#
		# Response event gets sent via the agents' reponse event handler, above.
		config$instances = set();
		for ( name, inst in ClusterController::instances )
			add config$instances[inst];
		send_config_to_agents(req, config);
		return;
		}

	for ( inst in config$instances )
		insts[|insts|] = inst;

	when ( local insts_res = resolve_instances(insts) )
		{
		for ( i in insts_res )
			{
			inst = insts_res[i];
			if ( ! inst?$address )
				{
				local res = ClusterController::Types::Result($reqid=reqid, $instance=inst$name);
				res$error = fmt("instance %s hostname %s did not resolve, skipping",
				                inst$name, inst$host);
				req$results += res;
				}
			}

		# XXX validate the configuration:
		# - Are all names unique?
		# - Do all node instances refer to instances that actually exist?
		# - Are all node options understood?
		# - Do node types with optional fields have required values?
		# ...
		# -> Strip any nodes / instances that failed

		# If we have errors at this point, just send them back and don't proceed further.
		# We don't want to establish a new cluster with wonky instance configuration.
		# We have not yet made any operational changes to the current instances & cluster.
		if ( |req$results| > 0 )
			{
			ClusterController::Log::info(fmt("tx ClusterController::API::set_configuration_response %s", req$id));
			event ClusterController::API::set_configuration_response(req$id, req$results);
			ClusterController::Request::finish(req$id);
			return;
			}

		# The config includes instances, some of which may be new to us. For any known
		# ones that aren't included in the new set no longer included, send config that
		# will shut down their cluster, and unpeer.
		local insts_current: set[string];
		local insts_new: set[string];

		for ( name in ClusterController::instances )
			add insts_current[name];
		for ( inst in config$instances )
			add insts_new[inst$name];

		for ( dropout in insts_new - insts_current )
			{
			inst = ClusterController::instances[dropout];
			agent_topic = ClusterAgent::topic_prefix + "/" + name;

			# This is "fire and forget", so we don't register proper requests,
			# or track the response.
			local cfg = ClusterController::Types::Configuration();
			Broker::publish(agent_topic, ClusterAgent::API::set_configuration_request, unique_id(""), cfg);

			if ( inst?$listen_port )
				{
				# XXX could use a real disconnect/shutdown here
				Broker::unpeer(inst$host, inst$listen_port);
				}

			delete ClusterController::instances[dropout];
			}

		# We need to update the instances in the provided config with
		# the ones that now have resolved addresses:
		config$instances = set();

		for ( i in insts_res )
			{
			inst = insts_res[i];
			add config$instances[inst];
			ClusterController::instances[inst$name] = inst;
			ClusterController::Log::info(fmt("registering %s: %s (%s)", inst$name, inst$host, inst$address));
			}

		# Transmit the configuration on to the agents. They need to be aware of
		# each other's location and nodes, so the data cluster nodes can connect
		# (for example, so a worker on instance 1 can connect to a logger on
		# instance 2).
		#
		# Response event gets sent via the agents' reponse event handler, above.
		send_config_to_agents(req, config);
		}
	}

event ClusterController::API::get_instances_request(reqid: string)
	{
	ClusterController::Log::info(fmt("rx ClusterController::API::set_instances_request %s", reqid));

	local insts: vector of ClusterController::Types::Instance;

	for ( i in ClusterController::instances )
		insts += ClusterController::instances[i];

	ClusterController::Log::info(fmt("tx ClusterController::API::get_instances_response %s", reqid));
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
		local inst: ClusterController::Types::Instance;
		local insts: ClusterController::Types::InstanceVec;
		local name: string;

		for ( name, inst in ClusterController::instances )
			{
			if ( ! inst?$listen_port )
				{
				# This isn't an instance we connect to, they'll talk to us.
				next;
				}

			insts[|insts|] = inst;
			}

		when ( local insts_res = resolve_instances(insts) )
			{
			for ( i in insts_res )
				{
				inst = insts_res[i];
				ClusterController::instances[inst$name] = inst;
				}

			# We peer with instance agent if we have a hostname/address
			# to connect to. Otherwise, the agents are to connect to us.
			for ( name, inst in ClusterController::instances )
				{
				if ( ! inst?$listen_port )
					next;

				ClusterController::Log::info(fmt("controller is peering with instance %s/%s",
				                                 inst$name, inst$host));
				Broker::peer(inst$host, inst$listen_port,
				             ClusterController::connect_retry);
				}
			}
		}

	# If ClusterController::instances is empty, agents peer with
	# us and we do nothing. We'll build up state as the
	# notify_agent_hello() events come int.

	ClusterController::Log::info("controller is live");
	}
