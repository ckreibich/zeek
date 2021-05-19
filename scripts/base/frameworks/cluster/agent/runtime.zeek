@load base/frameworks/broker
@load base/frameworks/cluster/agent/api
@load base/frameworks/cluster/controller/config
@load base/frameworks/cluster/controller/log

redef ClusterController::role = ClusterController::Types::AGENT;

event ClusterAgent::API::set_nodes_request(reqid: string, nodes: set[ClusterController::Types::Node])
	{
	local cluster: table[string] of Supervisor::ClusterEndpoint;
	local res: vector of ClusterController::Types::Result;

	for ( node in nodes )
		{
		local error = "";
		local success = T;

		if ( node$instance != ClusterAgent::name )
			{
			error = fmt("ignoring node %s for instance %s", node$name, node$instance);
			success = F;
			}

		res += ClusterController::Types::Result(
		    $reqid = reqid,
		    $instance = ClusterAgent::name,
		    $success = success,
		    $error = error,
		    $node = node$name
		);
		}

	event ClusterAgent::API::set_nodes_response(reqid, res);
	return;

	# Don't do this just yet
	for ( node in nodes )
		{
		local snc = Supervisor::NodeConfig($name=node$name);
		local cle: Supervisor::ClusterEndpoint;

		if ( node?$scripts )
			snc$scripts = node$scripts;
		if ( node?$interface )
			snc$interface = node$interface;
		if ( node?$cpu_affinity )
			snc$cpu_affinity = node$cpu_affinity;

		cle$role = node$role;
		cluster[node$name] = cle;
		}
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	# This does not (cannot?) immediately verify that the new peer
	# is in fact a controller, so we might send this redundantly.
	# Controllers handle the hello event accordingly.

	local epi = ClusterAgent::endpoint_info();
	# XXX
	event ClusterAgent::API::notify_agent_hello(epi$id,
	    to_addr(epi$network$address), ClusterAgent::API::version);
	}

event zeek_init()
	{
	local epi = ClusterAgent::endpoint_info();
	local agent_topic = ClusterAgent::topic_prefix + "/" + epi$id;

	Broker::subscribe(agent_topic);
	Broker::subscribe(SupervisorControl::topic_prefix);

	Broker::auto_publish(agent_topic, ClusterAgent::API::set_nodes_response);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_agent_hello);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_change);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_error);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_log);

	if ( ClusterAgent::controller$address != "0.0.0.0" )
		{
		# We connect to the controller.
		Broker::peer(ClusterAgent::controller$address,
			     ClusterAgent::controller$bound_port,
			     ClusterController::connect_retry);
		}
	else
		{
		# Controller connects to us; listen for it.
		Broker::listen(cat(epi$network$address), epi$network$bound_port);
		}

	ClusterController::Log::info("agent is live");
	}
