@load base/frameworks/broker
@load base/frameworks/cluster/agent/api
@load base/frameworks/cluster/controller/config
@load base/frameworks/cluster/controller/log

redef ClusterController::role = ClusterController::Types::AGENT;

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	# This does not (cannot?) immediately verify that the new peer
	# is in fact a controller, so we might send this redundantly.
	# Controllers handle the hello event accordingly.

	local epi = ClusterAgent::endpoint_info();
	event ClusterAgent::notify_agent_hello(epi$id,
	    to_addr(epi$network$address), ClusterAgent::api_version);
	}

event zeek_init()
	{
	local epi = ClusterAgent::endpoint_info();
	local agent_topic = ClusterAgent::topic_prefix + "/" + epi$id;

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

	Broker::subscribe(agent_topic);
	Broker::subscribe(SupervisorControl::topic_prefix);

	Broker::auto_publish(agent_topic, ClusterAgent::notify_agent_hello);
	Broker::auto_publish(agent_topic, ClusterAgent::notify_change);
	Broker::auto_publish(agent_topic, ClusterAgent::notify_error);
	Broker::auto_publish(agent_topic, ClusterAgent::notify_log);

	ClusterController::Log::info("agent is live");
	}
