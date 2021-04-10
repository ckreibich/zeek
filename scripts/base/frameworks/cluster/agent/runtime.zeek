@load base/frameworks/broker

module ClusterAgent;

event zeek_init()
	{
	local epi = ClusterAgent::endpoint_info();

	# XXX add support for agent -> controller conn establishment
	Broker::listen(cat(epi$network$address), epi$network$bound_port);

	Broker::subscribe(ClusterAgent::topic_prefix + "/" + epi$id);
	Broker::subscribe(SupervisorControl::topic_prefix);
	}
