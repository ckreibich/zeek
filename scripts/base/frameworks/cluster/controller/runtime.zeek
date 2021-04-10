@load base/frameworks/broker
@load base/frameworks/cluster/agent

module ClusterController;

event zeek_init()
	{
	local cni = ClusterController::network_info();

	# XXX add support for agent -> controller conn establishment
	Broker::listen(cat(cni$address), cni$bound_port);

	for ( i in ClusterController::agents )
		{
		local epi = ClusterController::agents[i];
		Broker::peer(epi$network$address, epi$network$bound_port);
		}

	Broker::subscribe(ClusterAgent::topic_prefix);
	Broker::subscribe(ClusterController::topic);
	}
