@load base/frameworks/cluster/agent/config

module ClusterController;

export {
	# The name of this controller in the cluster.
	const name = "controller" &redef;

	# Controller stdout/stderr log files to produce in Zeek's
	# working directory. If empty, no such logs will result.
	const stdout_file = "controller.stdout" &redef;
	const stderr_file = "controller.stderr" &redef;

	const listen_addr = getenv("ZEEK_CONTROLLER_ADDR") &redef;
	const default_addr = "127.0.0.1" &redef;

	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;
	const default_port = 2150/tcp &redef;

	# The controller listens for messages on this topic:
	const topic = "zeek/cluster-control/controller" &redef;

	const agents = vector(ClusterAgent::endpoint_info()) &redef;

        global network_info: function(): Broker::NetworkInfo;
}

function network_info(): Broker::NetworkInfo
	{
	local ni: Broker::NetworkInfo;

	if ( ClusterController::listen_addr != "" )
		ni$address = ClusterController::listen_addr;
	else
		ni$address = cat(ClusterController::default_addr);

	if ( ClusterController::listen_port != "" )
		ni$bound_port = to_port(ClusterController::listen_port);
	else
		ni$bound_port = ClusterController::default_port;

	return ni;
	}
