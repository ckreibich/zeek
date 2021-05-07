@load base/frameworks/cluster/agent/config

module ClusterController;

export {
	# The name of this controller in the cluster.
	# Without the environment variable and no redef, this
	# falls back to gethostname().
	const name = getenv("ZEEK_CONTROLLER_NAME") &redef;

	# Controller stdout/stderr log files to produce in Zeek's
	# working directory. If empty, no such logs will result.
	const stdout_file = "controller.stdout" &redef;
	const stderr_file = "controller.stderr" &redef;

	const listen_addr = getenv("ZEEK_CONTROLLER_ADDR") &redef;
	const default_addr = "127.0.0.1" &redef;

	const listen_port = getenv("ZEEK_CONTROLLER_PORT") &redef;
	const default_port = 2150/tcp &redef;

	# A more aggressive default retry interval (vs default 30s)
	const connect_retry = 1sec &redef;

	# The controller listens for messages on this topic:
	const topic = "zeek/cluster-control/controller" &redef;

	# The set of agents to interact with. When this is non-empty
	# at startup, the controller contacts the agents; when it is
	# empty, it waits for agents to connect.
	const instances: table[string] of ClusterController::Types::Instance = { } &redef;

	const role = ClusterController::Types::NONE &redef;

	# Returns the effective network information for this controller.
	global network_info: function(): Broker::NetworkInfo;
	global endpoint_info: function(): Broker::EndpointInfo;
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

function endpoint_info(): Broker::EndpointInfo
	{
	local epi: Broker::EndpointInfo;

	if ( ClusterController::name != "" )
		epi$id = ClusterController::name;
	else
		epi$id = fmt("controller-%s", gethostname());

	epi$network = network_info();

	return epi;
	}
