@load base/frameworks/supervisor/control
@load base/frameworks/cluster/controller/types

module ClusterAgent;

export {
	const api_version = 1;

	# Agent API methods

	global ClusterAgent::set_nodes: function(
	    nodes: set[ClusterController::Types::Node]):
	    vector of ClusterController::Types::Result;

	# Agent API events, named after methods, with request/response
	# pairing. These are initiated by the controller.
	global ClusterAgent::set_nodes_request: event(
	    reqid: string, nodes: set[ClusterController::Types::Node]);

	global ClusterAgent::set_nodes_response: event(
	    reqid: string, result: vector of ClusterController::Types::Result);

	# Notification events, agent -> controller

	# Report agent being available.
	global ClusterAgent::notify_agent_hello: event(
	    instance: string, host: addr, api_version: count);

	# Report node state changes.
	global ClusterAgent::notify_change: event(
	    instance: string, n: ClusterController::Types::Node,
	    old: ClusterController::Types::State,
	    new: ClusterController::Types::State);

	# Report operational error.
	global ClusterAgent::notify_error: event(
	    instance: string, msg: string,
	    n: ClusterController::Types::Node); # XXX make node optional

	# Report informational message.
	global ClusterAgent::notify_log: event(
	    instance: string, msg: string,
	    n: ClusterController::Types::Node); # XXX make node optional
}


function set_nodes(nodes: set[ClusterController::Types::Node]):
    vector of ClusterController::Types::Result
	{
	local cluster: table[string] of Supervisor::ClusterEndpoint;
	local res: vector of ClusterController::Types::Result;

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
