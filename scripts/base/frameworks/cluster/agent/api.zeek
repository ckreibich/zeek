@load base/frameworks/cluster/controller/types

module ClusterAgent;

export {
	const api_version = 1;

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
	    n: ClusterController::Types::Node &optional);

	# Report informational message.
	global ClusterAgent::notify_log: event(
	    instance: string, msg: string,
	    n: ClusterController::Types::Node &optional);
}
