# This test verifies basic agent-controller communication. We launch agent and
# controller via the supervisor, add an extra handler for the notify_agent_hello
# event that travels agent -> controller, and verify its print output in the
# controller's stdout log.

# The following env vars is known to the controller framework
# @TEST-PORT: ZEEK_CONTROLLER_PORT
# @TEST-PORT: BROKER_PORT

# A bit of a detour to get the port number into the agent configuration
# @TEST-EXEC: btest-bg-run zeek zeek -j %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/controller.stdout

@load policy/frameworks/cluster/agent
@load policy/frameworks/cluster/controller

redef Broker::default_port = to_port(getenv("BROKER_PORT"));

redef ClusterController::name = "controller";
redef ClusterAgent::name = "agent";

# Tell the agent where to locate the controller.
redef ClusterAgent::controller = [$address="127.0.0.1", $bound_port=to_port(getenv("ZEEK_CONTROLLER_PORT"))];

@if ( Supervisor::is_supervised() )

@load policy/frameworks/cluster/agent/api

event ClusterAgent::API::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	print(fmt("notify_agent_hello %s %s %s", instance, host, api_version));

	# This takes down the whole process tree. Looks like we need to delay
        # this a bit to get the above print to work reliably.
	schedule 2sec { SupervisorControl::stop_request() };
	}

@endif
