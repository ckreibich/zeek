@load base/frameworks/broker
@load base/frameworks/cluster/agent/api
@load base/frameworks/cluster/controller/config
@load base/frameworks/cluster/controller/log
@load base/frameworks/cluster/controller/request

redef ClusterController::role = ClusterController::Types::AGENT;

# The global configuration as passed to us by the controller
global global_config: ClusterController::Types::Configuration;

# A map to make other instance info accessible
global instances: table[string] of ClusterController::Types::Instance;

# A map for the nodes we run on this instance, via this agent.
global nodes: table[string] of ClusterController::Types::Node;

# The node map employed by the supervisor to describe the cluster
# topology to newly forked nodes. We refresh it when we receive
# new configurations.
global data_cluster: table[string] of Supervisor::ClusterEndpoint;

event SupervisorControl::create_response(reqid: string, result: string)
	{
	local req = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( |result| > 0 )
		{
		local msg = fmt("failed to create node %s: %s", name, result);
		ClusterController::Log::error(msg);
		event ClusterAgent::API::notify_error(ClusterAgent::name, msg, name);
		}

	ClusterController::Request::finish(reqid);
	}

event SupervisorControl::destroy_response(reqid: string, result: bool)
	{
	local req = ClusterController::Request::lookup(reqid);
	if ( ClusterController::Request::is_null(req) )
		return;

	local name = req$supervisor_state$node;

	if ( ! result )
		{
		local msg = fmt("failed to destroy node %s, %s", name, reqid);
		ClusterController::Log::error(msg);
		event ClusterAgent::API::notify_error(ClusterAgent::name, msg, name);
		}

	ClusterController::Request::finish(reqid);
	}

function supervisor_create(nc: Supervisor::NodeConfig)
	{
	local req = ClusterController::Request::create();
	req$supervisor_state = ClusterController::Request::SupervisorState($node = nc$name);
	event SupervisorControl::create_request(req$id, nc);
	ClusterController::Log::info(fmt("issued supervisor create for %s, %s", nc$name, req$id));
	}

function supervisor_destroy(node: string)
	{
	local req = ClusterController::Request::create();
	req$supervisor_state = ClusterController::Request::SupervisorState($node = node);
	event SupervisorControl::destroy_request(req$id, node);
	ClusterController::Log::info(fmt("issued supervisor destroy for %s, %s", node, req$id));
	}

event ClusterAgent::API::set_configuration_request(reqid: string, config: ClusterController::Types::Configuration)
	{
	ClusterController::Log::info(fmt("rx ClusterAgent::API::set_configuration_request %s", reqid));

	local nodename: string;
	local node: ClusterController::Types::Node;
	local nc: Supervisor::NodeConfig;
	local msg: string;

	# Adopt the global configuration provided.
	# XXX this can later handle validation and persistence
	# XXX should do this transactionally, only set when all else worked
	global_config = config;

	# Refresh the instances table:
	instances = table();
	for ( inst in config$instances )
		instances[inst$name] = inst;

	# Terminate existing nodes
	for ( nodename in nodes )
		supervisor_destroy(nodename);

	nodes = table();

	# Refresh the data cluster and nodes tables

	data_cluster = table();
	for ( node in config$nodes )
		{
		if ( node$instance == ClusterAgent::name )
			nodes[node$name] = node;

		local cep = Supervisor::ClusterEndpoint(
		    $role = node$role,
		    $host = instances[node$instance]$host,
		    $p = node$p);

		if ( node?$interface )
			cep$interface = node$interface;

		data_cluster[node$name] = cep;
		}

	# Apply the new configuration via the supervisor

	for ( nodename in nodes )
		{
		node = nodes[nodename];
		nc = Supervisor::NodeConfig($name=nodename);

		if ( node?$interface )
			nc$interface = node$interface;
		# XXX use options for the following:
		# - directory
		# - stdout_file
		# - stderr_file
		if ( node?$cpu_affinity )
			nc$cpu_affinity = node$cpu_affinity;
		if ( node?$scripts )
			nc$scripts = node$scripts;
		if ( node?$env )
			nc$env = node$env;
		nc$cluster = data_cluster;

		supervisor_create(nc);
		}

	# XXX this should fail if any of above problems occurred.

	local res = ClusterController::Types::Result(
	    $reqid = reqid,
	    $instance = ClusterAgent::name);

	ClusterController::Log::info(fmt("tx ClusterAgent::API::set_configuration_response %s", reqid));
	event ClusterAgent::API::set_configuration_response(reqid, res);
	}

event Broker::peer_added(peer: Broker::EndpointInfo, msg: string)
	{
	# This does not (cannot?) immediately verify that the new peer
	# is in fact a controller, so we might send this redundantly.
	# Controllers handle the hello event accordingly.

	local epi = ClusterAgent::endpoint_info();
	# XXX deal with unexpected peers, unless we're okay with it
	event ClusterAgent::API::notify_agent_hello(epi$id,
	    to_addr(epi$network$address), ClusterAgent::API::version);
	}

event zeek_init()
	{
	local epi = ClusterAgent::endpoint_info();
	local agent_topic = ClusterAgent::topic_prefix + "/" + epi$id;

	# The agent needs to peer with the supervisor, this doesn't currently
        # happen automatically. The address by default falls back to Broker's
	# default, which relies on ZEEK_DEFAULT_LISTEN_ADDR and so might just
	# be "". In that case, we substitute loopback.
	local supervisor_addr = SupervisorControl::listen_address;
	if ( |supervisor_addr| == 0 )
		supervisor_addr = "127.0.0.1";

	Broker::peer(supervisor_addr,
	             SupervisorControl::listen_port,
		     SupervisorControl::listen_retry);

	Broker::subscribe(agent_topic);
	Broker::subscribe(SupervisorControl::topic_prefix);

	Broker::auto_publish(agent_topic, ClusterAgent::API::set_configuration_response);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_agent_hello);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_change);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_error);
	Broker::auto_publish(agent_topic, ClusterAgent::API::notify_log);

	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::create_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::create_response);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::destroy_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::destroy_response);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::restart_request);
	Broker::auto_publish(SupervisorControl::topic_prefix, SupervisorControl::restart_response);

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
