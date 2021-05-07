@load base/frameworks/broker
@load base/frameworks/cluster/controller/api
@load base/frameworks/cluster/agent
@load base/frameworks/cluster/controller/log

redef ClusterController::role = ClusterController::Types::CONTROLLER;

event zeek_init()
	{
	# Controller always listens -- it needs to be able to respond
	# to the Zeek client. This port is also used by the agents
	# if they connect to the client.
	local cni = ClusterController::network_info();
	Broker::listen(cat(cni$address), cni$bound_port);

	if ( |ClusterController::instances| > 0 )
		{
		# We peer with the agents.
		for ( i in ClusterController::instances )
			{
			local inst = ClusterController::instances[i];

			if ( ! inst?$listen_port )
				{
				# XXX config error -- this must be there
				next;
				}

			Broker::peer(cat(inst$host), inst$listen_port,
				     ClusterController::connect_retry);
			}
		}
	else
		{
		# Agents peer with us, do nothing. We build up state as
		# notify_agent_hello() events come int.
		}

	Broker::subscribe(ClusterAgent::topic_prefix);
	Broker::subscribe(ClusterController::topic);

	ClusterController::Log::info("controller is live");
	}

event ClusterAgent::notify_agent_hello(instance: string, host: addr, api_version: count)
	{
	# See if we already know about this agent; if not, register
	# it.
	#
	# XXX protection against rogue agents?
	ClusterController::Log::info("hello agent!");

	if ( instance in ClusterController::instances )
		{
		# Do nothing, unless this known agent checks in with a mismatching
		# API version, in which case we kick it out.
		if ( api_version != ClusterController::API::api_version )
			{
			local inst = ClusterController::instances[instance];
			if ( inst?$listen_port )
				{
				# We peered with this instance, unpeer.
				Broker::unpeer(cat(inst$host), inst$listen_port );
				# XXX what to do if they connected to us?
				}
			delete ClusterController::instances[instance];
			}

		return;
		}

	if ( api_version != ClusterController::API::api_version )
		{
		Reporter::warning(fmt("agent %s/%s speaks incompatible agent protocol (%s, need %s). Unpeering.",
			instance, host, api_version, ClusterController::API::api_version));
		}

	ClusterController::instances[instance] = ClusterController::Types::Instance($name=instance, $host=host);
	print("WAHOO!");
	}

event ClusterAgent::notify_change(instance: string, n: ClusterController::Types::Node,
				  old: ClusterController::Types::State,
				  new: ClusterController::Types::State)
	{
	}

event ClusterAgent::notify_error(instance: string, msg: string,
				 n: ClusterController::Types::Node)
	{
	}

event ClusterAgent::notify_log(instance: string, msg: string,
			       n: ClusterController::Types::Node)
	{
	}
