@load base/frameworks/cluster/agent/config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() || ! ClusterAgent::enable )
		return;

	local epi = ClusterAgent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id,
		$scripts=vector("base/frameworks/cluster/agent/runtime.zeek"));

	if ( ClusterAgent::stdout_file_suffix != "" )
		sn$stdout_file = epi$id + "." + ClusterAgent::stdout_file_suffix;
	if ( ClusterAgent::stderr_file_suffix != "" )
		sn$stderr_file = epi$id + "." + ClusterAgent::stderr_file_suffix;

	sn$env["ZEEK_CLUSTER_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("XXX supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
