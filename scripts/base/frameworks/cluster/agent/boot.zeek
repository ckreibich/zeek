@load base/frameworks/cluster/agent/config

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() || ! ClusterAgent::enable )
		return;

	local epi = ClusterAgent::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id,
		$scripts=vector("base/frameworks/cluster/agent/main.zeek"));

	if ( ClusterAgent::directory != "" )
		sn$directory = ClusterAgent::directory;
	if ( ClusterAgent::stdout_file_suffix != "" )
		sn$stdout_file = epi$id + "." + ClusterAgent::stdout_file_suffix;
	if ( ClusterAgent::stderr_file_suffix != "" )
		sn$stderr_file = epi$id + "." + ClusterAgent::stderr_file_suffix;

	# This helps Zeek run controller and agent with a minimal set of scripts.
	sn$env["ZEEK_CLUSTER_MGMT_NODE"] = "AGENT";

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("error: supervisor could not create agent node: %s", res));
		exit(1);
		}
	}
