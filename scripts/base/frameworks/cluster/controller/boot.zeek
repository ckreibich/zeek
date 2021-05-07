event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local epi = ClusterController::endpoint_info();
	local sn = Supervisor::NodeConfig($name=epi$id,
	    $scripts=vector("base/frameworks/cluster/controller/runtime.zeek"));

	if ( ClusterController::stdout_file != "" )
		sn$stdout_file = ClusterController::stdout_file;
	if ( ClusterController::stderr_file != "" )
		sn$stderr_file = ClusterController::stderr_file;

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("XXX supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
