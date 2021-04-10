module ClusterController;

event zeek_init()
	{
	if ( ! Supervisor::is_supervisor() )
		return;

	local sn = Supervisor::NodeConfig($name=ClusterController::name,
		$scripts=vector("base/frameworks/cluster/controller/runtime.zeek"));

	if ( stdout_file != "" )
		sn$stdout_file = ClusterController::stdout_file;
	if ( stderr_file != "" )
		sn$stderr_file = ClusterController::stderr_file;

	local res = Supervisor::create(sn);

	if ( res != "" )
		{
		print(fmt("XXX supervisor could not create controller node: %s", res));
		exit(1);
		}
	}
