# Notifications for Broker-reported backpressure overflow.

@load base/frameworks/telemetry

module Cluster;

global broker_backpressure_overflows_cf = Telemetry::register_counter_family([
    $prefix="zeek",
    $name="broker-backpressure-overflows",
    $unit="",
    $label_names=vector("peer"),
    $help_text="Number of Broker peering drops due to a neighbor falling too far behind in message I/O",
]);

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( ! endpoint?$network || "caf::sec::backpressure_overflow" !in msg )
		return;

	local peerdesc = "non-cluster peer ";
	local id = endpoint$id;
	local name = nodeid_to_name(endpoint$id);

	if ( name != "" )
		{
		peerdesc = "";
		id = name;
		}

	Cluster::log(fmt("removed due to backpressure overflow: %s%s:%s (%s)",
	                 peerdesc, endpoint$network$address, endpoint$network$bound_port, id));
	Telemetry::counter_family_inc(broker_backpressure_overflows_cf, vector(id));
	}

event Broker::peer_lost(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( ! endpoint?$network || "caf::sec::backpressure_overflow" !in msg )
		return;

	local peerdesc = "non-cluster peer ";
	local id = endpoint$id;
	local name = nodeid_to_name(endpoint$id);

	if ( name != "" )
		{
		peerdesc = "";
		id = name;
		}

	Cluster::log(fmt("lost due to backpressure overflow: %s%s:%s (%s)",
	                 peerdesc, endpoint$network$address, endpoint$network$bound_port, id));
	Telemetry::counter_family_inc(broker_backpressure_overflows_cf, vector(id));
	}
