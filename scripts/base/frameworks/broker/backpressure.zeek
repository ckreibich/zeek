##! This handles Broker peers that fall so far behind in message I/O that the
##! local endpoint decides to unpeer them.  Zeek captures this via logging (with
##! a "peer-removed" entry in broker.log indicating CAF's underlying reason, and
##! a similar message in reporter.log) and eventing (via the existing
##! Broker::peer_removed/lost event types, also indicating the reason).

module Broker;

event Broker::peer_removed(endpoint: Broker::EndpointInfo, msg: string)
	{
	if ( "caf::sec::backpressure_overflow" !in msg ) {
		return;
	}

	# The peer_removed event indicates that the local endpoint previously
	# connected to the indicated node. We also know that Broker has un-peered
	# the other because it fell too far behind in message I/O, per the above
	# message.

	if ( ! endpoint?$network ) {
		Reporter::error(fmt("Missing network info to re-peer with %s", endpoint$id));
		return;
	}

	# Re-establish the peering so Broker's reconnect behavior kicks in once
	# the other endpoint catches up. Broker will periodically re-try this,
	# so it doesn't matter whether we schedule extra wait time for the peer
	# to recover at this point.
	#
	# If we are a passively peered endpoint (i.e. one that got connected
	# to), we may still lose the peering because the other endpoint becomes
	# slow. In that case we don't get a Broker::peer_removed event (we
	# instead get a Broker::peer_lost), but we do not need to re-peer: the
	# connecting endpoint will do so once it recovers.

	Broker::peer(endpoint$network$address, endpoint$network$bound_port);
}
