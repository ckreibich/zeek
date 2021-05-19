@load base/frameworks/cluster/controller/types

module ClusterController::Request;

export {
	type Request: record {
		id: string;
		parent_id: string &optional;
	};

	# State specific to the set_nodes request/response events
	type SetNodesState: record {
		requests: vector of Request &default=vector();
	};

	# The redef is a workaround so we can use the Request type
        # while it is still being defined
	redef record Request += {
		results: ClusterController::Types::ResultVec &default=vector();
		finished: bool &default=F;

		set_nodes_state: SetNodesState &optional;
	};

	global null_req = Request($id="", $finished=T);

	global create: function(reqid: string &default=unique_id("")): Request;
	global lookup: function(reqid: string): Request;
	global finish: function(reqid: string): bool;

	global is_null: function(request: Request): bool;
}

global requests: table[string] of Request;

function create(reqid: string): Request
	{
	local ret = Request($id=reqid);
	requests[reqid] = ret;
	return ret;
	}

function lookup(reqid: string): Request
	{
	if ( reqid in requests )
		return requests[reqid];

	return null_req;
	}

function finish(reqid: string): bool
	{
	if ( reqid !in requests )
		return F;

	local req = requests[reqid];
	delete requests[reqid];

	req$finished = T;

	return T;
	}

function is_null(request: Request): bool
	{
	if ( request$id == "" )
		return T;

	return F;
	}
