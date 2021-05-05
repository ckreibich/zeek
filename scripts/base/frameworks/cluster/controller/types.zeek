module ClusterController::Types;

export {
	## The cluster logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## The record type which contains the column fields of the cluster log.
	type Info: record {
		## The time at which a cluster message was generated.
		ts:       time;
		## The name of the node that is creating the log record.
		node: string;
		## The role of the node, as understood by the supervisor
		role: Supervisor::ClusterRole;
		## A message indicating information about cluster controller operation.
		message:  string;
	} &log;

	type Role: enum {
		NONE,
		LOGGER,
		MANAGER,
		PROXY,
		WORKER,
	};

	# A Zeek-side option with value.
	type Option: record {
		name: string; # Name of option
		value: string;   # Value of option -- XXX, "any" doesn't work here
	};

	# Configuration describing a Zeek instance running a Cluster
	# Agent. Normally, there'll be one instance per cluster
	# system: a single physical system.
	type Instance: record {
		# Unique, human-readable instance name
		name: string;
		# IP address of system
		host: addr;
		# Port where Broker is listening
		listen_port: port &optional; # XXX not needed if agents to connect to controller
	};

	# State that a Cluster Node can be in. State changes trigger an
	# API notification (see notify_change()).
	type State: enum {
		Running, # Running and operating normally
		Stopped, # Explicitly stopped
		Failed,  # Failed to start; and permanently halted
		Crashed,  # Crashed, will be restarted,
	        Unknown,  # State not known currently (e.g., because of lost connectivity)
	};

	# Configuration describing a Cluster Node process.
	type Node: record {
		name: string;    # Unique, human-readable instance name
		instance: string; # Name of instance where node is to run
		role: Role;     # Role of the node.
		state: State;   # Desired, or current, run state.
		scripts: vector of string;     # Additional Zeek scripts for node
		options: set[Option];    # Zeek options for node
		interface: string &optional;     # Interface to sniff
		cpu_affinity: int &optional;     # CPU/core number to pin to
		environ: table[string] of string; # Custom environment vars
	};

	# Data structure capturing a cluster's complete configuration.
	type Configuration: record {
		config_id: string &optional; # Unique ID of current config
		instances: set[Instance];
		nodes: set[Node];
	};

	# Return value for APIs
	type Result: record {
		reqid: string;  # Request ID of operation this result refers to
		success: bool;  # True if successful
		data: any &optional;      # Addl data returned for successful operation
		error: string &default="";  # Descriptive error on failure
		node: string &optional;   # Name of associated node (for context)
		instance: string; # Name of associated instance (for context)
	};
}
