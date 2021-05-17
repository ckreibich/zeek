##! This scripts loads only functionality needed for the supervisor to
##! fork required processes into place. In a supervised setting the
##! supervisor is unlikely to conduct traffic analysis, so we can skip
##! a large part of the scripting layer here. On the other hand we do
##! want to enable the cluster framework, allow plugins, and source in
##! potential additional functionality, so this setting also differs
##! from bare-mode.

@load base/frameworks/supervisor
@load base/frameworks/cluster/agent
@load base/frameworks/cluster/controller
