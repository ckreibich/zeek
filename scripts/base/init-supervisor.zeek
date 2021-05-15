##! This scripts loads the functionality the supervisor process itself
##! needs to possess in order to fork the needed child processes into
##! place via the stem node. In a supervised setting it is unlikely
##! that the supervisor itself does traffic analysis, so we can skip
##! this part of the script layer here. On the other hand we do want
##! to enable the cluster framework, load plugins, and source in
##! potential additional functionality, so this makes it different
##! from bare-mode as well.

@load base/frameworks/cluster/agent
@load base/frameworks/cluster/controller
