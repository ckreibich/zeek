zeek_add_plugin(
    Zeek ICMP
    SOURCES ICMP.cc ICMPSessionAdapter.cc Plugin.cc
    BIFS events.bif)
