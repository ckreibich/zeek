zeek_add_plugin(
    Zeek Login
    SOURCES Login.cc RSH.cc Telnet.cc Rlogin.cc NVT.cc Plugin.cc
    BIFS events.bif functions.bif)
