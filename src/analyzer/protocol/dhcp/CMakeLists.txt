zeek_add_plugin(
    Zeek DHCP
    SOURCES DHCP.cc Plugin.cc
    BIFS events.bif types.bif
    PAC dhcp.pac dhcp-protocol.pac dhcp-analyzer.pac dhcp-options.pac)
