zeek_add_plugin(
    Zeek DNP3
    SOURCES DNP3.cc Plugin.cc
    BIFS events.bif
    PAC dnp3.pac dnp3-analyzer.pac dnp3-protocol.pac dnp3-objects.pac)
