zeek_add_plugin(
    Zeek NTLM
    SOURCES NTLM.cc Plugin.cc
    BIFS types.bif events.bif
    PAC ntlm.pac ntlm-protocol.pac ntlm-analyzer.pac)
