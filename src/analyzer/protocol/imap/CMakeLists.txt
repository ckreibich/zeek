zeek_add_plugin(
    Zeek IMAP
    SOURCES Plugin.cc IMAP.cc
    BIFS events.bif
    PAC imap.pac imap-analyzer.pac imap-protocol.pac)
