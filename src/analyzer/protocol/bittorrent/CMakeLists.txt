zeek_add_plugin(
    Zeek BitTorrent
    SOURCES BitTorrent.cc BitTorrentTracker.cc Plugin.cc
    BIFS events.bif
    PAC bittorrent.pac bittorrent-analyzer.pac bittorrent-protocol.pac)
