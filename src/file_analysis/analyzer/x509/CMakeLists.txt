zeek_add_plugin(
    Zeek X509
    SOURCES X509Common.cc X509.cc OCSP.cc Plugin.cc
    BIFS events.bif types.bif functions.bif ocsp_events.bif
    PAC x509-extension.pac x509-signed_certificate_timestamp.pac)
