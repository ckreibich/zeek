zeek_add_plugin(
    Zeek MQTT
    SOURCES MQTT.cc Plugin.cc
    BIFS types.bif events.bif
    PAC mqtt.pac
        mqtt-protocol.pac
        commands/connect.pac
        commands/connack.pac
        commands/publish.pac
        commands/puback.pac
        commands/pubrec.pac
        commands/pubrel.pac
        commands/pubcomp.pac
        commands/subscribe.pac
        commands/suback.pac
        commands/unsuback.pac
        commands/unsubscribe.pac
        commands/disconnect.pac
        commands/pingreq.pac
        commands/pingresp.pac)
