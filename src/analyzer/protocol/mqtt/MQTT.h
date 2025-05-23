// See the file "COPYING" in the main distribution directory for copyright.

// Generated by binpac_quickstart

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace binpac {
namespace MQTT {
class MQTT_Conn;
}
} // namespace binpac

namespace zeek::analyzer::mqtt {

class MQTT_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    MQTT_Analyzer(Connection* conn);
    ~MQTT_Analyzer() override;

    void Done() override;
    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Undelivered(uint64_t seq, int len, bool orig) override;
    void EndpointEOF(bool is_orig) override;

    static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn) { return new MQTT_Analyzer(conn); }

protected:
    binpac::MQTT::MQTT_Conn* interp;
};

} // namespace zeek::analyzer::mqtt
