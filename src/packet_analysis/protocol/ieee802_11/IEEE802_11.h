// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::IEEE802_11 {

class IEEE802_11Analyzer : public Analyzer {
public:
    IEEE802_11Analyzer();
    ~IEEE802_11Analyzer() override = default;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<IEEE802_11Analyzer>(); }

private:
    bool HandleInnerPacket(size_t len, const uint8_t* data, Packet* packet) const;
};

} // namespace zeek::packet_analysis::IEEE802_11
