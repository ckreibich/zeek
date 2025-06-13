// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <netinet/in.h>
#include <optional>

#include "zeek/Conn.h"
#include "zeek/ConnKey.h"

namespace zeek {

namespace detail {

/**
 * Struct for embedding into an IPBasedConnKey.
 */
struct PackedConnTuple {
    in6_addr ip1;
    in6_addr ip2;
    uint16_t port1 = 0;
    uint16_t port2 = 0;
    uint16_t proto = detail::INVALID_CONN_KEY_IP_PROTO;
} __attribute__((packed, aligned));

} // namespace detail

/**
 * Abstract key class for IP-based connections.
 *
 * ConnKey instances for IP always hold a ConnTuple instance which is provided
 * by the IPBasedAnalyzer. The InitConnTuple() method stored a normalized version
 * in the tuple, loosing the information about orig and responder.
 */
class IPBasedConnKey : public zeek::ConnKey {
public:
    void InitTuple(const ConnTuple& ct) { InitPackedTuple(ct); }

    std::optional<std::string> Error() const override;

    /**
     * Return a modifiable reference to the embedded PackedConnTuple.
     *
     * This is virtual to give subclasses control over where
     * to place the tuple within the key.
     */
    virtual detail::PackedConnTuple& PackedTuple() const = 0;

private:
    /**
     * Initialize a packed tuple from a ConnTuple instance.
     */
    void InitPackedTuple(const ConnTuple& ct) {
        auto& tuple = PackedTuple();

        if ( ct.is_one_way || addr_port_canon_lt(ct.src_addr, ct.src_port, ct.dst_addr, ct.dst_port) ) {
            ct.src_addr.CopyIPv6(&tuple.ip1);
            ct.dst_addr.CopyIPv6(&tuple.ip2);
            tuple.port1 = ct.src_port;
            tuple.port2 = ct.dst_port;
        }
        else {
            ct.dst_addr.CopyIPv6(&tuple.ip1);
            ct.src_addr.CopyIPv6(&tuple.ip2);
            tuple.port1 = ct.dst_port;
            tuple.port2 = ct.src_port;
        }

        tuple.proto = ct.proto;
    }
};

using IPBasedConnKeyPtr = std::unique_ptr<IPBasedConnKey>;

/**
 * The usual 5-tuple ConnKey, fully instantiable.
 */
class IPConnKey : public IPBasedConnKey {
public:
    IPConnKey() {
        // Fill any holes since we use the full tuple as a key:
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    zeek::session::detail::Key SessionKey() const override {
        return zeek::session::detail::Key(reinterpret_cast<const void*>(&key), sizeof(key),
                                          // XXX: Not sure we need CONNECTION_KEY_TYPE?
                                          session::detail::Key::CONNECTION_KEY_TYPE);
    }

    detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

private:
    struct {
        // mutable to allow PackedTuple() to remain const.
        mutable struct detail::PackedConnTuple tuple;
    } key;
};

} // namespace zeek
