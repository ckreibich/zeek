// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Manager.h"

#include "zeek/Conn.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/session/Session.h"

zeek::conntuple::Manager* zeek::conntuple_mgr = nullptr;

namespace zeek::conntuple {

Manager::Manager() {}

Manager::~Manager() {}

ConnTuplePtr Manager::GetTuple(const Packet* pkt) { return std::make_shared<ConnTuple>(); }

zeek::detail::ConnKeyPtr Manager::GetKey(const ConnTuple& tuple) {
    return std::make_shared<zeek::detail::ConnKey>(tuple);
}


struct VlanConnTuple : public ConnTuple {
    uint32_t vlan = 0;
};

class VlanConnKey : public detail::ConnKey {
public:
    uint32_t vlan = 0;

    VlanConnKey(const ConnTuple& conn) : detail::ConnKey(conn) {};
    VlanConnKey(const VlanConnTuple& conn) : detail::ConnKey(conn) { vlan = conn.vlan; };

    size_t PackedSize() const override { return detail::ConnKey::PackedSize() + sizeof(vlan); }

    size_t Pack(uint8_t* data, size_t size) const override {
        if ( size < PackedSize() )
            return 0;

        uint8_t* ptr = data;

        ptr += detail::ConnKey::Pack(data, size);
        memcpy(ptr, &vlan, sizeof(vlan));
        ptr += sizeof(vlan);

        return ptr - data;
    }
};

ConnTuplePtr VlanAwareManager::GetTuple(const Packet* pkt) {
    auto res = std::make_shared<VlanConnTuple>();
    res->vlan = pkt->vlan;
    return res;
}

zeek::detail::ConnKeyPtr VlanAwareManager::GetKey(const ConnTuple& tuple) {
    const VlanConnTuple& vtuple = dynamic_cast<const VlanConnTuple&>(tuple);
    auto res = std::make_shared<VlanConnKey>(tuple);
    res->vlan = vtuple.vlan;
    return res;
}

void VlanAwareManager::FillVal(detail::ConnKeyPtr key, RecordValPtr& tuple) {
    if ( tuple->NumFields() <= 5 )
        return;

    auto vkey = dynamic_cast<VlanConnKey*>(key.get());

    tuple->Assign(5, vkey->vlan);
}

} // namespace zeek::conntuple
