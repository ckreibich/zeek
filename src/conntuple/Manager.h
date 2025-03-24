#pragma once

#include <memory>

#include "zeek/Conn.h"
#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"

namespace zeek {

class Packet;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace conntuple {

class Manager {
public:
    Manager();
    virtual ~Manager();

    virtual ConnTuplePtr GetTuple(const Packet* pkt);
    virtual zeek::detail::ConnKeyPtr GetKey(const ConnTuple& tuple);
    virtual void FillVal(detail::ConnKeyPtr key, RecordValPtr& tuple) {};

private:
};

class VlanAwareManager : public Manager {
    ConnTuplePtr GetTuple(const Packet* pkt) override;
    zeek::detail::ConnKeyPtr GetKey(const ConnTuple& tuple) override;
    void FillVal(detail::ConnKeyPtr key, RecordValPtr& tuple) override;
};

} // namespace conntuple

// Manager for connection tuple instantiations.
extern conntuple::Manager* conntuple_mgr;

} // namespace zeek
