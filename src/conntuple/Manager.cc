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

zeek::detail::ConnKeyPtr Manager::GetKey(const ConnTuple& tuple) { return std::make_shared<zeek::detail::ConnKey>(tuple); }

void Manager::FillVal(RecordValPtr& tuple) { }

} // namespace zeek::conntuple
