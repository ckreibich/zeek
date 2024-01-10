// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <maxminddb.h>

#include "zeek/Val.h"

namespace zeek {

#ifdef USE_GEOIP

class MMDB {
public:
    MMDB();
    virtual ~MMDB();

    virtual bool Open() = 0;
    bool OpenFile(const char* filename);
    void Close();
    bool IsOpen() const { return mmdb.filename != nullptr; }
    void Check();

    bool Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result);
    const char* Filename();

    void BuiltinError(const char* msg);
    static void ReportMsg(const char* format, ...);

private:
    MMDB_lookup_result_s Lookup(const struct sockaddr* const sa);
    bool StaleDB();

    MMDB_s mmdb;
    struct stat file_info;
    bool did_error;
    bool lookup_error;
    double last_check;
};

class LocDB : public MMDB {
public:
    bool Open();
};

class AsnDB : public MMDB {
public:
    bool Open();
};

#endif // USE_GEOIP

ValPtr mmdb_open_location_db(zeek::StringVal* filename);
ValPtr mmdb_open_asn_db(zeek::StringVal* filename);

RecordValPtr mmdb_lookup_location(zeek::AddrVal* addr);
RecordValPtr mmdb_lookup_autonomous_system(zeek::AddrVal* addr);

} // namespace zeek
