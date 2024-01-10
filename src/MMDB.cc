// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/MMDB.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <chrono>

#include "zeek/Func.h"
#include "zeek/IPAddr.h"
#include "zeek/ZeekString.h"

namespace zeek {

#ifdef USE_GEOIP

static int msg_count = 0;
static double msg_suppression_time = 0;
static constexpr int msg_limit = 20;
static constexpr double msg_suppression_duration = 300;

LocDB mmdb_loc;
AsnDB mmdb_asn;

MMDB::MMDB() : file_info{}, did_error{false}, lookup_error{false}, last_check{zeek::run_state::network_time} {}

MMDB::~MMDB() { Close(); }

bool MMDB::Lookup(const zeek::IPAddr& addr, MMDB_lookup_result_s& result) {
    if ( ! IsOpen() )
        return false;

    struct sockaddr_storage ss = {0};

    if ( IPv4 == addr.GetFamily() ) {
        struct sockaddr_in* sa = (struct sockaddr_in*)&ss;
        sa->sin_family = AF_INET;
        addr.CopyIPv4(&sa->sin_addr);
    }
    else {
        struct sockaddr_in6* sa = (struct sockaddr_in6*)&ss;
        sa->sin6_family = AF_INET6;
        addr.CopyIPv6(&sa->sin6_addr);
    }

    try {
        result = Lookup((struct sockaddr*)&ss);
    } catch ( const std::exception& e ) {
        MMDB::ReportMsg("MaxMind DB lookup location error [%s]", e.what());
        return false;
    }

    return result.found_entry;
}

MMDB_lookup_result_s MMDB::Lookup(const struct sockaddr* const sa) {
    int mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdb, sa, &mmdb_error);

    if ( MMDB_SUCCESS != mmdb_error ) {
        lookup_error = true;
        throw std::runtime_error(MMDB_strerror(mmdb_error));
    }

    return result;
}

bool MMDB::OpenFile(const char* filename) {
    Close();

    if ( 0 != stat(filename, &file_info) ) {
        return false;
    }

    int status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);

    if ( MMDB_SUCCESS != status ) {
        memset(&mmdb, 0, sizeof(mmdb));
        did_error = false;

        MMDB::ReportMsg("Failed to open MaxMind DB: %s [%s]", filename, MMDB_strerror(status));
        return false;
    }

    return true;
}

void MMDB::Close() {
    if ( IsOpen() ) {
        MMDB_close(&mmdb);
        memset(&mmdb, 0, sizeof(mmdb));
        did_error = false;
    }
}

void MMDB::Check() {
    if ( StaleDB() ) {
        MMDB::ReportMsg("Closing stale MaxMind DB [%s]", Filename());
        Close();
    }
}

// Check to see if the Maxmind DB should be closed and reopened.  This will
// happen if there was a lookup error or if the mmap'd file has been replaced
// by an external process.
bool MMDB::StaleDB() {
    if ( ! IsOpen() )
        return false;
    if ( lookup_error )
        return true;

    static double mmdb_stale_check_interval = zeek::id::find_val("mmdb_stale_check_interval")->AsInterval();

    if ( mmdb_stale_check_interval < 0.0 )
        return false;

    if ( zeek::run_state::network_time - last_check < mmdb_stale_check_interval )
        return false;

    last_check = zeek::run_state::network_time;
    struct stat buf;

    if ( 0 != stat(mmdb.filename, &buf) )
        return true;

    if ( buf.st_ino != file_info.st_ino || buf.st_mtime != file_info.st_mtime ) {
        MMDB::ReportMsg("%s change detected for MaxMind DB [%s]",
                        buf.st_ino != file_info.st_ino ? "Inode" : "Modification time", mmdb.filename);
        return true;
    }

    return false;
}

const char* MMDB::Filename() { return mmdb.filename; }

void MMDB::BuiltinError(const char* msg) {
    if ( ! did_error ) {
        did_error = true;
        zeek::emit_builtin_error(msg);
    }
}

void MMDB::ReportMsg(const char* format, ...) {
    if ( zeek::run_state::network_time > msg_suppression_time + msg_suppression_duration ) {
        msg_count = 0;
        msg_suppression_time = zeek::run_state::network_time;
    }

    if ( msg_count >= msg_limit )
        return;

    ++msg_count;

    va_list al;
    va_start(al, format);
    std::string msg = zeek::util::vfmt(format, al);
    va_end(al);

    zeek::reporter->Info("%s", msg.data());
}

bool LocDB::Open() {
    // City database is always preferred over Country database.
    const auto& mmdb_dir_val = zeek::detail::global_scope()->Find("mmdb_dir")->GetVal();
    std::string mmdb_dir = mmdb_dir_val->AsString()->CheckString();

    const auto& mmdb_city_db_val = zeek::detail::global_scope()->Find("mmdb_city_db")->GetVal();
    std::string mmdb_city_db = mmdb_city_db_val->AsString()->CheckString();

    const auto& mmdb_country_db_val = zeek::detail::global_scope()->Find("mmdb_country_db")->GetVal();
    std::string mmdb_country_db = mmdb_country_db_val->AsString()->CheckString();

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_city_db;

        if ( OpenFile(d.data()) )
            return true;

        d = mmdb_dir + "/" + mmdb_country_db;

        if ( OpenFile(d.data()) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::detail::global_scope()->Find("mmdb_dir_fallbacks")->GetVal();
    auto* vv = mmdb_dir_fallbacks_val->AsVectorVal();

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_city_db;
        if ( OpenFile(d.data()) )
            return true;
    }

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_country_db;
        if ( OpenFile(d.data()) )
            return true;
    }

    return false;
}

bool AsnDB::Open() {
    const auto& mmdb_dir_val = zeek::detail::global_scope()->Find("mmdb_dir")->GetVal();
    std::string mmdb_dir = mmdb_dir_val->AsString()->CheckString();

    const auto& mmdb_asn_db_val = zeek::detail::global_scope()->Find("mmdb_asn_db")->GetVal();
    std::string mmdb_asn_db = mmdb_asn_db_val->AsString()->CheckString();

    if ( ! mmdb_dir.empty() ) {
        auto d = mmdb_dir + "/" + mmdb_asn_db;

        if ( OpenFile(d.data()) )
            return true;
    }

    const auto& mmdb_dir_fallbacks_val = zeek::detail::global_scope()->Find("mmdb_dir_fallbacks")->GetVal();
    auto* vv = mmdb_dir_fallbacks_val->AsVectorVal();

    for ( unsigned int i = 0; i < vv->Size(); ++i ) {
        auto d = std::string(vv->StringAt(i)->CheckString()) + "/" + mmdb_asn_db;
        if ( OpenFile(d.data()) )
            return true;
    }

    return false;
}


static zeek::ValPtr mmdb_getvalue(MMDB_entry_data_s* entry_data, int status, int data_type) {
    switch ( status ) {
        case MMDB_SUCCESS:
            if ( entry_data->has_data ) {
                switch ( data_type ) {
                    case MMDB_DATA_TYPE_UTF8_STRING:
                        return zeek::make_intrusive<zeek::StringVal>(entry_data->data_size, entry_data->utf8_string);
                        break;

                    case MMDB_DATA_TYPE_DOUBLE:
                        return zeek::make_intrusive<zeek::DoubleVal>(entry_data->double_value);
                        break;

                    case MMDB_DATA_TYPE_UINT32: return zeek::val_mgr->Count(entry_data->uint32);

                    default: break;
                }
            }
            break;

        case MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR:
            // key doesn't exist, nothing to do
            break;

        default: MMDB::ReportMsg("MaxMind DB error [%s]", MMDB_strerror(status)); break;
    }

    return nullptr;
}

#endif // USE_GEOIP

ValPtr mmdb_open_location_db(StringVal* filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_loc.OpenFile(filename->CheckString()));
#else
    return zeek::val_mgr->False();
#endif
}

ValPtr mmdb_open_asn_db(StringVal* filename) {
#ifdef USE_GEOIP
    return zeek::val_mgr->Bool(mmdb_asn.OpenFile(filename->CheckString()));
#else
    return zeek::val_mgr->False();
#endif
}

RecordValPtr mmdb_lookup_location(AddrVal* addr) {
    static auto geo_location = zeek::id::find_type<zeek::RecordType>("geo_location");
    auto location = zeek::make_intrusive<zeek::RecordVal>(geo_location);

#ifdef USE_GEOIP
    mmdb_loc.Check();

    if ( ! mmdb_loc.IsOpen() && ! mmdb_loc.Open() ) {
        mmdb_loc.BuiltinError("Failed to open GeoIP location database");
        return location;
    }

    MMDB_lookup_result_s result;

    if ( mmdb_loc.Lookup(addr->AsAddr(), result) ) {
        MMDB_entry_data_s entry_data;
        int status;

        // Get Country ISO Code
        status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", nullptr);
        location->Assign(0, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get Major Subdivision ISO Code
        status = MMDB_get_value(&result.entry, &entry_data, "subdivisions", "0", "iso_code", nullptr);
        location->Assign(1, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get City English Name
        status = MMDB_get_value(&result.entry, &entry_data, "city", "names", "en", nullptr);
        location->Assign(2, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        // Get Location Latitude
        status = MMDB_get_value(&result.entry, &entry_data, "location", "latitude", nullptr);
        location->Assign(3, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_DOUBLE));

        // Get Location Longitude
        status = MMDB_get_value(&result.entry, &entry_data, "location", "longitude", nullptr);
        location->Assign(4, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_DOUBLE));

        return location;
    }

#else // not USE_GEOIP
    static int missing_geoip_reported = 0;

    if ( ! missing_geoip_reported ) {
        zeek::emit_builtin_error("Zeek was not configured for GeoIP support");
        missing_geoip_reported = 1;
    }
#endif

    // We can get here even if we have MMDB support if we weren't
    // able to initialize it or it didn't return any information for
    // the address.
    return location;
}

RecordValPtr mmdb_lookup_autonomous_system(AddrVal* addr) {
    static auto geo_autonomous_system = zeek::id::find_type<zeek::RecordType>("geo_autonomous_system");
    auto autonomous_system = zeek::make_intrusive<zeek::RecordVal>(geo_autonomous_system);

#ifdef USE_GEOIP
    mmdb_asn.Check();

    if ( ! mmdb_asn.IsOpen() && ! mmdb_asn.Open() ) {
        mmdb_asn.BuiltinError("Failed to open GeoIP ASN database");
        return autonomous_system;
    }

    MMDB_lookup_result_s result;

    if ( mmdb_asn.Lookup(addr->AsAddr(), result) ) {
        MMDB_entry_data_s entry_data;
        int status;

        // Get Autonomous System Number
        status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_number", nullptr);
        autonomous_system->Assign(0, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UINT32));

        // Get Autonomous System Organization
        status = MMDB_get_value(&result.entry, &entry_data, "autonomous_system_organization", nullptr);
        autonomous_system->Assign(1, mmdb_getvalue(&entry_data, status, MMDB_DATA_TYPE_UTF8_STRING));

        return autonomous_system;
    }

#else // not USE_GEOIP
    static int missing_geoip_reported = 0;

    if ( ! missing_geoip_reported ) {
        zeek::emit_builtin_error("Zeek was not configured for GeoIP ASN support");
        missing_geoip_reported = 1;
    }
#endif

    // We can get here even if we have GeoIP support, if we weren't
    // able to initialize it or it didn't return any information for
    // the address.
    return autonomous_system;
}

} // namespace zeek
