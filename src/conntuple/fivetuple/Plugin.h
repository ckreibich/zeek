// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/conntuple/Component.h"

namespace zeek::plugin::Zeek_Conntuple_Builder_Fivetuple {

class Plugin final : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
};

} // namespace zeek::plugin::Zeek_Conntuple_Builder_Fivetuple
