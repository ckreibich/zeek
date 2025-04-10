// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/fivetuple/Plugin.h"

#include "zeek/conntuple/Builder.h"
#include "zeek/conntuple/Component.h"

namespace zeek::plugin::Zeek_Conntuple_Builder_Fivetuple {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    // Just instantiate the conntuple::Builder: it already has the default
    // five-tuple behavior.
    AddComponent(new conntuple::Component("Fivetuple", zeek::conntuple::Builder::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Conntuple_Builder_Fivetuple";
    config.description = "Conntuple builder for Zeek's default five-tuples";
    return config;
}

} // namespace zeek::plugin::Zeek_Conntuple_Builder_Fivetuple
