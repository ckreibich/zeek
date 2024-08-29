##! Switches Zeek's MaxMind file parsing to ipinfo.io's data layout.

redef lookup_location = ipinfo_lookup_location;
redef lookup_autonomous_system = ipinfo_lookup_autonomous_system;
