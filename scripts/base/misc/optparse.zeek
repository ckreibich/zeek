module Optparse;

export {
	type Opt: record {
		name: string &optional;
		longname: string &optional;
		desc: string &default="";
		required: bool &default=F;
		default_vals: vector of string &optional;

		args_label: string &default="ARG";
		args_min: count &default=0;
		args_max: int &default=0; # if < 0 unlimited, if 0 equal to args_min

		vals: vector of string &default=vector();
	};

	type OptVec: vector of Opt;

	type Arg: record {
		name: string;
		desc: string &default="";
	};

	type ArgVec: vector of Arg;

	type Result: record {
		# parsed options
		opts: table[string] of Opt &default=table();

		# a possible matched argument
		arg: Arg &optional;

		# remaining unconsumed arguments
		unparsed: vector of string &default=vector();
	};

	type Parser: record {
		name: string;
		summary: string;
		opts: table[string] of Opt &default=table();
		args: table[string] of Arg &default=table();
	};


	global make_parser: function(name: string, opts: OptVec,
	    summary: string &default=""): Parser;
	global make_arg_parser: function(name: string, args: ArgVec, opts: OptVec,
	    summary: string &default=""): Parser;
	global print_parser: function(parser: Parser);
	global parse: function(parser: Parser, args: vector of string &default=zeek_script_args): Result;
}

function opt_warning(msg: string)
	{
	print(fmt("option error: %s", msg));
	}

function opt_error(msg: string)
	{
	print(fmt("option error: %s", msg));
	exit(1);
	}

function make_parser(name: string, opts: OptVec, summary: string): Parser
	{
	local parser = Parser($name=name, $summary=summary);

	for ( i in opts )
		{
		local opt = opts[i];

		if ( ! opt?$name && ! opt?$longname )
			{
			opt_warning("skipping option without any names");
			next;
			}

		if ( opt?$name )
			{
			if ( opt$name in parser$opts )
				opt_error(fmt("more than one option named '%s'", opt$name));
			parser$opts[opt$name] = opt;
			}
		if ( opt?$longname )
			{
			if ( opt$longname in parser$opts )
				opt_error(fmt("more than one option named '%s'", opt$longname));
			parser$opts[opt$longname] = opt;
			}
		}

	return parser;
	}

function make_arg_parser(name: string, args: ArgVec, opts: OptVec, summary: string): Parser
	{
	local parser = make_parser(name, opts, summary);

	for ( i in args )
		{
		local arg = args[i];
		if ( arg$name in parser$args )
			opt_error(fmt("more than one argument named '%s'", arg$name));
		parser$args[arg$name] = arg;
		}

	return parser;
	}

function print_parser(parser: Parser)
	{
	local names_set: set[string];
	local opt: Opt;

	for ( name in parser$opts )
		{
		opt = parser$opts[name];

		if ( opt?$name )
			{
			if ( opt$name in names_set )
				next;
			add names_set[opt$name];
			next;
			}

		if ( opt?$longname )
			add names_set[opt$longname];
		}

	local names: vector of string;
	for ( name in names_set )
		names += name;
	names = sort(names, strcmp);

	local short_specs_mixed: vector of string;
	local short_specs_longname: vector of string;
	local long_specs_mixed: vector of string;
	local long_specs_longname: vector of string;

	for ( i in names )
		{
		local tags: vector of string = { };
		local args_label = "";

		opt = parser$opts[names[i]];

		if ( opt?$name )
			tags += fmt("-%s", opt$name);
		if ( opt?$longname )
			tags += fmt("--%s", opt$longname);

		local tag = join_string_vec(tags, "|");

		if ( opt$args_min != 0 || opt$args_max != 0 )
			{
			local repeat_spec = "";
			if ( opt$args_min > 0 && opt$args_max > 0 )
				repeat_spec = fmt("{%d,%d}", opt$args_min, opt$args_max);
			else if ( opt$args_min > 1 && opt$args_max >= 0 && opt$args_max <= opt$args_min )
				repeat_spec = fmt("{%d}", opt$args_min);
			else if ( opt$args_min > 1 && opt$args_max < 0 )
				repeat_spec = fmt("{%d,}", opt$args_min);
			else if ( opt$args_min == 1 && opt$args_max < 0 )
				repeat_spec = "+";
			else if ( opt$args_min == 0 && opt$args_max < 0 )
				repeat_spec = "*";
			else if ( opt$args_min == 0 && opt$args_max == 1 )
				repeat_spec = "?";
			args_label = fmt(" %s%s", opt$args_label, repeat_spec);
			}

		local spec = fmt("%s%s", tag, args_label);
		local desc = opt$desc;

		if ( opt?$default_vals )
			{
			if ( |opt$default_vals| == 1 )
				desc = fmt("%s (%s)", desc, opt$default_vals[0]);
			else
				desc = fmt("%s (%s)", desc, opt$default_vals);
			}

		if ( opt?$name )
			{
			short_specs_mixed += fmt("[%s]", spec);
			long_specs_mixed += fmt("    %-30s  %s", spec, desc);
			}
		else
			{
			short_specs_longname += fmt("[%s]", spec);
			long_specs_longname += fmt("    %-30s  %s", spec, desc);
			}
		}

	local args_short: vector of string;
	local args_long: vector of string;

	if ( |parser$args| > 0 )
		{
		names = vector();
		for ( n in parser$args )
			names += n;
		names = sort(names, strcmp);

		for ( i in names )
			{
			local a = parser$args[names[i]];
			args_short += a$name;
			args_long += fmt("    %-30s  %s", a$name, a$desc);
			}
		}


	print(fmt("Usage: %s %s %s %s", parser$name,
	    join_string_vec(short_specs_mixed, " "),
	    join_string_vec(short_specs_longname, " "),
	    fmt("[%s]", join_string_vec(args_short, "|"))));

	print("");

	if ( parser$summary != "" )
		print(parser$summary);

	print("");
	print("Options:");

	for ( i in long_specs_mixed )
		print(long_specs_mixed[i]);
	for ( i in long_specs_longname )
		print(long_specs_longname[i]);

	print("");

	if ( |parser$args| > 0 )
		{
		print("Arguments:");
		for ( i in args_long )
			print(args_long[i]);
		print("");
		}
	}

function opt_needs_arg(opt: Opt): bool
	{
	if ( opt$args_min > 0 && |opt$vals| < opt$args_min )
		return T;

	return F;
	}

function opt_allows_arg(opt: Opt): bool
	{
	if ( opt$args_max < 0 || ( opt$args_max > 0 && |opt$vals| < opt$args_max ) )
		return T;

	return F;
	}

function opt_name(opt: Opt): string
	{
	if ( opt?$name )
		return opt$name;

	return opt$longname;
	}

function parse(parser: Parser, args: vector of string): Result
	{
	local res = Result();
	local opt = Opt();
	local name: string;
	local n: string;

	for ( i in args )
		{
		local arg = args[i];

		if ( opt_needs_arg(opt) )
			{
			opt$vals += arg;
			next;
			}

		if ( opt_allows_arg(opt) && arg[0:1] != "-" )
			{
			opt$vals += arg;
			next;
			}

		name = "";

		if ( arg[0:2] == "--" )
			name = arg[2:];
		else if ( arg[0:1] == "-" )
			name = arg[1:];
		else
			{
			res$unparsed = args[i:];
			break;
			}

		if ( name !in parser$opts )
			{
			res$unparsed = args[i:];
			break;
			}

		opt = parser$opts[name];

		# Store the option in the results, under any of its names
		if ( opt?$name )
			res$opts[opt$name] = opt;
		if ( opt?$longname )
			res$opts[opt$longname] = opt;
		}

	# Do a pass over the parser's options to see if we can add
        # anything that wasn't given but that has a default value.
	for ( name, opt in parser$opts )
		{
		n = opt_name(opt);
		if ( n !in res$opts && opt?$default_vals )
			{
			opt$vals = opt$default_vals;

			if ( opt?$name )
				res$opts[opt$name] = opt;
			if ( opt?$longname )
				res$opts[opt$longname] = opt;
			}
		}

	# And another pass to see if all required options are there:
	for ( name, opt in parser$opts )
		{
		n = opt_name(opt);
		if ( opt$required && n !in res$opts )
			opt_error(fmt("required option '%s' not provided", n));
		}

	# If this parser has arguments, now see whether the first of
        # any leftover arguments matches one of the defined ones.
	if ( |res$unparsed| > 0 && res$unparsed[0] in parser$args )
		{
		res$arg = parser$args[res$unparsed[0]];
		res$unparsed = res$unparsed[1:];
		}

	return res;
	}
