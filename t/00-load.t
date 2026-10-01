#!/usr/bin/env perl

# Every module compiles and loads

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/../www/lib";

use Test::Most;

BEGIN {
	use_ok('App::Syslogd::I18N');
	use_ok('App::Syslogd');
	use_ok('VWF::Blacklist');
}

diag("Testing App::Syslogd $App::Syslogd::VERSION, Perl $], $^X");

done_testing();
