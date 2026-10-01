#!/usr/bin/env perl

# Every module compiles and loads

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib", "$Bin/../www/lib";

use Test::Most;

BEGIN {
	use_ok('Syslogd::Server::I18N');
	use_ok('Syslogd::Server');
	use_ok('VWF::Blacklist');
}

diag("Testing Syslogd::Server $Syslogd::Server::VERSION, Perl $], $^X");

done_testing();
