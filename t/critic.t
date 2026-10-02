#!/usr/bin/env perl

# Author test: Perl::Critic at its default severity (5, "gentle")

use strict;
use warnings;

use Test::Most;
use Test::Needs 'Test::Perl::Critic';

Test::Perl::Critic->import();
all_critic_ok(qw(lib etc/syslogd));
