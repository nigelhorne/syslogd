#!/usr/bin/env perl

# Logic tests: each test is a small proof of one logical gate in the code,
# stated as premises and a conclusion.  Only the boundary that decides the
# gate is tested; values inside an already-proved partition are not.
#
# Major premises (always true, from the POD and the Z specification):
#	M1  open_socket() does nothing when a socket is open.
#	M2  run() opens the socket before its loop; open_socket() dies if it
#	    cannot.  _receive() runs only inside the loop.
#	M3  A log file is safe only if it is a regular file AND owned by us
#	    AND has exactly one link.
#	M4  A PRI is valid only if it matches the PRI pattern AND is <= 191.
#	M5  text() values are undef or a hash reference; nothing else.
#	M6  The caller's options are checked before Object::Configure can
#	    override them.
#	M7  Invariant: while run() is looping, the socket and the log are open
#	    (Z: running => bound /\ logging).
#
# Each subtest states its minor premise (the input) and proves the
# conclusion (the post-condition).

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Errno qw(EINTR);
use File::Spec;
use File::Temp qw(tempdir);
use Readonly;
use Socket qw(pack_sockaddr_in inet_aton);
use Test::Mockingbird;
use Test::Most;
use Test::Returns;

# Fake the owner or the link count that stat() reports, to prove each part
# of M3 on its own without root.  The real stat() still runs, so "-f _"
# (the file type) stays real.  Installed before App::Syslogd is compiled,
# because CORE::GLOBAL overrides only reach code compiled after them.
our %FAKE_STAT;
BEGIN {
	mock_core('stat' => sub {
		my ($real, @args) = @_;
		my @st = $real->(@args);
		return @st unless(@st);
		$st[4] = $main::FAKE_STAT{owner} if(exists($main::FAKE_STAT{owner}));
		$st[3] = $main::FAKE_STAT{links} if(exists($main::FAKE_STAT{links}));
		return @st;
	});
}

use App::Syslogd;
use App::Syslogd::I18N;

Readonly my %CONFIG => (
	peer_ip => '192.0.2.1',
	peer_name => 'sender.example.com',
	unprivileged_port => 5514,
	max_pri => 191,
	safe_links => 1,
	someone_else => $> + 1,		# a user id that is not ours
);

my $PEER = pack_sockaddr_in(514, inet_aton($CONFIG{peer_ip}));
my $dir = tempdir(CLEANUP => 1);
my $serial = 0;

sub new_path { return File::Spec->catfile($dir, 'logic' . ++$serial . '.csv') }

sub exact { my $message = shift; return qr/\A\Q$message\E at \S.* line \d+\.?\n?\z/s }

# A socket double whose recv() runs scripted steps
{
	package StepSocket;
	sub new { my ($class, @steps) = @_; return bless { steps => [@steps] }, $class }
	sub recv { my $self = $_[0]; my $step = shift(@{$self->{steps}}) or die "StepSocket: no steps left\n"; return $step->(\$_[1]) }
	sub sockport { return 1 }
	sub sockhost { return '127.0.0.1' }
	sub close { return 1 }
}

# ===========================================================================
# M1, M2: socket gates in run()
# ===========================================================================

subtest 'M1: run() may call open_socket() unconditionally' => sub {
	# Minor premise: a socket is already open.  By M1 open_socket() is a
	# no-op, so run() calling it must create nothing.  Conversely, with no
	# socket exactly one is created.
	my $created = 0;
	my $server;
	my $g = mock_scoped('IO::Socket::IP::new' => sub {
		$created++;
		return StepSocket->new(sub { $server->stop(); $! = EINTR; return undef });
	});

	$server = App::Syslogd->new(file => new_path(), resolve => 0,
		socket => StepSocket->new(sub { $server->stop(); $! = EINTR; return undef }));
	$server->run();
	is($created, 0, 'socket already open: none created');

	$server = App::Syslogd->new(file => new_path(), resolve => 0);
	$server->run();
	is($created, 1, 'no socket: exactly one created');
};

subtest 'M2: _receive() is unreachable without a socket' => sub {
	# Minor premise: open_socket() cannot bind.  By M2 run() dies there,
	# before the loop, so _receive() never runs; and because the socket is
	# opened first, the log is never touched (fail fast).
	my $g = mock_scoped('IO::Socket::IP::new' => sub { $IO::Socket::errstr = 'Permission denied'; return undef });
	my $receive = spy('App::Syslogd::_receive');
	my $open_log = spy('App::Syslogd::reopen_log');
	my $file = new_path();

	throws_ok { App::Syslogd->new(file => $file, port => $CONFIG{unprivileged_port})->run() }
		exact("Could not create a UDP socket on 0.0.0.0 port $CONFIG{unprivileged_port}: Permission denied"), 'dies in open_socket()';
	is(scalar(my @r = $receive->()), 0, '_receive() never ran');
	is(scalar(my @o = $open_log->()), 0, 'the log was never opened');
	ok(!-e $file, 'no file was created');
	restore_all();
};

subtest 'M7: while run() loops, the socket and the log are open' => sub {
	# Invariant from the Z specification: running => bound /\ logging.
	# Checked from inside the loop, at each step.
	my @states;
	my $server;
	my $check = sub { push @states, [($server->{socket} ? 1 : 0), ($server->{fh} ? 1 : 0)] };
	my $socket = StepSocket->new(
		sub { $check->(); ${$_[0]} = '<13>x'; return $PEER },
		sub { $check->(); $server->stop(); $! = EINTR; return undef },
	);
	$server = App::Syslogd->new(file => new_path(), resolve => 0, socket => $socket);
	$server->run();
	is_deeply(\@states, [[1, 1], [1, 1]], 'socket and log open at every step');
	ok(!$server->{socket} && !$server->{fh}, 'both released once the loop ends');
};

# ===========================================================================
# M3: the safe-file gate (an AND of three conditions)
# ===========================================================================

subtest 'M3: a log file is safe only if all three conditions hold' => sub {
	# A minimal truth table for an AND: all true accepts; each condition
	# false on its own refuses.  That proves every condition is needed.
	my $refused = sub { my $file = shift; return exact("Refusing to log to $file: it must be a regular file, owned by this user, with exactly one link") };

	my $good = new_path();
	lives_ok { App::Syslogd->new(file => $good)->reopen_log() } 'regular, ours, one link: accepted';

	{
		local %FAKE_STAT = (owner => $CONFIG{someone_else});
		my $file = new_path();
		throws_ok { App::Syslogd->new(file => $file)->reopen_log() } $refused->($file), 'owned by someone else: refused';
	}
	{
		local %FAKE_STAT = (links => $CONFIG{safe_links} + 1);
		my $file = new_path();
		throws_ok { App::Syslogd->new(file => $file)->reopen_log() } $refused->($file), 'two links: refused';
	}
	SKIP: {
		skip('no /dev/null here', 1) unless(-c '/dev/null');
		local %FAKE_STAT = (owner => $>, links => $CONFIG{safe_links});
		throws_ok { App::Syslogd->new(file => '/dev/null')->reopen_log() } $refused->('/dev/null'),
			'not a regular file (but ours, one link): refused';
	}
};

# ===========================================================================
# M4: the valid-PRI gate (match AND <= 191)
# ===========================================================================

subtest 'M4: a PRI is valid only if it matches and is at most 191' => sub {
	# Truth table: no match; match and 191 (the boundary, true); match and
	# 192 (the boundary, false).  Inside each partition nothing new is
	# decided, so no other values are needed.
	is(App::Syslogd->parse_message('<x>m')->{valid}, 0, 'no match: invalid');
	is(App::Syslogd->parse_message("<$CONFIG{max_pri}>m")->{valid}, 1, 'matches, 191: valid');
	is(App::Syslogd->parse_message('<' . ($CONFIG{max_pri} + 1) . '>m')->{valid}, 0, 'matches, 192: invalid');

	# Post-condition (Z: ParseMessage): an invalid PRI keeps the whole text
	is(App::Syslogd->parse_message('<192>m')->{message}, '<192>m', 'invalid: the whole text is the message');
	is(App::Syslogd->parse_message('<191>m')->{message}, 'm', 'valid: the text after the PRI');
};

# ===========================================================================
# Host gates in _peer_name, proved through process()
# ===========================================================================

subtest 'host: each gate of the sender lookup' => sub {
	# Gates, in order: not an address -> ""; resolution off -> address;
	# name found -> name; name not found -> address
	my $name = $CONFIG{peer_name};
	my $g = mock_scoped('App::Syslogd::getnameinfo' => sub {
		my (undef, $flags) = @_;
		return ('', $CONFIG{peer_ip}) if($flags & Socket::NI_NUMERICHOST());
		return defined($name) ? ('', $name) : ('Name or service not known', undef);
	});
	my $host_for = sub {
		my ($peer, %args) = @_;
		my $file = new_path();
		my $cache = bless {}, 'LogicCache';
		{ no strict 'refs'; *{'LogicCache::compute'} = sub { $_[3]->() } }
		App::Syslogd->new(file => $file, cache => $cache, %args)->reopen_log()->process('<13>x', $peer);
		open(my $fh, '<', $file) or die;
		my @lines = <$fh>;
		return $lines[1] =~ /\A"([^"]*)"/ ? $1 : undef;
	};

	is($host_for->(undef), '', 'not an address: empty');
	is($host_for->($PEER, resolve => 0), $CONFIG{peer_ip}, 'resolution off: the address');
	is($host_for->($PEER, resolve => 1), $CONFIG{peer_name}, 'name found: the name');
	$name = undef;
	is($host_for->($PEER, resolve => 1), $CONFIG{peer_ip}, 'name not found: the address');
};

# ===========================================================================
# Fail fast: the earliest guard decides
# ===========================================================================

subtest 'fail fast: process() checks the log before the datagram' => sub {
	# Minor premise: no log is open AND the datagram is a reference.  The
	# first guard (no log) must decide, before the datagram is looked at.
	throws_ok { App::Syslogd->new()->process(['<13>x'], $PEER) } exact('process() was called before reopen_log() succeeded'),
		'the no-log guard wins';
};

subtest 'M6: an invalid argument cannot be hidden by the environment' => sub {
	# Minor premise: the caller passes an invalid port and the environment
	# sets a valid one (which would win).  By M6 the caller's value is
	# checked first, so the mistake is still reported.  This is why the
	# first validation is not redundant with the second.
	local $ENV{App__Syslogd__port} = $CONFIG{unprivileged_port};
	throws_ok { App::Syslogd->new(port => 'abc') } qr/validate_strict: Parameter 'port' \(abc\) must be an integer/,
		'still refused';
	is(App::Syslogd->new(port => 1)->port(), $CONFIG{unprivileged_port}, 'a valid argument is overridden, as documented');
};

# ===========================================================================
# M5: the values domain of text()
# ===========================================================================

subtest 'M5 (regression): text() values are undef or a hash reference' => sub {
	# "||=" used to turn "" and 0 into "no values", so they were accepted
	# although M5 says they must die
	my $lh = App::Syslogd::I18N->handle('en');
	returns_ok($lh->text('open_failed', undef), { type => 'string' }, 'undef: accepted');
	returns_ok($lh->text('open_failed', {}), { type => 'string' }, 'a hash reference: accepted');
	foreach my $bad ('', 0, '0', 'x') {
		throws_ok { $lh->text('open_failed', $bad) }
			exact('Message values must be a hash reference (the type given was SCALAR)'), "'$bad': refused";
	}
	throws_ok { $lh->text('open_failed', []) }
		exact('Message values must be a hash reference (the type given was ARRAY)'), 'an array: refused';
};

# ===========================================================================
# The CSV gate: combine() alone decides
# ===========================================================================

subtest 'Text::CSV: when combine() succeeds, string() is defined' => sub {
	# The premise that let _csv_line drop its defined(string()) check,
	# proved for each kind of field the module writes
	my $csv = Text::CSV->new({ binary => 1, eol => "\n", always_quote => 1 });
	foreach my $fields (['h', 1, 5, 'plain'], ['', '', '', ''], ['h', 0, 0, 'say "hi", bye'],
		['h', 23, 7, '\x0A escaped'], ['h', 1, 5, "caf\xc3\xa9 \xff"]) {
		ok($csv->combine(@{$fields}), 'combine() succeeds');
		ok(defined($csv->string()), '...and string() is defined');
	}

	# And when combine() fails, the row is reported, not written
	my $file = new_path();
	my $server = App::Syslogd->new(file => $file, resolve => 0)->reopen_log();
	my $g = mock_scoped('Text::CSV::combine' => sub { 0 }, 'Text::CSV::error_diag' => sub { 'refused' });
	warning_like { $server->process('<13>x', $PEER) } exact("Could not write to log file $file: refused"), 'combine() fails: reported';
};

done_testing();
