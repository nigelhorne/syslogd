#!/usr/bin/env perl

# Simulated penetration tests for lib/App/Syslogd.pm.
#
# App::Syslogd is not a CGI program: it reads no HTTP request and writes
# CSV, not HTML.  Its real attack surface is (see SECURITY in the POD):
#	* UDP datagrams, from anyone who can reach the port
#	* reverse-DNS names, from whoever owns the sender's address
#	* the environment and configuration files (Object::Configure's
#	  App__Syslogd__* variables; LANG and friends for the language)
# Each classic web attack is therefore aimed at the input that carries it
# here, and each subtest also plants a hostile CGI environment (local
# %ENV) to prove the module ignores it.
#
# What must hold under attack:
#	* nothing is ever executed: system, exec and backticks are replaced
#	  (before the module is compiled) by recorders that must stay empty,
#	  and sentinel files that an injected command would create must not
#	  appear
#	* hostile text is stored as data, never interpreted, never splits a
#	  log line, and never reflected into warnings or errors
#	* hostile paths and NUL bytes are refused before anything is written
#	* under perl -T, tainted settings are refused, never untainted

use strict;
use warnings;

use FindBin qw($Bin);
use lib "$Bin/../lib";

use Errno qw(EINTR ENOSPC);
use File::Spec;
use File::Temp qw(tempdir);
use IPC::Open3 qw(open3);
use Readonly;
use Socket qw(pack_sockaddr_in inet_aton);
use Test::Mockingbird;
use Test::Most;
use Text::CSV;

# Record any attempt to run a program.  CORE::GLOBAL overrides reach only
# code compiled after them, so they are installed before App::Syslogd is
# loaded.  syswrite can be made to fail, to force the warning paths.
our (@EXECUTED, $DISK_FULL);
BEGIN {
	@EXECUTED = ();
	mock_core('system' => sub { my ($real, @args) = @_; push @main::EXECUTED, ['system', @args]; return -1 });
	mock_core('exec' => sub { my ($real, @args) = @_; push @main::EXECUTED, ['exec', @args]; return 0 });
	mock_core('readpipe' => sub { my ($real, @args) = @_; push @main::EXECUTED, ['backticks', @args]; return '' });
	mock_core('syswrite' => sub {
		my ($real, $fh, $buffer, $length, $offset) = @_;
		if($main::DISK_FULL) { $! = Errno::ENOSPC(); return undef }
		return $real->($fh, $buffer, $length // length($buffer), $offset // 0);
	});
}

use App::Syslogd;

my $dir = tempdir(CLEANUP => 1);

Readonly my %CONFIG => (
	peer_ip => '192.0.2.1',
	sentinel => File::Spec->catfile($dir, 'PWNED'),
	lib => File::Spec->catdir($Bin, File::Spec->updir(), 'lib'),
	header => [qw(Host facility severity msg)],
	default_port => 514,
);

# Shell payloads: each would create the sentinel file if a shell ever ran it
Readonly my @SHELL_PAYLOADS => (
	"; touch $CONFIG{sentinel}",
	"| touch $CONFIG{sentinel}",
	"`touch $CONFIG{sentinel}`",
	"\$(touch $CONFIG{sentinel})",
	"&& touch $CONFIG{sentinel}",
	"() { :;}; touch $CONFIG{sentinel}",	# Shellshock
);

# A hostile CGI request, planted in every subtest: none of it may matter
Readonly my %HOSTILE_CGI => (
	GATEWAY_INTERFACE => 'CGI/1.1',
	REQUEST_METHOD => 'POST',
	QUERY_STRING => 'file=/etc/passwd&port=1&language=../../etc/passwd',
	PATH_INFO => '/../../../etc/passwd%00.csv',
	HTTP_USER_AGENT => "() { :;}; touch $CONFIG{sentinel}",
	HTTP_REFERER => 'javascript:alert(document.cookie)',
	CONTENT_LENGTH => 32,
	HTTP_COOKIE => "file=/etc/passwd; port=1\r\nSet-Cookie: owned=1",
);
Readonly my $POST_BODY => 'file=/etc/passwd&resolve=0&port=1';

my $PEER = pack_sockaddr_in(514, inet_aton($CONFIG{peer_ip}));
my $serial = 0;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sub verbose_diag { diag(@_) if($ENV{TEST_VERBOSE}); return }

sub new_path { my $name = shift // ('pen' . ++$serial . '.csv'); return File::Spec->catfile($dir, $name) }

sub slurp { my $file = shift; open(my $fh, '<:raw', $file) or die "$file: $!"; local $/; return scalar(<$fh>) }

sub read_csv {
	my $file = shift;
	my $csv = Text::CSV->new({ binary => 1, decode_utf8 => 0 });
	open(my $fh, '<:raw', $file) or die "$file: $!";
	my $rows = $csv->getline_all($fh);
	close($fh);
	return $rows;
}

# Nothing ran and no injected command left its mark
sub nothing_executed {
	my $name = shift;
	is_deeply(\@EXECUTED, [], "$name: no program was run");
	ok(!-e $CONFIG{sentinel}, "$name: no injected command took effect");
	return;
}

# Record datagrams through a server and return the rows written
sub record {
	my (@datagrams) = @_;
	my $file = new_path();
	my $server = App::Syslogd->new(file => $file, resolve => 0)->reopen_log();
	$server->process($_, $PEER) foreach(@datagrams);
	return read_csv($file);
}

# Run a script in a child perl; returns (exit, stdout, stderr).  The code
# goes in a file (no -e quoting); @flags may add -T.
sub run_child {
	my ($code, @flags) = @_;
	my $script = new_path('child' . ++$serial . '.pl');
	open(my $fh, '>', $script) or die;
	print {$fh} "$code\n";
	close($fh);
	my ($out, $err) = map { new_path("child$serial.$_") } qw(out err);
	open(my $o, '>', $out) or die;
	open(my $e, '>', $err) or die;
	my $pid = open3(my $in, '>&' . fileno($o), '>&' . fileno($e), $^X, @flags, "-I$CONFIG{lib}", $script);
	close($in);
	waitpid($pid, 0);
	my $exit = $? >> 8;
	close($o);
	close($e);
	return ($exit, map { (my $t = slurp($_)) =~ s/\r\n/\n/g; $t } ($out, $err));
}

# ===========================================================================
# The CGI request is ignored
# ===========================================================================

subtest 'a hostile CGI request has no effect' => sub {
	# Exploit: an attacker who can set CGI variables (or the POST body)
	# tries to steer the log file, the port or the language.  The module
	# must read none of them, and must not touch STDIN.
	local %ENV = (%ENV, %HOSTILE_CGI);
	my $body = $POST_BODY;	# a copy: an in-memory handle cannot be opened on a Readonly scalar
	open(my $stdin, "<", \$body) or die;
	local *STDIN = $stdin;

	# resolve is left at its default, so the body's "resolve=0" would
	# show; a cache that answers with the address keeps the test off DNS
	my $file = new_path();
	my $cache = bless {}, 'AddressCache';
	{ no strict 'refs'; *{'AddressCache::compute'} = sub { $_[1] } }
	my $server = App::Syslogd->new(file => $file, cache => $cache)->reopen_log();
	$server->process('<13>normal', $PEER);
	is($server->port(), $CONFIG{default_port}, 'the port is not taken from QUERY_STRING or the body');
	is($server->{file}, $file, 'the file is not taken from QUERY_STRING, PATH_INFO or cookies');
	is($server->{resolve}, 1, 'resolve is not taken from the body');
	is(tell(STDIN), 0, 'STDIN (the POST body) was never read');
	is_deeply(read_csv($file)->[1], [$CONFIG{peer_ip}, 1, 5, 'normal'], 'logging works as normal');
	nothing_executed('hostile CGI environment');
};

# ===========================================================================
# Command injection
# ===========================================================================

subtest 'command injection through datagrams' => sub {
	# Exploit: shell metacharacters (and Shellshock) in a syslog message,
	# hoping something passes it to a shell.  Each must be stored as
	# plain text.
	local %ENV = (%ENV, %HOSTILE_CGI);
	my $rows = record(map { "<13>$_" } @SHELL_PAYLOADS);
	is_deeply([map { $_->[3] } @{$rows}[1 .. @SHELL_PAYLOADS]], [@SHELL_PAYLOADS], 'every payload stored as text, unchanged');
	nothing_executed('datagrams');
};

subtest 'command injection through settings' => sub {
	# Exploit: metacharacters in the file name, the address or the
	# language tag, as arguments or through App__Syslogd__* variables.
	# File names go to the system directly, never to a shell.
	local %ENV = (%ENV, %HOSTILE_CGI);
	foreach my $payload (@SHELL_PAYLOADS) {
		(my $name = $payload) =~ s{[/\\:]}{_}g;	# a single file name, no directories
		SKIP: {
			# Windows forbids | < > " * ? in file names
			skip('Windows does not allow these characters in file names', 2) if($^O eq 'MSWin32' && $name =~ /[|<>"*?]/);
			my $file = new_path("log $name.csv");
			lives_ok { App::Syslogd->new(file => $file, resolve => 0)->reopen_log()->process('<13>x', $PEER) } "file name '$name'";
			ok(-s $file, '...is used literally');
		}
		lives_ok { App::Syslogd->new(language => $payload) } "language '$payload' is only a tag";
		throws_ok { App::Syslogd->new(address => $payload, port => 0)->open_socket() } qr/\ACould not create a UDP socket on /,
			"address '$payload' is only refused by the resolver";
	}
	{
		local $ENV{App__Syslogd__port} = "514; touch $CONFIG{sentinel}";
		throws_ok { App::Syslogd->new() } qr/Parameter 'port' .* must be an integer/, 'App__Syslogd__port with a command: refused';
	}
	{
		my $file = new_path("env; touch PWNED.csv");
		local $ENV{App__Syslogd__file} = $file;
		lives_ok { App::Syslogd->new(resolve => 0)->reopen_log() } 'App__Syslogd__file with a command';
		ok(-e $file, '...is used literally as a file name');
	}
	nothing_executed('settings');
};

# ===========================================================================
# Path traversal and NUL bytes
# ===========================================================================

subtest 'path traversal through the file setting' => sub {
	# Exploit: point the log at a system file, by argument or through the
	# environment, so the server appends to it.  As an ordinary user it
	# must be refused (the file is not ours, or not writable).
	plan(skip_all => 'as root every file is "ours"; see SECURITY in the POD') if($> == 0);
	local %ENV = (%ENV, %HOSTILE_CGI);
	foreach my $target ('/etc/passwd', '../../../../../../../../etc/passwd', '/etc/shadow') {
		next unless(-e $target);
		my $before = slurp($target) if(-r $target);
		throws_ok { App::Syslogd->new(file => $target)->reopen_log() } qr/\A(?:Could not open log file|Refusing to log to) /, "file => '$target': refused";
		{
			local $ENV{App__Syslogd__file} = $target;
			throws_ok { App::Syslogd->new()->reopen_log() } qr/\A(?:Could not open log file|Refusing to log to) /, "App__Syslogd__file='$target': refused";
		}
		is(slurp($target), $before, "$target is unchanged") if(defined($before));
	}
};

subtest 'regression: NUL bytes are refused' => sub {
	# Exploit: a NUL truncates the string the C library sees.  An address
	# of "127.0.0.1\0.evil" bound to 127.0.0.1 while the server reported
	# the longer string; a file name could be cut short.  Refused at new().
	local %ENV = (%ENV, %HOSTILE_CGI);
	my %bad = (
		address => "127.0.0.1\0.evil.example",
		file => new_path('log.csv') . "\0../../../etc/passwd",
		language => "en\0../../x",
	);
	foreach my $option (sort keys %bad) {
		throws_ok { App::Syslogd->new($option => $bad{$option}) } qr/Parameter '$option' .*must match pattern/, "$option with a NUL: refused";
	}
	ok(!-e new_path('log.csv'), 'no truncated file was created');

	# A URL-encoded NUL is not decoded: it is just three characters
	my $encoded = new_path('log%00.csv');
	lives_ok { App::Syslogd->new(file => $encoded)->reopen_log() } 'a literal %00 is not decoded';
	ok(-e $encoded, '...and names exactly that file');
};

# ===========================================================================
# Script injection (XSS) and line injection (the CRLF equivalent)
# ===========================================================================

subtest 'markup is stored as data, never interpreted' => sub {
	# Exploit: <script> and other markup in a message, aimed at whatever
	# later displays the log.  The CSV is data: the markup must be kept
	# exactly (the viewer must HTML-encode it), must not break the CSV,
	# and must not change any other column.
	local %ENV = (%ENV, %HOSTILE_CGI);
	my @markup = ('<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "<svg/onload=alert('x')>", '&lt;script&gt;');
	my $rows = record(map { "<13>$_" } @markup);
	is(scalar(@{$rows}), @markup + 1, 'one row per message');
	is_deeply([map { $_->[3] } @{$rows}[1 .. @markup]], [@markup], 'stored exactly, not altered or decoded');
	is_deeply([map { [@{$_}[0 .. 2]] } @{$rows}[1 .. @markup]], [([$CONFIG{peer_ip}, 1, 5]) x @markup], 'no other column affected');
	nothing_executed('markup');
};

subtest 'line injection: CR and LF never split a record' => sub {
	# Exploit: the log-file version of CRLF header injection.  A message
	# (or a reverse-DNS name) with CR/LF tries to end its own line and
	# forge a second record, or rewrite the line on a terminal with \r.
	local %ENV = (%ENV, %HOSTILE_CGI);
	my $forged = qq{<13>ok\r\n"10.0.0.1","0","0","forged"\r\nSet-Cookie: owned=1\rhidden};
	my $file = new_path();
	my $g = mock_scoped('App::Syslogd::getnameinfo' => sub {
		my (undef, $flags) = @_;
		return ('', $CONFIG{peer_ip}) if($flags & Socket::NI_NUMERICHOST());
		return ('', "evil\r\nhost");
	});
	my $cache = bless {}, 'PenCache';
	{ no strict 'refs'; *{'PenCache::compute'} = sub { $_[3]->() } }
	App::Syslogd->new(file => $file, cache => $cache)->reopen_log()->process($forged, $PEER);
	my @lines = split(/\n/, slurp($file));
	is(scalar(@lines), 2, 'the header and exactly one record');
	unlike(slurp($file), qr/\r/, 'no carriage return reaches the file');
	like($lines[1], qr/\A"evil\\x0D\\x0Ahost","1","5","ok\\x0D\\x0A/, 'CR and LF written as \xNN in both columns');
};

subtest 'hostile data is never reflected into warnings or errors' => sub {
	# Exploit: get attacker text into the operator's error log (and from
	# there into another syslog, a terminal or a web page) by making a
	# write fail while processing it.
	local %ENV = (%ENV, %HOSTILE_CGI);
	my $payload = "<13><script>alert(1)</script>\r\nforged; touch $CONFIG{sentinel}";
	my $server = App::Syslogd->new(file => new_path(), resolve => 0)->reopen_log();
	my @warnings;
	{
		local $DISK_FULL = 1;
		local $SIG{__WARN__} = sub { push @warnings, $_[0] };
		$server->process($payload, $PEER);
	}
	verbose_diag(explain(\@warnings));
	is(scalar(@warnings), 1, 'one warning (the write failed)');
	unlike($warnings[0] // '', qr/script|forged|touch/, 'the warning carries none of the hostile text');
	nothing_executed('failed write');
};

# ===========================================================================
# Taint mode
# ===========================================================================

subtest 'taint mode: tainted settings are refused, not untainted' => sub {
	# Exploit: under perl -T, a tainted file name that slips through a
	# naive untainting regex (for example /^(.*)$/, which stops at a
	# newline, or one that ignores "..") reaches open().  The module does
	# no untainting, so every tainted file name must be refused.
	my $load = "use App::Syslogd;\n";

	my ($exit, $stdout, $stderr) = run_child($load
		. 'my $s = App::Syslogd->new(file => $ARGV[0], resolve => 0)->reopen_log();' . "\n"
		. 'my $tainted = substr($ENV{PATH}, 0, 0) . "<13>tainted data";' . "\n"
		. '$s->process($tainted, undef);' . "\n"
		. 'print "recorded ", $s->count(), "\n";', '-T');
	SKIP: {
		skip("this perl cannot run -T here: $stderr", 2) if($stderr =~ /taint mode not supported|-T is on the #!/i);
		is($stdout, "recorded 1\n", 'loads under -T and records tainted datagrams');
		is($exit, 0, 'exits cleanly');
	}

	my $safe_name = new_path('tainted.csv');
	foreach my $hostile ($safe_name, "$safe_name\n../../../etc/passwd", "$dir/../" . (File::Spec->splitdir($dir))[-1] . '/x.csv') {
		local $ENV{App__Syslogd__file} = $hostile;
		my ($code, $out, $err) = run_child($load . 'App::Syslogd->new(resolve => 0)->reopen_log(); print "OPENED\n";', '-T');
		(my $shown = $hostile) =~ s/\n/\\n/g;
		unlike($out, qr/OPENED/, "tainted file '$shown': not opened");
		like($err, qr/Insecure dependency/, '...refused by taint mode');
	}
	ok(!-e $safe_name, 'no tainted file was created');
};

subtest 'static check: no way to run a program' => sub {
	# The source must contain none of the calls that start a program, so
	# no input can ever reach a shell
	open(my $fh, '<', $INC{'App/Syslogd.pm'}) or die;
	my ($in_pod, @hits) = (0);
	while(my $line = <$fh>) {
		if($line =~ /\A=(\w+)/) { $in_pod = ($1 ne 'cut'); next }
		next if($in_pod || $line =~ /\A\s*#/);
		push @hits, "$.: $line" if($line =~ /\b(?:system|exec)\s*\(|\bqx\b|`|\bopen\s*\(.*['"]\s*[-|]|\|\s*['"]\s*\)|\beval\s*["']/);
	}
	is_deeply(\@hits, [], 'no system, exec, backticks, piped open or string eval');
};

done_testing();
