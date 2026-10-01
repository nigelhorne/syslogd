package Syslogd::Server;

use strict;
use warnings;
use autodie qw(:all);

# Sub::Private's enforce mode must be chosen before the module is loaded,
# otherwise :Private subs are removed from the stash and $self->_x() breaks
BEGIN { $Sub::Private::config{mode} = 'enforce' }
use Sub::Private;
use Sub::Protected;

use Carp qw(carp croak);
use CHI;
use Fcntl qw(O_WRONLY O_APPEND O_CREAT O_NOFOLLOW);
use IO::Handle;
use IO::Socket::IP;
use Params::Get;
use Params::Validate::Strict;
use Readonly;
use Socket qw(getnameinfo NI_NAMEREQD NI_NUMERICHOST NIx_NOSERV);
use Text::CSV;

use Syslogd::Server::I18N;

our $VERSION = '0.02';

# Every tunable lives here, so it can be overridden from new() and so
# nothing in the code below is a magic number
Readonly our %DEFAULTS => (
	port => 514,			# RFC 5426 well-known port
	address => '0.0.0.0',		# IPv4 wildcard, as the original script used
	file => '/tmp/syslog.log',	# Kept for compatibility; see LIMITATIONS
	resolve => 1,			# Log host names rather than addresses
	dns_ttl => 300,			# Seconds to remember a reverse lookup
	dns_cache_bytes => 262_144,	# Upper bound on the reverse-lookup cache
);

# Largest possible UDP payload, so datagrams are never silently truncated
# (RFC 5426 section 3.2 asks receivers to accept at least 2048 octets)
Readonly my $RECV_BUFFER => 65_535;

# One-character datagrams are keep-alives or noise, never a log line
Readonly my $MIN_MESSAGE_LENGTH => 2;

# PRI = facility * 8 + severity; RFC 5424 section 6.2.1 caps it at 191
Readonly my $SEVERITIES_PER_FACILITY => 8;
Readonly my $MAX_PRI => 191;

# RFC 3164 section 4.3.3: a message without a valid PRI is user.notice
Readonly my $DEFAULT_PRI => 13;

# The log holds other hosts' messages, so only its owner may read it
Readonly my $LOG_MODE => 0600;

# Column headings written to a brand-new log file.  VWF::Data::syslog_log
# reads these as its column names, so do not change them lightly.
Readonly my @CSV_HEADER => qw(Host facility severity msg);

# Parameter schema shared by new() and the API SPECIFICATION in the POD
Readonly my %NEW_SCHEMA => (
	port => { type => 'integer', min => 0, max => 65_535, optional => 1 },
	address => { type => 'string', min => 1, optional => 1 },
	file => { type => 'string', min => 1, optional => 1 },
	resolve => { type => 'boolean', optional => 1 },
	dns_ttl => { type => 'integer', min => 0, optional => 1 },
	dns_cache_bytes => { type => 'integer', min => 1, optional => 1 },
	language => { type => 'string', min => 1, optional => 1 },
	cache => { type => 'object', can => ['compute'], optional => 1 },
	socket => { type => 'object', can => ['recv'], optional => 1 },
);

=encoding utf8

=head1 NAME

Syslogd::Server - A small UDP syslog receiver that writes a CSV file

=head1 VERSION

Version 0.02

=head1 SYNOPSIS

	use Syslogd::Server;

	my $server = Syslogd::Server->new(port => 5514, file => '/var/log/remote.csv');
	$server->open_socket()->reopen_log();
	print $server->i18n('listening', { address => '0.0.0.0', port => $server->port() }), "\n";
	$server->run();		# returns after SIGTERM or SIGINT

=head1 DESCRIPTION

Receives RFC 3164 / RFC 5424 syslog datagrams over UDP, splits the PRI
field into facility and severity, and appends one CSV row per datagram:

	"Host","facility","severity","msg"

=over 4

=item * B<SIGHUP> closes and reopens the log file, for use with logrotate.

=item * B<SIGTERM> and B<SIGINT> make C<run()> return cleanly.

=item * Control characters (including embedded newlines) in a message are
written as C<\xNN>, so every record is exactly one line and nobody can
forge a record by sending a newline.

=item * A datagram without a valid PRI is recorded as C<user.notice> (PRI 13),
as RFC 3164 section 4.3.3 requires, with the whole datagram as the message.

=back

=head1 METHODS

=head2 new

Purpose: create a server object.  Nothing is bound or opened yet, so the
object can be built and inspected without privileges.

Args (all optional, as a hash or hashref):

=over 4

=item * C<port> - UDP port, default 514.  0 lets the kernel choose; call
C<port()> after C<open_socket()> to see which.

=item * C<address> - local address to bind, default C<0.0.0.0>.  Use C<::> for
IPv6.

=item * C<file> - CSV log file, default F</tmp/syslog.log>.

=item * C<resolve> - log host names (true, default) or addresses (false).

=item * C<dns_ttl>, C<dns_cache_bytes> - reverse-lookup cache tuning.

=item * C<language> - message language tag; default is from the environment.

=item * C<cache> - a L<CHI>-compatible object used instead of the built-in
reverse-lookup cache.

=item * C<socket> - an already-bound socket (anything with C<recv>), mainly
for tests and socket activation.

=back

Returns: a blessed C<Syslogd::Server>.

Side Effects: none.

Usage:

	my $server = Syslogd::Server->new({ port => 514, resolve => 0 });

=head3 EXAMPLE

	# Listen on an unprivileged port and log addresses, not names
	my $server = Syslogd::Server->new(port => 5514, resolve => 0);

=head3 API SPECIFICATION

=head4 INPUT

	{
		port => { type => 'integer', min => 0, max => 65535, optional => 1 },
		address => { type => 'string', min => 1, optional => 1 },
		file => { type => 'string', min => 1, optional => 1 },
		resolve => { type => 'boolean', optional => 1 },
		dns_ttl => { type => 'integer', min => 0, optional => 1 },
		dns_cache_bytes => { type => 'integer', min => 1, optional => 1 },
		language => { type => 'string', min => 1, optional => 1 },
		cache => { type => 'object', can => ['compute'], optional => 1 },
		socket => { type => 'object', can => ['recv'], optional => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

	+-------------------------------+------------------------+---------------------------+
	| Message                       | Meaning                | Resolution                |
	+-------------------------------+------------------------+---------------------------+
	| validate_strict: Unknown      | Misspelt argument      | Check the argument list   |
	|   parameter 'x'               |                        |   above                   |
	| validate_strict: Parameter    | Out-of-range value     | Use a port in 0..65535    |
	|   'port' ... must be ...      |                        |                           |
	+-------------------------------+------------------------+---------------------------+

=head3 FORMAL SPECIFICATION

	[ADDRESS, PATH, LANGTAG]
	PORT == 0 .. 65535

	Server
	  port : PORT ; address : ADDRESS ; file : PATH ; resolve : 𝔹
	  count : ℕ ; listening, logging, running : 𝔹

	New
	  Server'
	  args? : NAME ⇸ VALUE
	  ─────────
	  dom args? ⊆ dom NEW_SCHEMA
	  port' = args?(port) if port ∈ dom args? else 514
	  file' = args?(file) if file ∈ dom args? else /tmp/syslog.log
	  count' = 0 ∧ ¬listening' ∧ ¬logging' ∧ ¬running'

=cut

sub new
{
	my $class = shift;

	# Accept a hash, a hashref or nothing at all
	my $args = Params::Validate::Strict::validate_strict({
		schema => \%NEW_SCHEMA,
		input => Params::Get::get_params(undef, \@_) || {},
	});

	# Caller's values win over defaults
	my $self = bless { %DEFAULTS, %{$args}, count => 0 }, $class;

	# One handle per object: two servers in one process may speak
	# different languages
	$self->{lh} = Syslogd::Server::I18N->handle($self->{language});

	# Reverse DNS is synchronous; without a cache one slow resolver would
	# stall the receive loop for every packet from that host
	$self->{cache} ||= CHI->new(
		driver => 'Memory',
		datastore => {},
		max_size => $self->{dns_cache_bytes},
	);

	# binary => 1 permits non-ASCII bytes; always_quote matches the
	# header row style the original script wrote
	$self->{csv} = Text::CSV->new({ binary => 1, eol => "\n", always_quote => 1 });

	return $self;
}

=head2 open_socket

Purpose: bind the UDP socket.  Do this before dropping privileges if the port
is below 1024.

Args: none.

Returns: C<$self>, for chaining.

Side Effects: binds a socket.  Does nothing if a socket was given to C<new()>.

Usage:

	$server->open_socket();

=head3 EXAMPLE

	my $server = Syslogd::Server->new(port => 0)->open_socket();
	print 'Kernel chose port ', $server->port(), "\n";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

	+--------------------------------+-------------------------+----------------------------+
	| Message                        | Meaning                 | Resolution                 |
	+--------------------------------+-------------------------+----------------------------+
	| Could not create a UDP socket  | bind() failed: port in  | Run as root for port 514,  |
	|   on ADDR port N: ERROR        |   use, no permission or |   stop the other syslogd,  |
	|                                |   bad address           |   or fix --address         |
	+--------------------------------+-------------------------+----------------------------+

=head3 FORMAL SPECIFICATION

	OpenSocket
	  ΔServer
	  ─────────
	  listening' ∧ (port = 0 ⇒ port' ∈ 1 .. 65535) ∧ (port ≠ 0 ⇒ port' = port)

=cut

sub open_socket
{
	my $self = shift;

	# IO::Socket::IP handles both families; IO::Socket::INET is IPv4-only
	$self->{socket} ||= IO::Socket::IP->new(
		LocalHost => $self->{address},
		LocalPort => $self->{port},
		Proto => 'udp',
	) || croak($self->i18n('socket_failed', {
		address => $self->{address},
		port => $self->{port},
		error => $IO::Socket::errstr || "$!",
	}));

	return $self;
}

=head2 port

Purpose: the UDP port actually in use.

Args: none.

Returns: an integer.  After C<open_socket()> with C<port =E<gt> 0> this is the
kernel-assigned port; before C<open_socket()> it is the configured port.

Side Effects: none.

Usage:

	my $port = $server->port();

=head3 EXAMPLE

	print Syslogd::Server->new()->port(), "\n";	# 514

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0, max => 65535 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Port
	  ΞServer
	  p! : PORT
	  ─────────
	  p! = port

=cut

sub port
{
	my $self = shift;

	# An injected test socket may not know its port, so ask only real ones
	my $socket = $self->{socket};

	return ($socket && $socket->can('sockport')) ? $socket->sockport() : $self->{port};
}

=head2 address

Purpose: the local address the socket is bound to.

Args: none.

Returns: a string.  After C<open_socket()> this is what the kernel reports;
before it, the configured address.

Side Effects: none.

Usage:

	my $address = $server->address();

=head3 EXAMPLE

	print Syslogd::Server->new(address => "::")->address(), "\n";	# ::

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => "string", min => 1 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Address
	  ΞServer
	  a! : ADDRESS
	  ─────────
	  a! = address

=cut

sub address
{
	my $self = shift;

	# Mirrors port(): injected test sockets need not know their address
	my $socket = $self->{socket};

	return ($socket && $socket->can("sockhost")) ? $socket->sockhost() : $self->{address};
}

=head2 count

Purpose: the number of datagrams recorded so far.

Args: none.

Returns: a non-negative integer.

Side Effects: none.

Usage:

	print $server->count(), " messages\n";

=head3 EXAMPLE

	$server->process("<13>hello", $peer);
	print $server->count(), "\n";	# 1

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0 }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Count
	  ΞServer
	  n! : ℕ
	  ─────────
	  n! = count

=cut

sub count
{
	my $self = shift;

	return $self->{count};
}

=head2 reopen_log

Purpose: (re)open the CSV log.  Called at start-up and on SIGHUP, so that
after logrotate renames the file a fresh one is created.

Args: none.

Returns: C<$self>, for chaining.

Side Effects: closes any open log; creates the file with mode 0600 if absent
and writes the header row if it is empty; forces mode 0600 on an existing
file.

Usage:

	$server->reopen_log();

=head3 EXAMPLE

	# logrotate postrotate script:  kill -HUP $(cat /run/syslogd.pid)
	# ...which, inside run(), calls:
	$server->reopen_log();

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

	+------------------------------+------------------------------+--------------------------------+
	| Message                      | Meaning                      | Resolution                     |
	+------------------------------+------------------------------+--------------------------------+
	| Could not open log file F:   | open(2) failed; ERROR is $!  | Create the directory or fix    |
	|   ERROR                      |   in the current locale      |   its permissions              |
	| Refusing to log to F: it     | F is a symlink, a hard link, | Remove F and let the server    |
	|   must be a regular file ... |   or owned by someone else   |   create it                    |
	+------------------------------+------------------------------+--------------------------------+

=head3 FORMAL SPECIFICATION

	ReopenLog
	  ΔServer
	  ─────────
	  logging'
	  owner(file) = euid ∧ links(file) = 1 ∧ mode(file) = 0600
	  size(file) = 0 ⇒ contents'(file) = ⟨HEADER⟩

=cut

sub reopen_log
{
	my $self = shift;

	# Closing first means a failed reopen leaves no stale handle that
	# would silently keep writing to the rotated file
	$self->_close_log();
	$self->{fh} = $self->_open_log();

	return $self;
}

=head2 parse_message

Purpose: split a raw datagram into facility, severity and message.  Pure: it
touches no state, so it can be used and tested on its own.

Args: the raw datagram (a byte string).

Returns: C<undef> for datagrams too short to be a message, otherwise a
hashref:

	{ facility => 0..23, severity => 0..7, message => '...', valid => 0|1 }

C<valid> is false when the PRI was missing or out of range; the record is
then user.notice and C<message> is the whole datagram.

Side Effects: none.

Usage:

	my $rec = Syslogd::Server->parse_message('<34>su: root failed');

=head3 EXAMPLE

	my $rec = Syslogd::Server->parse_message("<34>su: 'su root' failed\n");
	# { facility => 4, severity => 2, message => "su: 'su root' failed", valid => 1 }

	$rec = Syslogd::Server->parse_message("no pri\there");
	# { facility => 1, severity => 5, message => 'no pri\x09here', valid => 0 }

=head3 API SPECIFICATION

=head4 INPUT

	{
		datagram => { type => 'string', position => 0 },
	}

=head4 OUTPUT

	{
		type => 'hashref',
		optional => 1,
		schema => {
			facility => { type => 'integer', min => 0, max => 23 },
			severity => { type => 'integer', min => 0, max => 7 },
			message => { type => 'string', matches => qr/\A[^\x00-\x1F\x7F]*\z/ },
			valid => { type => 'boolean' },
		},
	}

=head3 MESSAGES

None; malformed input is recorded, never rejected.

=head3 FORMAL SPECIFICATION

	ParseMessage
	  d? : seq BYTE
	  r! : RECORD ∪ {⊥}
	  ─────────
	  let t == stripTrailing({CR, LF, NUL}, d?) •
	  #t < 2 ⇒ r! = ⊥
	  #t ≥ 2 ∧ t = ⟨'<'⟩ ⁀ digits(p) ⁀ ⟨'>'⟩ ⁀ b ∧ p ≤ 191 ⇒
	    r! = ⟨facility ↦ p div 8, severity ↦ p mod 8, message ↦ escape(b), valid ↦ true⟩
	  otherwise ⇒
	    r! = ⟨facility ↦ 1, severity ↦ 5, message ↦ escape(t), valid ↦ false⟩

=head3 PSEUDOCODE

	strip trailing CR, LF and NUL
	if fewer than 2 characters remain: return undef
	if text is "<" PRI ">" BODY with PRI a canonical integer <= 191:
		valid = true
	else:
		PRI = 13, BODY = whole text, valid = false
	return { PRI div 8, PRI mod 8, escape_controls(BODY), valid }

=cut

sub parse_message
{
	my ($self, $datagram) = @_;

	# Senders disagree about terminators: "\n", "\r\n" and "\0" are all seen
	(my $text = $datagram // '') =~ s/[\r\n\0]+\z//;

	return undef if(length($text) < $MIN_MESSAGE_LENGTH);

	# 1-3 digits, no leading zeros except "<0>" itself (RFC 5424 6.2.1)
	my ($pri, $body) = $text =~ /\A<(0|[1-9][0-9]{0,2})>(.*)\z/s;
	my $valid = (defined($pri) && ($pri <= $MAX_PRI)) ? 1 : 0;

	# RFC 3164 4.3.3: keep the whole datagram rather than discarding it
	($pri, $body) = ($DEFAULT_PRI, $text) unless($valid);

	return {
		facility => int($pri / $SEVERITIES_PER_FACILITY),
		severity => $pri % $SEVERITIES_PER_FACILITY,
		message => _escape_controls($body),
		valid => $valid,
	};
}

=head2 process

Purpose: record one received datagram.

Args: the raw datagram, and the sender's packed C<sockaddr> as returned by
C<recv>.

Returns: C<$self>, for chaining.

Side Effects: may perform a reverse DNS lookup (cached); appends one row to
the log; increments C<count>.  A write failure is reported with C<carp> and
the datagram is dropped, so a full disk does not kill the daemon.

Usage:

	my $peer = $socket->recv(my $data, 65535);
	$server->process($data, $peer);

=head3 EXAMPLE

	use Socket qw(pack_sockaddr_in inet_aton);
	my $peer = pack_sockaddr_in(514, inet_aton('192.0.2.1'));
	$server->reopen_log()->process('<13>hello', $peer);

=head3 API SPECIFICATION

=head4 INPUT

	{
		datagram => { type => 'string', position => 0 },
		peer => { type => 'string', min => 1, position => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

	+-----------------------------+----------------------------+----------------------------+
	| Message                     | Meaning                    | Resolution                 |
	+-----------------------------+----------------------------+----------------------------+
	| process() was called before | No log file is open        | Call reopen_log() first    |
	|   reopen_log() succeeded    |   (croak)                  |                            |
	| Could not write to log file | write(2) failed, e.g. disk | Free space; the datagram   |
	|   F: ERROR                  |   full (carp)              |   was lost                 |
	+-----------------------------+----------------------------+----------------------------+

=head3 FORMAL SPECIFICATION

	Process
	  ΔServer
	  d? : seq BYTE ; peer? : SOCKADDR
	  ─────────
	  logging
	  ParseMessage(d?) = ⊥ ⇒ count' = count ∧ contents' = contents
	  ParseMessage(d?) = r ≠ ⊥ ⇒
	    count' = count + 1 ∧
	    contents'(file) = contents(file) ⁀ ⟨csv(host(peer?), r)⟩

=cut

sub process
{
	my ($self, $datagram, $peer) = @_;

	croak($self->i18n('no_log_open')) unless($self->{fh});

	# Too-short datagrams are dropped quietly, as the original script did
	if(my $record = $self->parse_message($datagram)) {
		my $host = $self->_peer_name($peer);
		$self->_write_row([$host, @{$record}{qw(facility severity message)}]);
		$self->{count}++;
	}

	return $self;
}

=head2 run

Purpose: the receive loop.

Args: none.

Returns: C<$self>, after SIGTERM, SIGINT or C<stop()>.

Side Effects: calls C<open_socket()> and C<reopen_log()> if they have not been
called; installs SIGHUP, SIGTERM and SIGINT handlers for its duration only
(the caller's handlers are restored on return); closes the socket and the
log on return.

Usage:

	$server->run();

=head3 EXAMPLE

	my $server = Syslogd::Server->new(port => 5514, file => '/var/log/remote.csv');
	$server->run();
	print $server->i18n('shutdown', { count => $server->count() }), "\n";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

	+-------------------------------+----------------------------+-------------------------+
	| Message                       | Meaning                    | Resolution              |
	+-------------------------------+----------------------------+-------------------------+
	| Error receiving a datagram:   | recv(2) failed for a       | Usually transient;      |
	|   ERROR                       |   reason other than EINTR  |   logged and retried    |
	|                               |   (carp)                   |                         |
	| (any open_socket() or reopen_log() | Start-up or SIGHUP reopen  | See those methods       |
	|   message)                    |   failed (croak)           |                         |
	+-------------------------------+----------------------------+-------------------------+

=head3 FORMAL SPECIFICATION

	Run ≙ (OpenSocket ⨾ ReopenLog) ⨾ Loop
	Loop ≙ μ L • (¬running ∧ Close) □
	             (running ∧ hup ∧ ReopenLog ⨾ L) □
	             (running ∧ ¬hup ∧ Receive ⨾ Process ⨾ L)

=head3 PSEUDOCODE

	listen and open the log if not already done
	install HUP -> "reopen requested", TERM/INT -> "stop"
	while running:
		if reopen requested: reopen the log
		wait for a datagram
		if interrupted by a signal: loop again (to act on the flag)
		if any other error: warn and loop again
		process the datagram
	close socket and log
	restore previous signal handlers

=cut

sub run
{
	my $self = shift;

	$self->open_socket() unless($self->{socket});
	$self->reopen_log() unless($self->{fh});

	# Handlers only set flags: Perl's deferred signals make that safe, and
	# the real work then happens at a known point in the loop below
	local $SIG{HUP} = sub { $self->{reopen_requested} = 1 };
	local $SIG{TERM} = local $SIG{INT} = sub { $self->{running} = 0 };

	$self->{running} = 1;
	while($self->{running}) {
		# Perl does not use SA_RESTART, so a signal interrupts recv()
		# and we get here promptly to act on it
		if($self->{reopen_requested}) {
			$self->{reopen_requested} = 0;
			$self->reopen_log();
		}

		my $peer = $self->_receive(\my $datagram);
		$self->process($datagram, $peer) if($peer);
	}

	$self->_shutdown();

	return $self;
}

=head2 stop

Purpose: ask C<run()> to return after the current datagram.

Args: none.

Returns: C<$self>.

Side Effects: clears the running flag.

Usage:

	$server->stop();

=head3 EXAMPLE

	local $SIG{ALRM} = sub { $server->stop() };
	alarm 60;	# run for a minute
	$server->run();

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'Syslogd::Server' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Stop
	  ΔServer
	  ─────────
	  ¬running'

=cut

sub stop
{
	my $self = shift;

	$self->{running} = 0;

	return $self;
}

=head2 i18n

Purpose: render a user-facing message in the server's language.

Args: a message key and an optional hashref of named arguments.  May be
called as a class method (e.g. for a usage message before C<new()>), in which
case the language comes from the environment.

Returns: the rendered string.

Side Effects: none.

Usage:

	croak $self->i18n('open_failed', { file => $file, error => "$!" });

=head3 EXAMPLE

	print Syslogd::Server->i18n('shutdown', { count => 3 }), "\n";
	# Syslog server shutting down after recording 3 messages

=head3 API SPECIFICATION

=head4 INPUT

	{
		key => { type => 'string', min => 1, position => 0 },
		args => { type => 'hashref', optional => 1, position => 1 },
	}

=head4 OUTPUT

	{ type => 'string' }

=head3 MESSAGES

	+----------------+------------------------------------------------+
	| Key            | English text                                   |
	+----------------+------------------------------------------------+
	| usage          | Usage: PROGRAM [--port ...] ...                |
	| listening      | Syslog server listening on ADDR UDP port N     |
	| shutdown       | ... shutting down after recording N message(s) |
	| socket_failed  | Could not create a UDP socket on ADDR port N   |
	| open_failed    | Could not open log file F: ERROR               |
	| unsafe_file    | Refusing to log to F: ...                      |
	| write_failed   | Could not write to log file F: ERROR           |
	| recv_failed    | Error receiving a datagram: ERROR              |
	| not_listening  | run() was called before open_socket() ...       |
	| no_log_open    | process() was called before reopen_log() ...   |
	+----------------+------------------------------------------------+

=head3 FORMAL SPECIFICATION

	I18n
	  key? : KEY ; args? : NAME ⇸ VALUE ; out! : STRING
	  ─────────
	  out! = Text(handle(language), key?, args?)

=cut

sub i18n
{
	my ($self, $key, $args) = @_;

	# Class-method calls have no object and so no stored handle
	my $lh = ref($self) ? $self->{lh} : Syslogd::Server::I18N->handle();

	return $lh->text($key, $args);
}

# ---------------------------------------------------------------------------
# Private and protected helpers
# ---------------------------------------------------------------------------

# _receive
# Purpose:	wait for one datagram.
# Entry:	$self->{socket} set; $buffer_ref a scalar ref to fill.
# Exit:		the sender's sockaddr, or undef if interrupted or on error.
# Side Effects:	carps on errors other than EINTR.
sub _receive :Private
{
	my ($self, $buffer_ref) = @_;

	croak($self->i18n('not_listening')) unless($self->{socket});

	my $peer = $self->{socket}->recv(${$buffer_ref}, $RECV_BUFFER);

	# EINTR is how a signal wakes us; it is expected, not an error
	if(!defined($peer) && !$!{EINTR}) {
		carp($self->i18n('recv_failed', { error => "$!" }));
	}

	return $peer;
}

# _open_log
# Purpose:	open $self->{file} for appending, safely.
# Entry:	$self->{file} set.
# Exit:		an autoflushed filehandle; croaks on failure.
# Side Effects:	may create the file (mode 0600) and write the header row;
#		chmods an existing file to 0600.
sub _open_log :Private
{
	my $self = shift;
	my $file = $self->{file};

	# O_NOFOLLOW: the default lives in /tmp, where anyone could plant a
	# symlink to /etc/shadow before root starts us.  O_APPEND: rows from
	# one write() are never interleaved with another writer's.
	my $fh;
	{
		no autodie qw(sysopen);
		sysopen($fh, $file, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, $LOG_MODE)
			or croak($self->i18n('open_failed', { file => $file, error => "$!" }));
	}

	# O_NOFOLLOW cannot catch a hard link or a file someone else pre-created
	# for us to fill with their reading material, so check after opening
	my @st = stat($fh);
	if((!-f _) || ($st[4] != $>) || ($st[3] != 1)) {
		croak($self->i18n('unsafe_file', { file => $file }));
	}

	# Tighten an existing file too: previous versions created it 0644
	chmod($LOG_MODE, $fh);
	binmode($fh);
	$fh->autoflush(1);

	# Header only on an empty file, so a reopened file is not given a
	# second header row half way down
	$self->_write_header($fh) if(-z $fh);

	return $fh;
}

# _write_header
# Purpose:	put the column headings at the top of a new log.
# Entry:	$fh open on an empty file.
# Exit:		$self.
# Side Effects:	writes one line; croaks if it cannot, since a log that
#		cannot take its first line will not take any others.
sub _write_header :Private
{
	my ($self, $fh) = @_;

	$self->{csv}->combine(@CSV_HEADER);
	print { $fh } $self->{csv}->string()
		or croak($self->i18n('write_failed', { file => $self->{file}, error => "$!" }));

	return $self;
}

# _close_log
# Purpose:	close the log if it is open.
# Entry:	none.
# Exit:		$self; $self->{fh} is undef.
# Side Effects:	closes a filehandle.
sub _close_log :Private
{
	my $self = shift;

	if(my $fh = delete $self->{fh}) {
		close($fh);
	}

	return $self;
}

# _shutdown
# Purpose:	release the socket and the log when run() finishes.
# Entry:	none.
# Exit:		$self.
# Side Effects:	closes the socket and log; open_socket() and reopen_log() are
#		needed before another run().
sub _shutdown :Private
{
	my $self = shift;

	if(my $socket = delete $self->{socket}) {
		$socket->close();
	}

	return $self->_close_log();
}

# _write_row
# Purpose:	append one CSV row to the log.
# Entry:	$self->{fh} open; $row an arrayref of fields.
# Exit:		$self.
# Side Effects:	writes to the log; carps (does not croak) if that fails, so
#		that a transiently full disk does not stop the daemon.
sub _write_row :Private
{
	my ($self, $row) = @_;

	# combine() then a plain print, rather than Text::CSV's print(): the
	# XS print emits a spurious "uninitialized" warning when write() fails
	my $csv = $self->{csv};
	$csv->combine(@{$row});
	unless(print { $self->{fh} } $csv->string()) {
		carp($self->i18n('write_failed', { file => $self->{file}, error => "$!" }));
	}

	return $self;
}

# _peer_name
# Purpose:	turn the sender's sockaddr into the string to log.
# Entry:	$peer a packed sockaddr (IPv4 or IPv6).
# Exit:		the host name if resolution is on and succeeds, else the
#		numeric address.
# Side Effects:	may do a (cached) reverse DNS lookup.
# Protected rather than private so that a subclass can, say, log
# "name (address)" or use an asynchronous resolver.
sub _peer_name :Protected
{
	my ($self, $peer) = @_;

	# getnameinfo copes with both families, unlike inet_ntoa
	my (undef, $address) = getnameinfo($peer, NI_NUMERICHOST, NIx_NOSERV);
	$address //= '';

	return $address unless($self->{resolve} && length($address));

	# getnameinfo consults /etc/hosts before DNS (via nsswitch.conf), so
	# there is no need to read /etc/hosts ourselves
	return $self->{cache}->compute($address, $self->{dns_ttl}, sub {
		my ($error, $name) = getnameinfo($peer, NI_NAMEREQD, NIx_NOSERV);
		return $error ? $address : $name;
	});
}

# _escape_controls
# Purpose:	make a message safe to store as one CSV line.
# Entry:	a string.
# Exit:		the string with every C0 control and DEL written as \xNN.
# Side Effects:	none.
# A plain function, not a method, because it uses no state.
sub _escape_controls :Private
{
	my $text = shift;

	$text =~ s/([\x00-\x1F\x7F])/sprintf('\\x%02X', ord($1))/ge;

	return $text;
}

=head1 LIMITATIONS

=over 4

=item * B<The default log file is in /tmp.>  It is kept for compatibility with
earlier versions.  The server refuses symlinks, hard links and files owned
by anyone else, which closes the classic /tmp attacks, but an attacker can
still delete the file between rotations.  Use C<--file> to put it somewhere
private such as F</var/log>.

=item * B<The web viewer cannot read the log.>  The file is mode 0600 (owned
by whoever runs the daemon, usually root), but the VWF pages under F<www/>
run as the web server user.  You must choose between privacy and the
viewer, for example with a shared group and a change to C<$LOG_MODE>.

=item * B<No privilege drop.>  Port 514 needs root (or CAP_NET_BIND_SERVICE)
and the server keeps root for its whole life.  Prefer a high port with a
firewall redirect, or systemd socket activation passing the socket to
C<new(socket =E<gt> ...)>.

=item * B<No receive timestamp.>  Rows hold only what the sender put in the
message.  Adding a column would break the header of existing files and
VWF::Data::syslog_log, so it needs a migration and has not been done.

=item * B<Reverse DNS is synchronous.>  The cache limits the damage, but the
first packet from a host with a slow resolver blocks the loop, and UDP
datagrams that arrive meanwhile can be dropped by the kernel.  Use
C<--no-resolve> on busy servers.

=item * B<UDP only.>  No TCP (RFC 6587) or TLS (RFC 5425) transport, so there
is no delivery guarantee and no authentication: anyone who can reach the
port can write to the log.

=item * B<Messages are not parsed beyond PRI.>  RFC 3164 timestamps and
host names, and RFC 5424 structured data, stay in the C<msg> column.

=item * B<CSV formula injection.>  A message starting with C<=>, C<+>, C<->
or C<@> may be run as a formula if the file is opened in a spreadsheet.
The data is stored unchanged on purpose; beware when opening it.

=item * B<Backslashes are not escaped.>  A literal C<\x0A> in a message
cannot be told apart from an escaped newline.

=item * B<Not Object::Configure.>  C<%DEFAULTS> is a flat hash of the kind
Object::Configure uses, but C<configure()> is not called: it brings in a
global Log::Abstraction logger, which may log through syslog, and a
syslog server logging to itself can loop.

=back

=head1 AUTHOR

Nigel Horne

=head1 LICENCE

GPL2

=cut

1;
