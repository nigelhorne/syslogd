package App::Syslogd;

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
use Fcntl qw(O_WRONLY O_APPEND O_CREAT);
use IO::Handle;
use IO::Socket::IP;
use Params::Get;
use Params::Validate::Strict;
use Readonly;
use Socket qw(getnameinfo NI_NAMEREQD NI_NUMERICHOST NIx_NOSERV);
use Text::CSV;

use App::Syslogd::I18N;

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

# O_NOFOLLOW is not defined everywhere: on Windows, Fcntl exports the name
# but calling it dies ("Your vendor has not defined Fcntl macro").  Where it
# is missing, 0 leaves the open flags unchanged.  Windows symbolic links
# need administrator rights to create, so the attack it prevents is rare
# there; see LIMITATIONS.
Readonly my $O_NOFOLLOW => eval { Fcntl::O_NOFOLLOW() } // 0;

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

App::Syslogd - A small UDP syslog receiver that writes a CSV file

=head1 VERSION

Version 0.02

=head1 SYNOPSIS

=head2 1. Run a syslog server

This is what the program F<etc/syslogd> does.  It listens for messages
until it receives SIGTERM or SIGINT (Ctrl-C).

	use App::Syslogd;

	my $server = App::Syslogd->new(
		port => 5514,				# 514 needs root
		file => '/var/log/remote-syslog.csv',
	);
	$server->open_socket()->reopen_log();	# fail now, not later
	print $server->i18n('listening', {
		address => $server->address(),
		port => $server->port(),
	}), "\n";
	$server->run();				# waits here until stopped
	print $server->i18n('shutdown', { count => $server->count() }), "\n";

=head2 2. Decode one message, without a network or a file

C<parse_message()> uses no state, so you can call it on the class.

	use App::Syslogd;

	my $record = App::Syslogd->parse_message('<34>su: authentication failure');
	print "facility $record->{facility}, severity $record->{severity}\n";
	# facility 4, severity 2

=head2 3. Record messages that your own code received

Use this when your program already has a socket loop, for example an event
loop that watches many sockets.

	use App::Syslogd;
	use IO::Socket::IP;

	my $recorder = App::Syslogd->new(file => '/var/log/remote.csv', resolve => 0);
	$recorder->reopen_log();

	my $socket = IO::Socket::IP->new(LocalPort => 5514, Proto => 'udp')
		or die "Cannot listen: $IO::Socket::errstr";
	while(my $peer = $socket->recv(my $datagram, 65535)) {
		$recorder->process($datagram, $peer);
	}

=head2 4. Use a socket that someone else opened, for a fixed time

Pass the socket to C<new()>, for example one received from systemd socket
activation, or one opened before giving up root.  C<stop()> ends C<run()>.

	my $server = App::Syslogd->new(socket => $already_bound_socket, file => $file);

	local $SIG{ALRM} = sub { $server->stop() };
	alarm(3600);		# stop after one hour
	$server->run();

=head2 5. Change how the sender is written in the log

C<_peer_name()> is protected: a subclass may replace it.

	package My::Syslogd;
	use parent 'App::Syslogd';
	use Socket ();

	# Write "name [address]" instead of just the name
	sub _peer_name {
		my ($self, $peer) = @_;
		my $name = $self->SUPER::_peer_name($peer);
		my (undef, $address) = Socket::getnameinfo($peer, Socket::NI_NUMERICHOST());
		return "$name [$address]";
	}

=head1 DESCRIPTION

=head2 What syslog is

Many machines (servers, routers, printers, firewalls) can send their log
messages over the network with the I<syslog> protocol.  Each message is one
UDP packet, called a I<datagram>.  A message usually starts with a number in
angle brackets, the I<PRI> (priority), for example C<< <34> >>.  The PRI
holds two smaller numbers:

=over 4

=item * B<facility> = PRI divided by 8, rounded down (0 to 23).  It says which
part of the system sent the message, for example 4 means "security".

=item * B<severity> = the remainder of PRI divided by 8 (0 to 7).  It says how
serious the message is: 0 is "emergency" and 7 is "debug".

=back

So C<< <34> >> means facility 4 (34 / 8 = 4) and severity 2 (34 - 32 = 2).

=head2 What this module does

It waits for syslog datagrams and adds one line to a CSV file for each one.
The first line of a new file names the columns:

	"Host","facility","severity","msg"
	"router.example.com","4","2","su: authentication failure"

=over 4

=item * B<Host> is the name of the machine that sent the message.  The name
is found with the normal system lookup (F</etc/hosts>, then DNS) and
remembered for a few minutes.  If no name is found, or if you turn names
off, the IP address is written instead.  IPv4 and IPv6 both work.

=item * B<facility> and B<severity> come from the PRI.  If the PRI is missing
or not valid, the message is still kept: it is recorded as facility 1,
severity 5 ("user.notice"), and the whole datagram becomes the message.
RFC 3164 section 4.3.3 asks for this.  A valid PRI is a number from 0 to 191
with no extra leading zeros.

=item * B<msg> is the rest of the datagram.  Line endings at the end are
removed.  Other control characters, including a newline in the middle, are
written as C<\xNN> (for example C<\x0A>).  So every message is exactly one
line, and nobody can create a fake extra line by sending a newline.

=back

=head2 Other behaviour

=over 4

=item * Signal B<SIGHUP> closes and reopens the log file.  Log rotation tools
such as logrotate use this: they rename the file, then send SIGHUP, and the
server starts a new file.

=item * Signals B<SIGTERM> and B<SIGINT> stop the server cleanly.

=item * The log file is created so that only its owner can read it (mode
0600).  The server will not write through a symbolic link or a hard link, or
into a file that another user owns.  This protects against attacks that trick
a root process into overwriting a file.  (Windows is weaker here: see
L</LIMITATIONS>.)

=item * Datagrams up to 65535 bytes (the largest UDP size) are read
completely.  Datagrams shorter than 2 characters are ignored.

=back

=head1 COMMAND LINE

The program F<etc/syslogd> is a small wrapper around this module:

	/usr/local/etc/syslogd [--port 514] [--address 0.0.0.0] [--file /tmp/syslog.log]
		[--no-resolve] [--language en]

=over 4

=item C<--port> - the UDP port to listen on.  The default is 514, the
standard syslog port.  Ports below 1024 need root.

=item C<--address> - the local address to listen on.  The default
C<0.0.0.0> means "every IPv4 address of this machine".  Use C<::> for IPv6.

=item C<--file> - the CSV log file.  The default F</tmp/syslog.log> exists
only for compatibility with older versions.  For real use, choose a private
place, such as F</var/log/remote-syslog.csv> (see L</LIMITATIONS>).

=item C<--no-resolve> - write IP addresses instead of host names.  This is
faster on a busy server.

=item C<--language> - the language of the program's own messages, for example
C<en>.  By default it comes from the environment (C<LANG> and similar).

=back

Send B<SIGHUP> to reopen the log file.  Send B<SIGTERM>, or press Ctrl-C, to
stop.

=head2 Log rotation

An example logrotate configuration:

	/var/log/remote-syslog.csv {
		weekly
		rotate 8
		postrotate
			pkill -HUP -f /usr/local/etc/syslogd
		endscript
	}

=head1 INSTALLATION

Install the module from CPAN:

	cpanm App::Syslogd

or from a git checkout:

	perl Makefile.PL && make && make test && sudo make install

Then copy the program by hand:

	sudo cp etc/syslogd /usr/local/etc/

C<make install> does not install the program on purpose.  It would put it in
a F<bin> directory, and a program called F<syslogd> there could hide the
system's own F</usr/sbin/syslogd>.

To use a git checkout without installing the module, copy the module next to
the program:

	sudo cp -r lib/App /usr/local/lib/

The program looks for modules in F<../lib> relative to itself (that is
F</usr/local/lib> after installation, or F<lib/> in a git checkout), and also
in Perl's normal module directories.

=head1 DEPENDENCIES

Perl 5.14 or later, and these modules: L<autodie> (which needs
L<IPC::System::Simple>), L<CHI>, L<IO::Socket::IP>, L<Locale::Maketext>,
L<Params::Get>, L<Params::Validate::Strict>, L<Readonly>, L<Socket>,
L<Sub::Private>, L<Sub::Protected> and L<Text::CSV>.  F<Makefile.PL> lists
the minimum versions.

=head1 FILES

=over 4

=item F<etc/syslogd> - the command-line program.  Install it as
F</usr/local/etc/syslogd>.

=item F<lib/App/Syslogd.pm> - this module.

=item F<lib/App/Syslogd/I18N.pm> and F<lib/App/Syslogd/I18N/en.pm> - the
messages that people see, and their English text.

=item F<t/> - the tests.  Run them with C<prove -l t/>.

=item F<www/> - a web page that shows the log.  It is only in the git
repository, not in the CPAN distribution.

=back

=head1 ENCODING

The module works with B<bytes>, not with decoded text.  It never decodes or
encodes anything itself.

=over 4

=item * B<Datagrams> (C<parse_message()>, C<process()>, and everything that
C<run()> receives) can contain any bytes.  UTF-8 text, other non-ASCII text
and emoji are written to the file exactly as they arrived.  Invalid UTF-8 is
also written unchanged.  Only bytes 0x00 to 0x1F and 0x7F are changed (to
C<\xNN>).  Bytes 0x80 to 0x9F are not changed, so a UTF-8 character is never
broken.

=item * If you call C<parse_message()> or C<process()> yourself with a Perl
I<character> string (text that came from C<decode()>, or that contains a
character above 255, such as an emoji written as C<"\x{1F600}">), first
encode it to bytes, for example with C<Encode::encode('UTF-8', $text)>.
Otherwise Perl prints a "Wide character" warning when the line is written.

=item * B<The file name> (C<file>) is passed to the operating system as
bytes.  A name with non-ASCII characters must be given as encoded bytes
(normally UTF-8 on Unix).

=item * B<Host names> come from the system resolver.  An international domain
name normally arrives in its ASCII form (C<xn--...>).

=item * B<The language tag> (C<language>) must be ASCII, for example C<en-gb>.

=item * B<Messages from i18n()> are Perl strings.  The English messages are
ASCII, but a value you pass in (for example a file name) is copied into the
message as it is.  If you print a message that contains wide characters,
set an output layer first: C<binmode(STDOUT, ':encoding(UTF-8)')>.

=back

=head1 COMMON PITFALLS

=over 4

=item * B<undef means "use the default".>  C<< new(file => undef) >> gives the
default file, not an empty file name.  This is useful when you pass options
straight from L<Getopt::Long>, but it means you cannot use C<undef> to switch
something off.  To turn off host names, use C<< resolve => 0 >>.

=item * B<The options are merged one level deep only.>  Each option you give
replaces the default with the same name; nothing is merged inside a value.
Objects you pass (C<cache>, C<socket>) are shared, not copied: two servers
given the same C<cache> object share their host name answers.

=item * B<True and false.>  C<resolve> accepts 1, 0, and the words C<true>,
C<false>, C<yes>, C<no>, C<on> and C<off>.  Any other value, such as 2, is an
error.

=item * B<Order of calls.>  C<process()> needs an open log, so call
C<reopen_log()> first.  C<run()> opens the socket and the log by itself if
you have not.

=item * B<Signals are handled only inside run().>  Before C<run()> starts and
after it returns, SIGHUP has its normal effect, which is to end the program.
C<run()> puts back your own signal handlers when it returns.

=item * B<stop() before run() does nothing.>  C<run()> sets the "running"
flag when it starts, so an earlier C<stop()> is forgotten.

=item * B<run() closes everything when it returns.>  If you call C<run()>
again, it opens a new socket.  With C<< port => 0 >>, the new socket can get
a different port number.

=item * B<A failed reopen stops run().>  If SIGHUP arrives and the log file
cannot be opened (for example, the directory was removed), C<run()> dies
with the error.  The socket stays open and the log stays closed.

=item * B<An existing log file is made private.>  C<reopen_log()> changes the
file's permissions to 0600 without asking.

=item * B<A short datagram is ignored silently.>  After removing line endings
at the end, a datagram must have at least 2 characters.  C<parse_message()>
then returns C<undef>, and C<process()> writes nothing and does not count it.

=item * B<A missing sender is not an error.>  C<process($datagram, undef)>
writes the message with an empty Host column.

=item * B<port() and address() change meaning.>  Before C<open_socket()> they
return what you asked for.  After it they return what the system actually
gave, so C<< port => 0 >> becomes a real port number.

=item * B<Backslashes are not escaped.>  A message that really contains the
four characters C<\x0A> looks the same in the file as an escaped newline.

=back

=head1 METHODS

Every method except C<parse_message()> and C<i18n()> needs an object made by
C<new()>; those two also work on the class.  Methods that have nothing
useful to return give back the object, so you can chain calls:

	App::Syslogd->new(port => 5514)->open_socket()->reopen_log()->run();

The mathematical description of each method is in
L</FORMAL SPECIFICATION>, and the life cycle of an object is in
L</STATE DIAGRAM>, both at the end of this document.

=head2 new

Purpose: make a new server object.  It does not open the network or the
file yet, so you can create and inspect it without any special permissions.

Args: all optional, given as a list of pairs or as one hash reference.  An
option given as C<undef> uses its default.

=over 4

=item * C<port> - the UDP port number, 0 to 65535.  Default 514.  0 means
"let the system choose a free port"; call C<port()> after C<open_socket()>
to find out which one.

=item * C<address> - the local address to listen on.  Default C<0.0.0.0> (all
IPv4 addresses).  Use C<::> for IPv6.

=item * C<file> - the CSV log file.  Default F</tmp/syslog.log>.

=item * C<resolve> - true (the default) to write host names, false to write
IP addresses.

=item * C<dns_ttl> - how many seconds to remember a host name.  Default 300.

=item * C<dns_cache_bytes> - the most memory, in bytes, used to remember host
names.  Default 262144.

=item * C<language> - the language of messages, such as C<en>.  Default: from
the environment.

=item * C<cache> - your own cache for host names, instead of the built-in
one.  Any object with a L<CHI>-style C<compute()> method.

=item * C<socket> - a socket that is already open, instead of opening one.
Any object with a C<recv()> method.

=back

Returns: the new object.

Side Effects: none.  Dies if an option is unknown or has a wrong value.

Usage:

	my $server = App::Syslogd->new({ port => 514, resolve => 0 });

=head3 EXAMPLE

	# Listen on a port that does not need root, and write addresses only
	my $server = App::Syslogd->new(port => 5514, resolve => 0);

	# Options from Getopt::Long: options not given stay undef = default
	my %opts;
	GetOptions(\%opts, 'port=i', 'file=s');
	my $server2 = App::Syslogd->new(\%opts);

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

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

	+------------------------------------+--------------------------+-----------------------------+
	| Message (dies)                     | Meaning                  | What to do                  |
	+------------------------------------+--------------------------+-----------------------------+
	| validate_strict: Unknown parameter | An option name is wrong  | Check the spelling against  |
	|   'x'                              |                          |   the list above            |
	| validate_strict: Parameter 'port'  | A value is the wrong     | Use a whole number from 0   |
	|   (x) must be an integer           |   type                   |   to 65535                  |
	| validate_strict: Parameter 'port'  | A number is out of range | Use a value inside the      |
	|   (x) must be no more than 65535   |                          |   range shown above         |
	| validate_strict: Parameter         | Not a true/false value   | Use 1, 0, true, false, yes, |
	|   'resolve' (x) must be a boolean  |                          |   no, on or off             |
	+------------------------------------+--------------------------+-----------------------------+

=head3 PSEUDOCODE

	check the options against the schema (die if one is wrong)
	remove options whose value is undef
	start from the defaults, then copy the options over them
	set the message counter to 0
	choose the message language
	if no cache was given, make an in-memory cache
	make the CSV writer
	return the object

=cut

sub new
{
	my $class = shift;

	# Accept a hash, a hashref or nothing at all
	my $args = Params::Validate::Strict::validate_strict({
		schema => \%NEW_SCHEMA,
		input => Params::Get::get_params(undef, \@_) || {},
	});

	# An undef value means "use the default": without this,
	# new(file => undef) replaced the default with undef and failed later,
	# far from the mistake
	delete @{$args}{grep { !defined($args->{$_}) } keys %{$args}};

	# Caller's values win over defaults (a one-level merge: nothing nested)
	my $self = bless { %DEFAULTS, %{$args}, count => 0 }, $class;

	# One handle per object: two servers in one process may speak
	# different languages
	$self->{lh} = App::Syslogd::I18N->handle($self->{language});

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

Purpose: start listening for UDP datagrams on the configured address and
port.  If the port is below 1024, do this before your program gives up root.

Args: none.

Returns: the object, so you can chain another call.

Side Effects: opens a UDP socket.  Does nothing if a socket is already open,
including one given to C<new()>.

Usage:

	$server->open_socket();

=head3 EXAMPLE

	# Let the system choose a free port, then ask which one it chose
	my $server = App::Syslogd->new(port => 0)->open_socket();
	print 'Listening on port ', $server->port(), "\n";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

	+---------------------------------+---------------------------+------------------------------+
	| Message (dies)                  | Meaning                   | What to do                   |
	+---------------------------------+---------------------------+------------------------------+
	| Could not create a UDP socket   | The system refused: the   | Run as root for ports below  |
	|   on ADDR port N: ERROR         |   port is in use, needs   |   1024, stop the other       |
	|                                 |   root, or the address is |   syslog server, or correct  |
	|                                 |   wrong                   |   the address                |
	+---------------------------------+---------------------------+------------------------------+

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

Purpose: tell you the UDP port number.

Args: none.

Returns: a whole number from 0 to 65535.  Before C<open_socket()> it is the
port you asked for.  After it, it is the port really in use, so
C<< port => 0 >> becomes the number the system chose.

Side Effects: none.

Usage:

	my $port = $server->port();

=head3 EXAMPLE

	print App::Syslogd->new()->port(), "\n";	# 514

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0, max => 65535 }

=head3 MESSAGES

None.

=cut

sub port
{
	my $self = shift;

	# An injected test socket may not know its port, so ask only real ones
	my $socket = $self->{socket};

	return ($socket && $socket->can('sockport')) ? $socket->sockport() : $self->{port};
}

=head2 address

Purpose: tell you the local address the server listens on.

Args: none.

Returns: a string, such as C<0.0.0.0> or C<::1>.  Before C<open_socket()> it
is the address you asked for.  After it, it is the address the system reports.

Side Effects: none.

Usage:

	my $address = $server->address();

=head3 EXAMPLE

	print App::Syslogd->new(address => '::')->address(), "\n";	# ::

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'string', min => 1 }

=head3 MESSAGES

None.

=cut

sub address
{
	my $self = shift;

	# Mirrors port(): injected test sockets need not know their address
	my $socket = $self->{socket};

	return ($socket && $socket->can("sockhost")) ? $socket->sockhost() : $self->{address};
}

=head2 count

Purpose: tell you how many datagrams have been written to the log.

Args: none.

Returns: a whole number, 0 or more.  Ignored datagrams (shorter than 2
characters) are not counted.  A datagram that could not be written because
the disk was full is counted.

Side Effects: none.

Usage:

	print $server->count(), " messages\n";

=head3 EXAMPLE

	$server->reopen_log()->process('<13>hello', $peer);
	print $server->count(), "\n";	# 1

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'integer', min => 0 }

=head3 MESSAGES

None.

=cut

sub count
{
	my $self = shift;

	return $self->{count};
}

=head2 reopen_log

Purpose: open the CSV log file, closing it first if it is already open.  Use
it once at the start.  C<run()> also calls it when SIGHUP arrives, so that
after a log rotation tool renames the file, a new file is started.

Args: none.

Returns: the object, so you can chain another call.

Side Effects:

=over 4

=item * Closes the log file if it is open.

=item * Creates the file if it does not exist, readable only by its owner.

=item * Writes the column names if the file is empty.

=item * Changes an existing file's permissions to 0600.

=item * Dies, leaving no log open, if the file cannot be used safely.

=back

Usage:

	$server->reopen_log();

=head3 EXAMPLE

	# Open the log before starting, so that a problem is reported at once
	my $server = App::Syslogd->new(file => '/var/log/remote.csv');
	eval { $server->reopen_log(); 1 } or die "Cannot start: $@";

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

	+-------------------------------+--------------------------------+-------------------------------+
	| Message (dies)                | Meaning                        | What to do                    |
	+-------------------------------+--------------------------------+-------------------------------+
	| Could not open log file F:    | The system could not open the  | Create the directory, or fix  |
	|   ERROR                       |   file.  ERROR is the system's |   its permissions.  Remove a  |
	|                               |   reason.  A symbolic link or  |   symbolic link; give a file  |
	|                               |   a directory also gives this  |   name, not a directory       |
	| Refusing to log to F: it must | F is a hard link or another    | Remove F and let the server   |
	|   be a regular file, owned by |   user's file                  |   create it again             |
	|   this user, with exactly one |                                |                               |
	|   link                        |                                |                               |
	| Could not write to log file   | The column names could not be  | Free some disk space          |
	|   F: ERROR                    |   written to a new file        |                               |
	+-------------------------------+--------------------------------+-------------------------------+

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

Purpose: split one datagram into its facility, severity and message text.
It uses no state and writes nothing, so you can call it on the class and use
it on its own.

Args: one datagram, as a string of bytes.

Returns: C<undef> if the datagram is too short to be a message (fewer than 2
characters after removing line endings at the end).  Otherwise a hash
reference with these keys:

=over 4

=item * C<facility> - 0 to 23.

=item * C<severity> - 0 to 7.

=item * C<message> - the text after the PRI, with control characters
written as C<\xNN>.

=item * C<valid> - 1 if the datagram had a valid PRI.  0 if not; then facility
is 1, severity is 5, and C<message> is the whole datagram.

=back

Side Effects: none.

Usage:

	my $record = App::Syslogd->parse_message($datagram);

=head3 EXAMPLE

	my $r = App::Syslogd->parse_message("<34>su: 'su root' failed\n");
	# { facility => 4, severity => 2, message => "su: 'su root' failed", valid => 1 }

	$r = App::Syslogd->parse_message("no pri\there");
	# { facility => 1, severity => 5, message => 'no pri\x09here', valid => 0 }

	$r = App::Syslogd->parse_message("x\n");
	# undef: too short

=head3 API SPECIFICATION

=head4 INPUT

	{
		datagram => { type => 'string', optional => 1, position => 0 },
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

None.  A malformed datagram is recorded, never rejected.

=head3 PSEUDOCODE

	treat undef as an empty string
	remove CR, LF and NUL characters from the end
	if fewer than 2 characters remain: return undef
	if the text is "<" NUMBER ">" REST, where NUMBER is 0 to 191
	   written without extra leading zeros:
		valid = 1
	else:
		NUMBER = 13, REST = the whole text, valid = 0
	return {
		facility => NUMBER divided by 8, rounded down,
		severity => remainder of NUMBER divided by 8,
		message  => REST with control characters written as \xNN,
		valid    => valid,
	}

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

Purpose: write one received datagram to the log.

Args:

=over 4

=item 1. The datagram, as a string of bytes.

=item 2. The sender's address, in the packed form that C<recv()> returns.
C<undef> is allowed: the Host column is then empty.

=back

Returns: the object, so you can chain another call.

Side Effects:

=over 4

=item * May look up the sender's host name (the answer is remembered).

=item * Adds one line to the log and adds 1 to C<count()>, unless the
datagram is too short, in which case nothing happens.

=item * If the line cannot be written (for example, the disk is full), it
warns and continues.  That message is lost, but the server keeps working.

=back

Usage:

	my $peer = $socket->recv(my $datagram, 65535);
	$server->process($datagram, $peer);

=head3 EXAMPLE

	use Socket qw(pack_sockaddr_in inet_aton);

	my $peer = pack_sockaddr_in(514, inet_aton('192.0.2.1'));
	$server->reopen_log()->process('<13>hello', $peer);
	# The file now ends with: "192.0.2.1","1","5","hello"

=head3 API SPECIFICATION

=head4 INPUT

	{
		datagram => { type => 'string', optional => 1, position => 0 },
		peer => { type => 'string', optional => 1, position => 1 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

	+-----------------------------------+------------------------------+-------------------------------+
	| Message                           | Meaning                      | What to do                    |
	+-----------------------------------+------------------------------+-------------------------------+
	| process() was called before       | No log file is open (dies)   | Call reopen_log() first       |
	|   reopen_log() succeeded          |                              |                               |
	| Could not write to log file F:    | The line was not written,    | Free disk space; this message |
	|   ERROR                           |   e.g. disk full (warning)   |   is lost, later ones are not |
	+-----------------------------------+------------------------------+-------------------------------+

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

Purpose: the main loop.  Wait for datagrams and write each one to the log,
until told to stop.

Args: none.

Returns: the object, after SIGTERM, SIGINT or C<stop()>.

Side Effects:

=over 4

=item * Calls C<open_socket()> and C<reopen_log()> first if they have not been
called.

=item * While it runs: SIGHUP reopens the log, and SIGTERM or SIGINT stop the
loop.  Your own handlers for these three signals are put back when it
returns.

=item * When it returns, the socket and the log file are closed.

=back

Usage:

	$server->run();

=head3 EXAMPLE

	my $server = App::Syslogd->new(port => 5514, file => '/var/log/remote.csv');
	$server->run();		# Ctrl-C to stop
	print $server->i18n('shutdown', { count => $server->count() }), "\n";
	# Syslog server shutting down after recording 42 messages

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

	+---------------------------------+--------------------------------+------------------------------+
	| Message                         | Meaning                        | What to do                   |
	+---------------------------------+--------------------------------+------------------------------+
	| Error receiving a datagram:     | Reading from the network       | Usually nothing: the loop    |
	|   ERROR                         |   failed (warning).  Not given |   continues.  If it repeats, |
	|                                 |   when a signal interrupts the |   check the network          |
	|                                 |   wait                         |                              |
	| Any message of open_socket() or | Starting, or reopening the     | See those methods            |
	|   reopen_log()                  |   log after SIGHUP, failed     |                              |
	|                                 |   (dies)                       |                              |
	+---------------------------------+--------------------------------+------------------------------+

=head3 PSEUDOCODE

	if no socket is open: open_socket()
	if no log is open: reopen_log()
	for the duration of run():
		SIGHUP          -> set "reopen requested"
		SIGTERM, SIGINT -> clear "running"
	set "running"
	while "running":
		if "reopen requested": clear it, then reopen_log()
		wait for a datagram
		if a datagram arrived: process() it
		(a signal ends the wait early, so the flags are seen at once;
		 any other read error is a warning, and the loop continues)
	close the socket and the log
	put back the caller's signal handlers
	return the object

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

Purpose: ask C<run()> to finish.  C<run()> returns after the datagram it is
handling, or at once if it is waiting.

Args: none.

Returns: the object.

Side Effects: clears the "running" flag.  Calling it before C<run()> has no
effect, because C<run()> sets the flag when it starts.

Usage:

	$server->stop();

=head3 EXAMPLE

	# Run for one minute
	local $SIG{ALRM} = sub { $server->stop() };
	alarm(60);
	$server->run();

=head3 API SPECIFICATION

=head4 INPUT

	{}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd' }

=head3 MESSAGES

None.

=cut

sub stop
{
	my $self = shift;

	$self->{running} = 0;

	return $self;
}

=head2 i18n

Purpose: make a message for people to read, in the server's language.  All
of this module's own messages are made with it, so they can be translated.

Args:

=over 4

=item 1. The message key, for example C<listening>.  The keys are in the
table below.

=item 2. Optional: a hash reference of values to put into the message, for
example C<< { port => 514 } >>.  A missing value becomes an empty string.

=back

It also works on the class (C<< App::Syslogd->i18n(...) >>); the language then
comes from the environment.

Returns: the message as a string.  An unknown key does not die: you get the
key and its values back, such as C<no_such_key (a=1)>.

Side Effects: none.

Usage:

	print $server->i18n('listening', { address => '0.0.0.0', port => 514 }), "\n";

=head3 EXAMPLE

	print App::Syslogd->i18n('shutdown', { count => 1 }), "\n";
	# Syslog server shutting down after recording 1 message
	print App::Syslogd->i18n('shutdown', { count => 3 }), "\n";
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

The keys, the values each one uses, and the English text:

	+---------------+------------------------+--------------------------------------------------+
	| Key           | Values                 | English text                                     |
	+---------------+------------------------+--------------------------------------------------+
	| usage         | program                | Usage: PROGRAM [--port <port_number>] ...        |
	| listening     | address, port          | Syslog server listening on ADDRESS UDP port PORT |
	| shutdown      | count                  | Syslog server shutting down after recording      |
	|               |                        |   COUNT message(s)                               |
	| socket_failed | address, port, error   | Could not create a UDP socket on ADDRESS port    |
	|               |                        |   PORT: ERROR                                    |
	| open_failed   | file, error            | Could not open log file FILE: ERROR              |
	| unsafe_file   | file                   | Refusing to log to FILE: it must be a regular    |
	|               |                        |   file, owned by this user, with exactly one     |
	|               |                        |   link                                           |
	| write_failed  | file, error            | Could not write to log file FILE: ERROR          |
	| recv_failed   | error                  | Error receiving a datagram: ERROR                |
	| not_listening | (none)                 | run() was called before open_socket() succeeded  |
	| no_log_open   | (none)                 | process() was called before reopen_log()         |
	|               |                        |   succeeded                                      |
	+---------------+------------------------+--------------------------------------------------+

=cut

sub i18n
{
	my ($self, $key, $args) = @_;

	# Class-method calls have no object and so no stored handle
	my $lh = ref($self) ? $self->{lh} : App::Syslogd::I18N->handle();

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
		sysopen($fh, $file, O_WRONLY | O_APPEND | O_CREAT | $O_NOFOLLOW, $LOG_MODE)
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

	# getnameinfo copes with both families, unlike inet_ntoa.  It dies on
	# undef ("addr is not a string"), so a missing peer is treated like an
	# undecodable one: logged as an empty host
	my $address = '';
	(undef, $address) = getnameinfo($peer, NI_NUMERICHOST, NIx_NOSERV) if(defined($peer));
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

=item * B<The default log file is in /tmp.>  This keeps compatibility with
older versions.  The checks described in L</DESCRIPTION> stop the usual
attacks on files in F</tmp>, but another user can still delete the file.
Use C<file> (or C<--file>) to choose a private place such as F</var/log>.

=item * B<The web viewer cannot read the log.>  The file is readable only by
its owner (usually root), but the web pages in F<www/> run as the web
server's user.  You must choose between privacy and the viewer, for example
by using a shared group and changing C<$LOG_MODE> in the source.

=item * B<It does not give up root.>  Port 514 needs root (or the
CAP_NET_BIND_SERVICE capability), and the server keeps root while it runs.
Better: use a port above 1023 with a firewall redirect, or let systemd open
the socket and pass it with C<< new(socket => ...) >>.

=item * B<No time of arrival.>  A line holds only what the sender put in the
message.  Adding a column would break existing files and the web viewer, so
it needs a migration and has not been done.

=item * B<Host name lookups block.>  Answers are remembered, but the first
message from a host with a slow DNS server makes the loop wait, and the
system may drop datagrams that arrive during the wait.  Use C<--no-resolve>
on a busy server.

=item * B<UDP only.>  There is no TCP (RFC 6587) or TLS (RFC 5425).  So
delivery is not guaranteed, and anyone who can reach the port can write to
the log.

=item * B<Only the PRI is decoded.>  Time stamps and host names inside RFC 3164
messages, and RFC 5424 structured data, stay in the C<msg> column.

=item * B<Spreadsheet formulas.>  A message that starts with C<=>, C<+>, C<->
or C<@> may run as a formula if you open the file in a spreadsheet.  The
data is kept unchanged on purpose; take care when you open it.

=item * B<Backslashes are not escaped>, so the text C<\x0A> and an escaped
newline look the same (see L</COMMON PITFALLS>).

=item * B<Windows is less protected.>  The module works on Windows, but:

=over 4

=item * Windows has no C<O_NOFOLLOW>, so the server cannot refuse a symbolic
link as the log file.  (Creating a symbolic link on Windows normally needs
administrator rights, which makes this attack rare.)

=item * Mode 0600 does not make the file private: Windows uses access control
lists, which this module does not change.  Put the log in a folder that only
the right users can read.

=item * There is no C<kill -HUP> from outside the process, so log rotation by
signal is not available.  Stop and restart the server instead.

=item * A signal such as Ctrl-C may not interrupt the wait for a datagram, so
the server may stop only after the next datagram arrives.

=back

=item * B<Object::Configure is not used.>  C<%DEFAULTS> has the flat form that
Object::Configure uses, but its C<configure()> is not called.  It would add a
global logger that may log through syslog, and a syslog server that logs to
itself can loop.

=back

=head1 AUTHOR

Nigel Horne, C<< <njh at nigelhorne.com> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2026 Nigel Horne.

This program is released under the GNU General Public License, version 2
(see the F<LICENSE> file).  If you use it, please let me know.

=head1 FORMAL SPECIFICATION

This section describes each method exactly, in the Z notation.  You do not
need it to use the module; the descriptions in L</METHODS> say the same
things in words.

=head2 State

	[ADDRESS, PATH, LANGTAG, SOCKADDR, BYTE, NAME, VALUE]
	PORT == 0 .. 65535
	HEADER == ⟨"Host", "facility", "severity", "msg"⟩
	RECORD == ⟨facility : 0 .. 23, severity : 0 .. 7,
	           message : seq BYTE, valid : 𝔹⟩

	Server
	  port : PORT ; address : ADDRESS ; file : PATH
	  resolve : 𝔹 ; language : LANGTAG
	  count : ℕ
	  bound, logging, running, hup : 𝔹
	  contents : PATH ⇸ seq (seq BYTE)
	  ─────────
	  running ⇒ bound ∧ logging

	ΞServer ≙ [ ΔServer | θServer' = θServer ]

=head2 new

	New
	  Server'
	  args? : NAME ⇸ VALUE
	  ─────────
	  let a == args? ⩥ {⊥} •
	    dom args? ⊆ dom NEW_SCHEMA ∧
	    θServer' = (DEFAULTS ⊕ a) ⊕ {count ↦ 0} ∧
	    bound' = (socket ∈ dom a) ∧ ¬logging' ∧ ¬running' ∧ ¬hup'

	NewFail
	  ΞServer
	  args? : NAME ⇸ VALUE
	  error! : STRING
	  ─────────
	  dom args? ⊈ dom NEW_SCHEMA ∨ ¬ conforms(args?, NEW_SCHEMA)

=head2 open_socket

	OpenSocketOk
	  ΔServer
	  ─────────
	  bound' ∧ logging' = logging ∧ count' = count
	  (port = 0 ∧ ¬bound ⇒ port' ∈ 1 .. 65535)
	  (port ≠ 0 ∨ bound ⇒ port' = port)

	OpenSocketFail
	  ΞServer
	  error! : STRING
	  ─────────
	  ¬bound ∧ ¬ canBind(address, port)

	OpenSocket ≙ OpenSocketOk ∨ OpenSocketFail

=head2 port

	Port
	  ΞServer
	  p! : PORT
	  ─────────
	  p! = port

=head2 address

	Address
	  ΞServer
	  a! : ADDRESS
	  ─────────
	  a! = address

=head2 count

	Count
	  ΞServer
	  n! : ℕ
	  ─────────
	  n! = count

=head2 reopen_log

	ReopenLogOk
	  ΔServer
	  ─────────
	  logging' ∧ bound' = bound ∧ count' = count
	  isRegular(file) ∧ ¬ isSymlink(file)
	  owner(file) = euid ∧ links(file) = 1 ∧ mode'(file) = 0600
	  contents(file) = ⟨⟩ ⇒ contents'(file) = ⟨csv(HEADER)⟩
	  contents(file) ≠ ⟨⟩ ⇒ contents'(file) = contents(file)

	ReopenLogFail
	  ΔServer
	  error! : STRING
	  ─────────
	  ¬logging' ∧ bound' = bound ∧ count' = count

	ReopenLog ≙ ReopenLogOk ∨ ReopenLogFail

=head2 parse_message

	ParseMessage
	  d? : seq BYTE
	  r! : RECORD ∪ {⊥}
	  ─────────
	  let t == stripTrailing({CR, LF, NUL}, d?) •
	  #t < 2 ⇒ r! = ⊥
	  #t ≥ 2 ∧ (∃ p : 0 .. 191 ; b : seq BYTE •
	           t = ⟨'<'⟩ ⁀ canonical(p) ⁀ ⟨'>'⟩ ⁀ b) ⇒
	    r! = ⟨facility ↦ p div 8, severity ↦ p mod 8,
	          message ↦ escape(b), valid ↦ true⟩
	  otherwise ⇒
	    r! = ⟨facility ↦ 1, severity ↦ 5,
	          message ↦ escape(t), valid ↦ false⟩

	escape : seq BYTE → seq BYTE
	∀ c : BYTE • escape(⟨c⟩) =
	  if c ∈ 0 .. 31 ∪ {127} then "\x" ⁀ hex2(c) else ⟨c⟩
	∀ s, u : seq BYTE • escape(s ⁀ u) = escape(s) ⁀ escape(u)

=head2 process

	ProcessOk
	  ΔServer
	  d? : seq BYTE ; peer? : SOCKADDR ∪ {⊥}
	  ─────────
	  logging ∧ bound' = bound ∧ logging'
	  ParseMessage(d?) = ⊥ ⇒ count' = count ∧ contents' = contents
	  ParseMessage(d?) = r ≠ ⊥ ⇒
	    count' = count + 1 ∧
	    (writable(file) ⇒
	      contents'(file) = contents(file) ⁀ ⟨csv(host(peer?), r)⟩) ∧
	    (¬ writable(file) ⇒ contents' = contents)

	host(⊥) = ""
	resolve ⇒ host(p) = reverseName(p) if found, else numeric(p)
	¬resolve ⇒ host(p) = numeric(p)

	ProcessFail
	  ΞServer
	  error! : STRING
	  ─────────
	  ¬logging

	Process ≙ ProcessOk ∨ ProcessFail

=head2 run

	Start ≙ (¬bound ∧ OpenSocket ∨ bound ∧ ΞServer) ⨾
	        (¬logging ∧ ReopenLog ∨ logging ∧ ΞServer)

	Loop ≙ μ L •
	    (¬running ∧ Shutdown)
	  □ (running ∧ hup ∧ [ ΔServer | ¬hup' ] ⨾ ReopenLog ⨾ L)
	  □ (running ∧ ¬hup ∧ Receive ⨾ Process ⨾ L)

	Shutdown
	  ΔServer
	  ─────────
	  ¬bound' ∧ ¬logging' ∧ ¬running' ∧ count' = count

	Run ≙ Start ⨾ [ ΔServer | running' ] ⨾ Loop

	SIGHUP received during Run      ⇒ hup' = true
	SIGTERM or SIGINT during Run    ⇒ running' = false

=head2 stop

	Stop
	  ΔServer
	  ─────────
	  ¬running' ∧ bound' = bound ∧ logging' = logging ∧ count' = count

=head2 i18n

	I18n
	  key? : KEY ; args? : NAME ⇸ VALUE ; out! : STRING
	  ─────────
	  key? ∈ dom ARGUMENT_ORDER ⇒
	    out! = render(lexicon(language, key?),
	                  ⟨args?(n) | n ∈ ARGUMENT_ORDER(key?)⟩)
	  key? ∉ dom ARGUMENT_ORDER ⇒ key? ⊑ out!

=head1 STATE DIAGRAM

An object is always in one of six states.  The boxes are the states; the
arrows are the method calls or events that move it from one state to another.
The text in square brackets is what happens during the move.

	                      new()
	                        |   [check options; nothing opened]
	                        |
	                        |       new(socket => S) starts in BOUND instead
	                        v
	          +---------------------------+
	          |           IDLE            |<--------------------------------+
	          |  no socket, no log file   |                                 |
	          +---------------------------+                                 |
	              |                   |                                     |
	 open_socket()|                   |reopen_log()                         |
	 [bind UDP    |                   |[open or create file (0600),         |
	  socket]     |                   | write header if empty]              |
	              v                   v                                     |
	      +---------------+   +---------------+                             |
	      |     BOUND     |   |    LOGGING    |<-- process()                |
	      | socket open,  |   | log open,     |    [write row, count + 1]   |
	      | no log file   |   | no socket     |                             |
	      +---------------+   +---------------+                             |
	              |                   |                                     |
	  reopen_log()|                   |open_socket()                        |
	              |    +---------+    |                                     |
	              +--->|  READY  |<---+                                     |
	                   | socket  |<-- process()   [write row, count + 1]    |
	                   | and log |<-- reopen_log() [close, reopen file]     |
	                   +---------+                                          |
	                        |                                               |
	                        | run()   [also allowed from IDLE, BOUND or     |
	                        |          LOGGING: opens what is missing;      |
	                        v          installs HUP/TERM/INT handlers]      |
	                   +---------+                                          |
	   datagram ------>|         |   [process(): write row, count + 1]      |
	   SIGHUP -------->| RUNNING |   [reopen_log() at top of loop]          |
	   read error ---->|         |   [warning; keep going]                  |
	                   +---------+                                          |
	                        |                                               |
	                        | SIGTERM, SIGINT or stop()                     |
	                        v         [clear "running" flag]                |
	                   +----------+                                         |
	                   | STOPPING |   the current wait or datagram ends     |
	                   +----------+                                         |
	                        |                                               |
	                        | loop sees the flag                            |
	                        | [close socket and log; restore caller's       |
	                        |  signal handlers; run() returns]              |
	                        +-----------------------------------------------+

=head2 Transition table

	+----------+-------------------------------+----------+------------------------------------+
	| From     | Trigger                       | To       | Action / side effect               |
	+----------+-------------------------------+----------+------------------------------------+
	| (none)   | new()                         | IDLE     | options checked and stored         |
	| (none)   | new(socket => S)              | BOUND    | S used as the socket               |
	| IDLE     | open_socket()                 | BOUND    | UDP socket bound                   |
	| IDLE     | reopen_log()                  | LOGGING  | file opened or created, header     |
	| BOUND    | reopen_log()                  | READY    | file opened or created, header     |
	| LOGGING  | open_socket()                 | READY    | UDP socket bound                   |
	| BOUND    | open_socket()                 | BOUND    | nothing (already bound)            |
	| READY    | open_socket()                 | READY    | nothing (already bound)            |
	| LOGGING  | reopen_log()                  | LOGGING  | file closed and opened again       |
	| READY    | reopen_log()                  | READY    | file closed and opened again       |
	| LOGGING  | process()                     | LOGGING  | one row written, count + 1         |
	| READY    | process()                     | READY    | one row written, count + 1         |
	| IDLE,    | run()                         | RUNNING  | open what is missing, install      |
	| BOUND,   |                               |          |   signal handlers, set "running"   |
	| LOGGING, |                               |          |                                    |
	| READY    |                               |          |                                    |
	| RUNNING  | datagram arrives              | RUNNING  | process(): row written, count + 1  |
	| RUNNING  | SIGHUP                        | RUNNING  | log closed and opened again        |
	| RUNNING  | read error (not a signal)     | RUNNING  | warning "Error receiving ..."      |
	| RUNNING  | SIGTERM, SIGINT or stop()     | STOPPING | "running" flag cleared             |
	| STOPPING | the wait or datagram ends     | IDLE     | socket and log closed, handlers    |
	|          |                               |          |   restored, run() returns          |
	+----------+-------------------------------+----------+------------------------------------+

Failures (the method dies and the object changes as shown):

	+----------+-------------------------------+----------+------------------------------------+
	| From     | Trigger                       | To       | Action / side effect               |
	+----------+-------------------------------+----------+------------------------------------+
	| IDLE,    | open_socket() fails           | (same)   | dies "Could not create a UDP       |
	| LOGGING  |                               |          |   socket ..."                      |
	| IDLE,    | reopen_log() fails            | (same)   | dies "Could not open log file ..." |
	| BOUND    |                               |          |   or "Refusing to log ..."         |
	| LOGGING, | reopen_log() fails            | IDLE or  | log closed, then dies "Could not   |
	| READY    |                               | BOUND    |   open log file ..." or            |
	|          |                               |          |   "Refusing to log ..."            |
	| IDLE,    | process()                     | (same)   | dies "process() was called before  |
	| BOUND    |                               |          |   reopen_log() succeeded"          |
	| RUNNING  | SIGHUP, and the reopen fails  | BOUND    | log closed, handlers restored,     |
	|          |                               |          |   run() dies with the error        |
	+----------+-------------------------------+----------+------------------------------------+

C<port()>, C<address()>, C<count()>, C<parse_message()> and C<i18n()> never
change the state.  C<stop()> outside C<run()> changes nothing that matters,
because C<run()> sets the "running" flag again when it starts.

=cut

1;
