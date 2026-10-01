## Name

App::Syslogd - A small UDP syslog receiver that writes a CSV file

## Version

Version 0.02

## Synopsis

### 1. Run a Syslog Server

This is what the program `etc/syslogd` does.  It listens for messages
until it receives SIGTERM or SIGINT (Ctrl-C).

```perl
    use App::Syslogd;

    my $server = App::Syslogd->new(
            port => 5514,                           # 514 needs root
            file => '/var/log/remote-syslog.csv',
    );
    $server->open_socket()->reopen_log();   # fail now, not later
    print $server->i18n('listening', {
            address => $server->address(),
            port => $server->port(),
    }), "\n";
    $server->run();                         # waits here until stopped
    print $server->i18n('shutdown', { count => $server->count() }), "\n";
```

### 2. Decode One Message, Without a Network or a File

`parse_message()` uses no state, so you can call it on the class.

```perl
    use App::Syslogd;

    my $record = App::Syslogd->parse_message('<34>su: authentication failure');
    print "facility $record->{facility}, severity $record->{severity}\n";
    # facility 4, severity 2
```

### 3. Record Messages That Your Own Code Received

Use this when your program already has a socket loop, for example an event
loop that watches many sockets.

```perl
    use App::Syslogd;
    use IO::Socket::IP;

    my $recorder = App::Syslogd->new(file => '/var/log/remote.csv', resolve => 0);
    $recorder->reopen_log();

    my $socket = IO::Socket::IP->new(LocalPort => 5514, Proto => 'udp')
            or die "Cannot listen: $IO::Socket::errstr";
    while(my $peer = $socket->recv(my $datagram, 65535)) {
            $recorder->process($datagram, $peer);
    }
```

### 4. Use a Socket That Someone Else Opened, for a Fixed Time

Pass the socket to `new()`, for example one received from systemd socket
activation, or one opened before giving up root.  `stop()` ends `run()`.

```perl
    my $server = App::Syslogd->new(socket => $already_bound_socket, file => $file);

    local $SIG{ALRM} = sub { $server->stop() };
    alarm(3600);            # stop after one hour
    $server->run();
```

### 5. Change How the Sender Is Written in the Log

`_peer_name()` is protected: a subclass may replace it.

```perl
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
```

## Description

### What Syslog Is

Many machines (servers, routers, printers, firewalls) can send their log
messages over the network with the _syslog_ protocol.  Each message is one
UDP packet, called a _datagram_.  A message usually starts with a number in
angle brackets, the _PRI_ (priority), for example `<34>`.  The PRI
holds two smaller numbers:

- **facility** = PRI divided by 8, rounded down (0 to 23).  It says which
part of the system sent the message, for example 4 means "security".
- **severity** = the remainder of PRI divided by 8 (0 to 7).  It says how
serious the message is: 0 is "emergency" and 7 is "debug".

So `<34>` means facility 4 (34 / 8 = 4) and severity 2 (34 - 32 = 2).

### What This Module Does

It waits for syslog datagrams and adds one line to a CSV file for each one.
The first line of a new file names the columns:

```
    "Host","facility","severity","msg"
    "router.example.com","4","2","su: authentication failure"
```

- **Host** is the name of the machine that sent the message.  The name
is found with the normal system lookup (`/etc/hosts`, then DNS) and
remembered for a few minutes.  If no name is found, or if you turn names
off, the IP address is written instead.  IPv4 and IPv6 both work.
- **facility** and **severity** come from the PRI.  If the PRI is missing
or not valid, the message is still kept: it is recorded as facility 1,
severity 5 ("user.notice"), and the whole datagram becomes the message.
RFC 3164 section 4.3.3 asks for this.  A valid PRI is a number from 0 to 191
with no extra leading zeros.
- **msg** is the rest of the datagram.  Line endings at the end are
removed.  Other control characters, including a newline in the middle, are
written as `\xNN` (for example `\x0A`).  So every message is exactly one
line, and nobody can create a fake extra line by sending a newline.

### Other Behaviour

- Signal **SIGHUP** closes and reopens the log file.  Log rotation tools
such as logrotate use this: they rename the file, then send SIGHUP, and the
server starts a new file.
- Signals **SIGTERM** and **SIGINT** stop the server cleanly.
- The log file is created so that only its owner can read it (mode
0600).  The server will not write through a symbolic link or a hard link, or
into a file that another user owns.  This protects against attacks that trick
a root process into overwriting a file.  (Windows is weaker here: see
["LIMITATIONS"](#limitations).)
- Datagrams up to 65535 bytes (the largest UDP size) are read
completely.  Datagrams shorter than 2 characters are ignored.

## Command Line

The program `etc/syslogd` is a small wrapper around this module:

```
    /usr/local/etc/syslogd [--port 514] [--address 0.0.0.0] [--file /tmp/syslog.log]
            [--no-resolve] [--language en]
```

- `--port` - the UDP port to listen on.  The default is 514, the
standard syslog port.  Ports below 1024 need root.
- `--address` - the local address to listen on.  The default
`0.0.0.0` means "every IPv4 address of this machine".  Use `::` for IPv6.
- `--file` - the CSV log file.  The default `/tmp/syslog.log` exists
only for compatibility with older versions.  For real use, choose a private
place, such as `/var/log/remote-syslog.csv` (see ["LIMITATIONS"](#limitations)).
- `--no-resolve` - write IP addresses instead of host names.  This is
faster on a busy server.
- `--language` - the language of the program's own messages, for example
`en`.  By default it comes from the environment (`LANG` and similar).

Send **SIGHUP** to reopen the log file.  Send **SIGTERM**, or press Ctrl-C, to
stop.

### Log Rotation

An example logrotate configuration:

```
    /var/log/remote-syslog.csv {
            weekly
            rotate 8
            postrotate
                    pkill -HUP -f /usr/local/etc/syslogd
            endscript
    }
```

## Installation

Install the module from CPAN:

```
    cpanm App::Syslogd
```

or from a git checkout:

```
    perl Makefile.PL && make && make test && sudo make install
```

Then copy the program by hand:

```
    sudo cp etc/syslogd /usr/local/etc/
```

`make install` does not install the program on purpose.  It would put it in
a `bin` directory, and a program called `syslogd` there could hide the
system's own `/usr/sbin/syslogd`.

To use a git checkout without installing the module, copy the module next to
the program:

```
    sudo cp -r lib/App /usr/local/lib/
```

The program looks for modules in `../lib` relative to itself (that is
`/usr/local/lib` after installation, or `lib/` in a git checkout), and also
in Perl's normal module directories.

## Dependencies

Perl 5.14 or later, and these modules: [autodie](https://metacpan.org/pod/autodie) (which needs
[IPC::System::Simple](https://metacpan.org/pod/IPC%3A%3ASystem%3A%3ASimple)), [CHI](https://metacpan.org/pod/CHI), [IO::Socket::IP](https://metacpan.org/pod/IO%3A%3ASocket%3A%3AIP), [Locale::Maketext](https://metacpan.org/pod/Locale%3A%3AMaketext),
[Params::Get](https://metacpan.org/pod/Params%3A%3AGet), [Params::Validate::Strict](https://metacpan.org/pod/Params%3A%3AValidate%3A%3AStrict), [Readonly](https://metacpan.org/pod/Readonly), [Socket](https://metacpan.org/pod/Socket),
[Sub::Private](https://metacpan.org/pod/Sub%3A%3APrivate), [Sub::Protected](https://metacpan.org/pod/Sub%3A%3AProtected) and [Text::CSV](https://metacpan.org/pod/Text%3A%3ACSV).  `Makefile.PL` lists
the minimum versions.

## Files

- `etc/syslogd` - the command-line program.  Install it as
`/usr/local/etc/syslogd`.
- `lib/App/Syslogd.pm` - this module.
- `lib/App/Syslogd/I18N.pm` and `lib/App/Syslogd/I18N/en.pm` - the
messages that people see, and their English text.
- `t/` - the tests.  Run them with `prove -l t/`.
- `www/` - a web page that shows the log.  It is only in the git
repository, not in the CPAN distribution.

## Encoding

The module works with **bytes**, not with decoded text.  It never decodes or
encodes anything itself.

- **Datagrams** (`parse_message()`, `process()`, and everything that
`run()` receives) can contain any bytes.  UTF-8 text, other non-ASCII text
and emoji are written to the file exactly as they arrived.  Invalid UTF-8 is
also written unchanged.  Only bytes 0x00 to 0x1F and 0x7F are changed (to
`\xNN`).  Bytes 0x80 to 0x9F are not changed, so a UTF-8 character is never
broken.
- If you call `parse_message()` or `process()` yourself with a Perl
_character_ string (text that came from `decode()`, or that contains a
character above 255, such as an emoji written as `"\x{1F600}"`), first
encode it to bytes, for example with `Encode::encode('UTF-8', $text)`.
Otherwise Perl prints a "Wide character" warning when the line is written.
- **The file name** (`file`) is passed to the operating system as
bytes.  A name with non-ASCII characters must be given as encoded bytes
(normally UTF-8 on Unix).
- **Host names** come from the system resolver.  An international domain
name normally arrives in its ASCII form (`xn--...`).
- **The language tag** (`language`) must be ASCII, for example `en-gb`.
- **Messages from i18n()** are Perl strings.  The English messages are
ASCII, but a value you pass in (for example a file name) is copied into the
message as it is.  If you print a message that contains wide characters,
set an output layer first: `binmode(STDOUT, ':encoding(UTF-8)')`.

## Common Pitfalls

- **undef means "use the default".**  `new(file => undef)` gives the
default file, not an empty file name.  This is useful when you pass options
straight from [Getopt::Long](https://metacpan.org/pod/Getopt%3A%3ALong), but it means you cannot use `undef` to switch
something off.  To turn off host names, use `resolve => 0`.
- **The options are merged one level deep only.**  Each option you give
replaces the default with the same name; nothing is merged inside a value.
Objects you pass (`cache`, `socket`) are shared, not copied: two servers
given the same `cache` object share their host name answers.
- **True and false.**  `resolve` accepts 1, 0, and the words `true`,
`false`, `yes`, `no`, `on` and `off`.  Any other value, such as 2, is an
error.
- **Order of calls.**  `process()` needs an open log, so call
`reopen_log()` first.  `run()` opens the socket and the log by itself if
you have not.
- **Signals are handled only inside run().**  Before `run()` starts and
after it returns, SIGHUP has its normal effect, which is to end the program.
`run()` puts back your own signal handlers when it returns.
- **stop() before run() does nothing.**  `run()` sets the "running"
flag when it starts, so an earlier `stop()` is forgotten.
- **run() closes everything when it returns.**  If you call `run()`
again, it opens a new socket.  With `port => 0`, the new socket can get
a different port number.
- **A failed reopen stops run().**  If SIGHUP arrives and the log file
cannot be opened (for example, the directory was removed), `run()` dies
with the error.  The socket stays open and the log stays closed.
- **An existing log file is made private.**  `reopen_log()` changes the
file's permissions to 0600 without asking (except on Windows; see
["LIMITATIONS"](#limitations)).
- **A short datagram is ignored silently.**  After removing line endings
at the end, a datagram must have at least 2 characters.  `parse_message()`
then returns `undef`, and `process()` writes nothing and does not count it.
- **A missing sender is not an error.**  `process($datagram, undef)`
writes the message with an empty Host column.
- **port() and address() change meaning.**  Before `open_socket()` they
return what you asked for.  After it they return what the system actually
gave, so `port => 0` becomes a real port number.
- **Backslashes are not escaped.**  A message that really contains the
four characters `\x0A` looks the same in the file as an escaped newline.

## Methods

Every method except `parse_message()` and `i18n()` needs an object made by
`new()`; those two also work on the class.  Methods that have nothing
useful to return give back the object, so you can chain calls:

```perl
    App::Syslogd->new(port => 5514)->open_socket()->reopen_log()->run();
```

The mathematical description of each method is in
["FORMAL SPECIFICATION"](#formal-specification), and the life cycle of an object is in
["STATE DIAGRAM"](#state-diagram), both at the end of this document.

### New

Purpose: make a new server object.  It does not open the network or the
file yet, so you can create and inspect it without any special permissions.

Args: all optional, given as a list of pairs or as one hash reference.  An
option given as `undef` uses its default.

- `port` - the UDP port number, 0 to 65535.  Default 514.  0 means
"let the system choose a free port"; call `port()` after `open_socket()`
to find out which one.
- `address` - the local address to listen on.  Default `0.0.0.0` (all
IPv4 addresses).  Use `::` for IPv6.
- `file` - the CSV log file.  Default `/tmp/syslog.log`.
- `resolve` - true (the default) to write host names, false to write
IP addresses.
- `dns_ttl` - how many seconds to remember a host name.  Default 300.
- `dns_cache_bytes` - the most memory, in bytes, used to remember host
names.  Default 262144.
- `language` - the language of messages, such as `en`.  Default: from
the environment.
- `cache` - your own cache for host names, instead of the built-in
one.  Any object with a [CHI](https://metacpan.org/pod/CHI)-style `compute()` method.
- `socket` - a socket that is already open, instead of opening one.
Any object with a `recv()` method.

Returns: the new object.

Side Effects: none.  Dies if an option is unknown or has a wrong value.

Usage:

```perl
    my $server = App::Syslogd->new({ port => 514, resolve => 0 });
```

#### Example

```perl
    # Listen on a port that does not need root, and write addresses only
    my $server = App::Syslogd->new(port => 5514, resolve => 0);

    # Options from Getopt::Long: options not given stay undef = default
    my %opts;
    GetOptions(\%opts, 'port=i', 'file=s');
    my $server2 = App::Syslogd->new(\%opts);
```

#### Api Specification

##### Input

```perl
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
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```
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
```

#### Pseudocode

```
    check the options against the schema (die if one is wrong)
    remove options whose value is undef
    start from the defaults, then copy the options over them
    set the message counter to 0
    choose the message language
    if no cache was given, make an in-memory cache
    make the CSV writer
    return the object
```

### Open\_Socket

Purpose: start listening for UDP datagrams on the configured address and
port.  If the port is below 1024, do this before your program gives up root.

Args: none.

Returns: the object, so you can chain another call.

Side Effects: opens a UDP socket.  Does nothing if a socket is already open,
including one given to `new()`.

Usage:

```
    $server->open_socket();
```

#### Example

```perl
    # Let the system choose a free port, then ask which one it chose
    my $server = App::Syslogd->new(port => 0)->open_socket();
    print 'Listening on port ', $server->port(), "\n";
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```perl
    +---------------------------------+---------------------------+------------------------------+
    | Message (dies)                  | Meaning                   | What to do                   |
    +---------------------------------+---------------------------+------------------------------+
    | Could not create a UDP socket   | The system refused: the   | Run as root for ports below  |
    |   on ADDR port N: ERROR         |   port is in use, needs   |   1024, stop the other       |
    |                                 |   root, or the address is |   syslog server, or correct  |
    |                                 |   wrong                   |   the address                |
    +---------------------------------+---------------------------+------------------------------+
```

### Port

Purpose: tell you the UDP port number.

Args: none.

Returns: a whole number from 0 to 65535.  Before `open_socket()` it is the
port you asked for.  After it, it is the port really in use, so
`port => 0` becomes the number the system chose.

Side Effects: none.

Usage:

```perl
    my $port = $server->port();
```

#### Example

```
    print App::Syslogd->new()->port(), "\n";        # 514
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'integer', min => 0, max => 65535 }
```

#### Messages

None.

### Address

Purpose: tell you the local address the server listens on.

Args: none.

Returns: a string, such as `0.0.0.0` or `::1`.  Before `open_socket()` it
is the address you asked for.  After it, it is the address the system reports.

Side Effects: none.

Usage:

```perl
    my $address = $server->address();
```

#### Example

```perl
    print App::Syslogd->new(address => '::')->address(), "\n";      # ::
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'string', min => 1 }
```

#### Messages

None.

### Count

Purpose: tell you how many datagrams have been written to the log.

Args: none.

Returns: a whole number, 0 or more.  Ignored datagrams (shorter than 2
characters) are not counted.  A datagram that could not be written because
the disk was full is counted.

Side Effects: none.

Usage:

```
    print $server->count(), " messages\n";
```

#### Example

```
    $server->reopen_log()->process('<13>hello', $peer);
    print $server->count(), "\n";   # 1
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'integer', min => 0 }
```

#### Messages

None.

### Reopen\_Log

Purpose: open the CSV log file, closing it first if it is already open.  Use
it once at the start.  `run()` also calls it when SIGHUP arrives, so that
after a log rotation tool renames the file, a new file is started.

Args: none.

Returns: the object, so you can chain another call.

Side Effects:

- Closes the log file if it is open.
- Creates the file if it does not exist, readable only by its owner.
- Writes the column names if the file is empty.
- Changes an existing file's permissions to 0600 (not on Windows).
- Dies, leaving no log open, if the file cannot be used safely.

Usage:

```
    $server->reopen_log();
```

#### Example

```perl
    # Open the log before starting, so that a problem is reported at once
    my $server = App::Syslogd->new(file => '/var/log/remote.csv');
    eval { $server->reopen_log(); 1 } or die "Cannot start: $@";
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```
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
```

### Parse\_Message

Purpose: split one datagram into its facility, severity and message text.
It uses no state and writes nothing, so you can call it on the class and use
it on its own.

Args: one datagram, as a string of bytes.

Returns: `undef` if the datagram is too short to be a message (fewer than 2
characters after removing line endings at the end).  Otherwise a hash
reference with these keys:

- `facility` - 0 to 23.
- `severity` - 0 to 7.
- `message` - the text after the PRI, with control characters
written as `\xNN`.
- `valid` - 1 if the datagram had a valid PRI.  0 if not; then facility
is 1, severity is 5, and `message` is the whole datagram.

Side Effects: none.

Usage:

```perl
    my $record = App::Syslogd->parse_message($datagram);
```

#### Example

```perl
    my $r = App::Syslogd->parse_message("<34>su: 'su root' failed\n");
    # { facility => 4, severity => 2, message => "su: 'su root' failed", valid => 1 }

    $r = App::Syslogd->parse_message("no pri\there");
    # { facility => 1, severity => 5, message => 'no pri\x09here', valid => 0 }

    $r = App::Syslogd->parse_message("x\n");
    # undef: too short
```

#### Api Specification

##### Input

```perl
    {
            datagram => { type => 'string', optional => 1, position => 0 },
    }
```

##### Output

```perl
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
```

#### Messages

None.  A malformed datagram is recorded, never rejected.

#### Pseudocode

```perl
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
```

### Process

Purpose: write one received datagram to the log.

Args:

- 1. The datagram, as a string of bytes.
- 2. The sender's address, in the packed form that `recv()` returns.
`undef` is allowed: the Host column is then empty.

Returns: the object, so you can chain another call.

Side Effects:

- May look up the sender's host name (the answer is remembered).
- Adds one line to the log and adds 1 to `count()`, unless the
datagram is too short, in which case nothing happens.
- If the line cannot be written (for example, the disk is full), it
warns and continues.  That message is lost, but the server keeps working.

Usage:

```perl
    my $peer = $socket->recv(my $datagram, 65535);
    $server->process($datagram, $peer);
```

#### Example

```perl
    use Socket qw(pack_sockaddr_in inet_aton);

    my $peer = pack_sockaddr_in(514, inet_aton('192.0.2.1'));
    $server->reopen_log()->process('<13>hello', $peer);
    # The file now ends with: "192.0.2.1","1","5","hello"
```

#### Api Specification

##### Input

```perl
    {
            datagram => { type => 'string', optional => 1, position => 0 },
            peer => { type => 'string', optional => 1, position => 1 },
    }
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```
    +-----------------------------------+------------------------------+-------------------------------+
    | Message                           | Meaning                      | What to do                    |
    +-----------------------------------+------------------------------+-------------------------------+
    | process() was called before       | No log file is open (dies)   | Call reopen_log() first       |
    |   reopen_log() succeeded          |                              |                               |
    | Could not write to log file F:    | The line was not written,    | Free disk space; this message |
    |   ERROR                           |   e.g. disk full (warning)   |   is lost, later ones are not |
    +-----------------------------------+------------------------------+-------------------------------+
```

### Run

Purpose: the main loop.  Wait for datagrams and write each one to the log,
until told to stop.

Args: none.

Returns: the object, after SIGTERM, SIGINT or `stop()`.

Side Effects:

- Calls `open_socket()` and `reopen_log()` first if they have not been
called.
- While it runs: SIGHUP reopens the log, and SIGTERM or SIGINT stop the
loop.  Your own handlers for these three signals are put back when it
returns.
- When it returns, the socket and the log file are closed.

Usage:

```
    $server->run();
```

#### Example

```perl
    my $server = App::Syslogd->new(port => 5514, file => '/var/log/remote.csv');
    $server->run();         # Ctrl-C to stop
    print $server->i18n('shutdown', { count => $server->count() }), "\n";
    # Syslog server shutting down after recording 42 messages
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```
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
```

#### Pseudocode

```
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
```

### Stop

Purpose: ask `run()` to finish.  `run()` returns after the datagram it is
handling, or at once if it is waiting.

Args: none.

Returns: the object.

Side Effects: clears the "running" flag.  Calling it before `run()` has no
effect, because `run()` sets the flag when it starts.

Usage:

```
    $server->stop();
```

#### Example

```perl
    # Run for one minute
    local $SIG{ALRM} = sub { $server->stop() };
    alarm(60);
    $server->run();
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

None.

### i18n

Purpose: make a message for people to read, in the server's language.  All
of this module's own messages are made with it, so they can be translated.

Args:

- 1. The message key, for example `listening`.  The keys are in the
table below.
- 2. Optional: a hash reference of values to put into the message, for
example `{ port => 514 }`.  A missing value becomes an empty string.

It also works on the class (`App::Syslogd->i18n(...)`); the language then
comes from the environment.

Returns: the message as a string.  An unknown key does not die: you get the
key and its values back, such as `no_such_key (a=1)`.

Side Effects: none.

Usage:

```perl
    print $server->i18n('listening', { address => '0.0.0.0', port => 514 }), "\n";
```

#### Example

```perl
    print App::Syslogd->i18n('shutdown', { count => 1 }), "\n";
    # Syslog server shutting down after recording 1 message
    print App::Syslogd->i18n('shutdown', { count => 3 }), "\n";
    # Syslog server shutting down after recording 3 messages
```

#### Api Specification

##### Input

```perl
    {
            key => { type => 'string', min => 1, position => 0 },
            args => { type => 'hashref', optional => 1, position => 1 },
    }
```

##### Output

```perl
    { type => 'string' }
```

#### Messages

The keys, the values each one uses, and the English text:

```
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
```

## Limitations

- **The default log file is in /tmp.**  This keeps compatibility with
older versions.  The checks described in ["DESCRIPTION"](#description) stop the usual
attacks on files in `/tmp`, but another user can still delete the file.
Use `file` (or `--file`) to choose a private place such as `/var/log`.
- **The web viewer cannot read the log.**  The file is readable only by
its owner (usually root), but the web pages in `www/` run as the web
server's user.  You must choose between privacy and the viewer, for example
by using a shared group and changing `$LOG_MODE` in the source.
- **It does not give up root.**  Port 514 needs root (or the
CAP\_NET\_BIND\_SERVICE capability), and the server keeps root while it runs.
Better: use a port above 1023 with a firewall redirect, or let systemd open
the socket and pass it with `new(socket => ...)`.
- **No time of arrival.**  A line holds only what the sender put in the
message.  Adding a column would break existing files and the web viewer, so
it needs a migration and has not been done.
- **Host name lookups block.**  Answers are remembered, but the first
message from a host with a slow DNS server makes the loop wait, and the
system may drop datagrams that arrive during the wait.  Use `--no-resolve`
on a busy server.
- **UDP only.**  There is no TCP (RFC 6587) or TLS (RFC 5425).  So
delivery is not guaranteed, and anyone who can reach the port can write to
the log.
- **Only the PRI is decoded.**  Time stamps and host names inside RFC 3164
messages, and RFC 5424 structured data, stay in the `msg` column.
- **Spreadsheet formulas.**  A message that starts with `=`, `+`, `-`
or `@` may run as a formula if you open the file in a spreadsheet.  The
data is kept unchanged on purpose; take care when you open it.
- **Backslashes are not escaped**, so the text `\x0A` and an escaped
newline look the same (see ["COMMON PITFALLS"](#common-pitfalls)).
- **Windows is less protected.**  The module works on Windows, but:
    - Windows has no `O_NOFOLLOW`, so the server cannot refuse a symbolic
    link as the log file.  (Creating a symbolic link on Windows normally needs
    administrator rights, which makes this attack rare.)
    - Mode 0600 does not make the file private: Windows uses access control
    lists, which this module does not change.  An existing file's permissions
    are not changed either, because Windows Perl cannot change the permissions
    of an open file.  Put the log in a folder that only the right users can
    read.
    - There is no `kill -HUP` from outside the process, so log rotation by
    signal is not available.  Stop and restart the server instead.
    - A signal such as Ctrl-C may not interrupt the wait for a datagram, so
    the server may stop only after the next datagram arrives.
- **Object::Configure is not used.**  `%DEFAULTS` has the flat form that
Object::Configure uses, but its `configure()` is not called.  It would add a
global logger that may log through syslog, and a syslog server that logs to
itself can loop.

## Author

Nigel Horne, `<njh at nigelhorne.com>`

## Formal Specification

This section describes each method exactly, in the Z notation.  You do not
need it to use the module; the descriptions in ["METHODS"](#methods) say the same
things in words.

### State

```
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
```

### New

```
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
```

### Open\_Socket

```
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
```

### Port

```
    Port
      ΞServer
      p! : PORT
      ─────────
      p! = port
```

### Address

```
    Address
      ΞServer
      a! : ADDRESS
      ─────────
      a! = address
```

### Count

```
    Count
      ΞServer
      n! : ℕ
      ─────────
      n! = count
```

### Reopen\_Log

```
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
```

### Parse\_Message

```
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
```

### Process

```
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
```

### Run

```
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
```

### Stop

```
    Stop
      ΔServer
      ─────────
      ¬running' ∧ bound' = bound ∧ logging' = logging ∧ count' = count
```

### i18n

```
    I18n
      key? : KEY ; args? : NAME ⇸ VALUE ; out! : STRING
      ─────────
      key? ∈ dom ARGUMENT_ORDER ⇒
        out! = render(lexicon(language, key?),
                      ⟨args?(n) | n ∈ ARGUMENT_ORDER(key?)⟩)
      key? ∉ dom ARGUMENT_ORDER ⇒ key? ⊑ out!
```

## State Diagram

An object is always in one of six states.  The boxes are the states; the
arrows are the method calls or events that move it from one state to another.
The text in square brackets is what happens during the move.

```perl
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
```

### Transition Table

```perl
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
```

Failures (the method dies and the object changes as shown):

```
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
```

`port()`, `address()`, `count()`, `parse_message()` and `i18n()` never
change the state.  `stop()` outside `run()` changes nothing that matters,
because `run()` sets the "running" flag again when it starts.

## License and Copyright

Copyright 2026 Nigel Horne.

Usage is subject to the GPL2 licence terms.
If you use it,
please let me know.
