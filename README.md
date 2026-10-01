## Name

App::Syslogd - A small UDP syslog receiver that writes a CSV file

## Version

Version 0.02

## Synopsis

```perl
    use App::Syslogd;

    my $server = App::Syslogd->new(port => 5514, file => '/var/log/remote.csv');
    $server->open_socket()->reopen_log();
    print $server->i18n('listening', { address => '0.0.0.0', port => $server->port() }), "\n";
    $server->run();         # returns after SIGTERM or SIGINT
```

## Description

Receives RFC 3164 / RFC 5424 syslog datagrams over UDP, splits the PRI
field into facility and severity, and appends one CSV row per datagram:

```
    "Host","facility","severity","msg"
```

- **SIGHUP** closes and reopens the log file, for use with logrotate.
- **SIGTERM** and **SIGINT** make `run()` return cleanly.
- Control characters (including embedded newlines) in a message are
written as `\xNN`, so every record is exactly one line and nobody can
forge a record by sending a newline.
- A datagram without a valid PRI is recorded as `user.notice` (PRI 13),
as RFC 3164 section 4.3.3 requires, with the whole datagram as the message.
A valid PRI is 0-191 with no leading zeros (RFC 5424 section 6.2.1).
- The sender is logged by host name, looked up through the system
resolver (so `/etc/hosts` is honoured) and cached.  With `--no-resolve`
it is logged by address.  IPv4 and IPv6 are both supported.
- The log file is created with mode 0600.  The server refuses to write
through a symlink or a hard link, or to a file owned by another user.
- Datagrams of up to 65535 bytes are accepted without truncation.

## Command Line

The program `etc/syslogd` is a thin wrapper around this module:

```
    /usr/local/etc/syslogd [--port 514] [--address 0.0.0.0] [--file /tmp/syslog.log]
            [--no-resolve] [--language en]
```

- `--port` - UDP port to listen on, default 514 (which needs root).
- `--address` - local address to bind, default `0.0.0.0`; use `::` for IPv6.
- `--file` - the CSV log file, default `/tmp/syslog.log`.  The default
is kept for compatibility only; choose somewhere private for real use (see
["LIMITATIONS"](#limitations)).
- `--no-resolve` - log sender addresses instead of host names.
- `--language` - language for the program's own messages; by default
it is taken from the environment.

Send **SIGHUP** to reopen the log file and **SIGTERM** or **SIGINT** to stop.

### Log Rotation

An example logrotate stanza:

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

or, from a git checkout:

```
    perl Makefile.PL && make && make test && sudo make install
```

Then install the program by hand.  It is deliberately not installed by
`make install`: that would put it in a `bin` directory, where a program
called `syslogd` could shadow the system's `/usr/sbin/syslogd` on `PATH`.

```
    sudo cp etc/syslogd /usr/local/etc/
```

To run from a checkout without installing the module, copy it alongside:

```
    sudo cp -r lib/App /usr/local/lib/
```

The program looks for its modules in `../lib` relative to itself (which is
`/usr/local/lib` once installed, or `lib/` in a git checkout) as well as
on Perl's normal `@INC`.

## Dependencies

Perl 5.14 or later, plus [autodie](https://metacpan.org/pod/autodie) (with [IPC::System::Simple](https://metacpan.org/pod/IPC%3A%3ASystem%3A%3ASimple)), [CHI](https://metacpan.org/pod/CHI),
[IO::Socket::IP](https://metacpan.org/pod/IO%3A%3ASocket%3A%3AIP), [Locale::Maketext](https://metacpan.org/pod/Locale%3A%3AMaketext), [Params::Get](https://metacpan.org/pod/Params%3A%3AGet),
[Params::Validate::Strict](https://metacpan.org/pod/Params%3A%3AValidate%3A%3AStrict), [Readonly](https://metacpan.org/pod/Readonly), [Socket](https://metacpan.org/pod/Socket), [Sub::Private](https://metacpan.org/pod/Sub%3A%3APrivate),
[Sub::Protected](https://metacpan.org/pod/Sub%3A%3AProtected) and [Text::CSV](https://metacpan.org/pod/Text%3A%3ACSV).  The exact versions are in `Makefile.PL`.

## Files

- `etc/syslogd` - the command-line program, installed as `/usr/local/etc/syslogd`.
- `lib/App/Syslogd.pm` - this module.
- `lib/App/Syslogd/I18N.pm`, `lib/App/Syslogd/I18N/en.pm` - the message catalogue.
- `t/` - the tests; run them with `prove -l t/`.
- `www/` - a VWF-based web viewer for the log (git checkout only; it is
not part of the CPAN distribution).

## Methods

### New

Purpose: create a server object.  Nothing is bound or opened yet, so the
object can be built and inspected without privileges.

Args (all optional, as a hash or hashref):

- `port` - UDP port, default 514.  0 lets the kernel choose; call
`port()` after `open_socket()` to see which.
- `address` - local address to bind, default `0.0.0.0`.  Use `::` for
IPv6.
- `file` - CSV log file, default `/tmp/syslog.log`.
- `resolve` - log host names (true, default) or addresses (false).
- `dns_ttl`, `dns_cache_bytes` - reverse-lookup cache tuning.
- `language` - message language tag; default is from the environment.
- `cache` - a [CHI](https://metacpan.org/pod/CHI)-compatible object used instead of the built-in
reverse-lookup cache.
- `socket` - an already-bound socket (anything with `recv`), mainly
for tests and socket activation.

Returns: a blessed `App::Syslogd`.

Side Effects: none.

Usage:

```perl
    my $server = App::Syslogd->new({ port => 514, resolve => 0 });
```

#### Example

```perl
    # Listen on an unprivileged port and log addresses, not names
    my $server = App::Syslogd->new(port => 5514, resolve => 0);
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
    +-------------------------------+------------------------+---------------------------+
    | Message                       | Meaning                | Resolution                |
    +-------------------------------+------------------------+---------------------------+
    | validate_strict: Unknown      | Misspelt argument      | Check the argument list   |
    |   parameter 'x'               |                        |   above                   |
    | validate_strict: Parameter    | Out-of-range value     | Use a port in 0..65535    |
    |   'port' ... must be ...      |                        |                           |
    +-------------------------------+------------------------+---------------------------+
```

#### Formal Specification

```
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
```

### Open\_Socket

Purpose: bind the UDP socket.  Do this before dropping privileges if the port
is below 1024.

Args: none.

Returns: `$self`, for chaining.

Side Effects: binds a socket.  Does nothing if a socket was given to `new()`.

Usage:

```
    $server->open_socket();
```

#### Example

```perl
    my $server = App::Syslogd->new(port => 0)->open_socket();
    print 'Kernel chose port ', $server->port(), "\n";
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
    +--------------------------------+-------------------------+----------------------------+
    | Message                        | Meaning                 | Resolution                 |
    +--------------------------------+-------------------------+----------------------------+
    | Could not create a UDP socket  | bind() failed: port in  | Run as root for port 514,  |
    |   on ADDR port N: ERROR        |   use, no permission or |   stop the other syslogd,  |
    |                                |   bad address           |   or fix --address         |
    +--------------------------------+-------------------------+----------------------------+
```

#### Formal Specification

```
    OpenSocket
      ΔServer
      ─────────
      listening' ∧ (port = 0 ⇒ port' ∈ 1 .. 65535) ∧ (port ≠ 0 ⇒ port' = port)
```

### Port

Purpose: the UDP port actually in use.

Args: none.

Returns: an integer.  After `open_socket()` with `port => 0` this is the
kernel-assigned port; before `open_socket()` it is the configured port.

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

#### Formal Specification

```
    Port
      ΞServer
      p! : PORT
      ─────────
      p! = port
```

### Address

Purpose: the local address the socket is bound to.

Args: none.

Returns: a string.  After `open_socket()` this is what the kernel reports;
before it, the configured address.

Side Effects: none.

Usage:

```perl
    my $address = $server->address();
```

#### Example

```perl
    print App::Syslogd->new(address => "::")->address(), "\n";      # ::
```

#### Api Specification

##### Input

```
    {}
```

##### Output

```perl
    { type => "string", min => 1 }
```

#### Messages

None.

#### Formal Specification

```
    Address
      ΞServer
      a! : ADDRESS
      ─────────
      a! = address
```

### Count

Purpose: the number of datagrams recorded so far.

Args: none.

Returns: a non-negative integer.

Side Effects: none.

Usage:

```
    print $server->count(), " messages\n";
```

#### Example

```
    $server->process("<13>hello", $peer);
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

#### Formal Specification

```
    Count
      ΞServer
      n! : ℕ
      ─────────
      n! = count
```

### Reopen\_Log

Purpose: (re)open the CSV log.  Called at start-up and on SIGHUP, so that
after logrotate renames the file a fresh one is created.

Args: none.

Returns: `$self`, for chaining.

Side Effects: closes any open log; creates the file with mode 0600 if absent
and writes the header row if it is empty; forces mode 0600 on an existing
file.

Usage:

```
    $server->reopen_log();
```

#### Example

```
    # logrotate postrotate script:  kill -HUP $(cat /run/syslogd.pid)
    # ...which, inside run(), calls:
    $server->reopen_log();
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
    +------------------------------+------------------------------+--------------------------------+
    | Message                      | Meaning                      | Resolution                     |
    +------------------------------+------------------------------+--------------------------------+
    | Could not open log file F:   | open(2) failed; ERROR is $!  | Create the directory or fix    |
    |   ERROR                      |   in the current locale      |   its permissions              |
    | Refusing to log to F: it     | F is a symlink, a hard link, | Remove F and let the server    |
    |   must be a regular file ... |   or owned by someone else   |   create it                    |
    +------------------------------+------------------------------+--------------------------------+
```

#### Formal Specification

```
    ReopenLog
      ΔServer
      ─────────
      logging'
      owner(file) = euid ∧ links(file) = 1 ∧ mode(file) = 0600
      size(file) = 0 ⇒ contents'(file) = ⟨HEADER⟩
```

### Parse\_Message

Purpose: split a raw datagram into facility, severity and message.  Pure: it
touches no state, so it can be used and tested on its own.

Args: the raw datagram (a byte string).

Returns: `undef` for datagrams too short to be a message, otherwise a
hashref:

```perl
    { facility => 0..23, severity => 0..7, message => '...', valid => 0|1 }
```

`valid` is false when the PRI was missing or out of range; the record is
then user.notice and `message` is the whole datagram.

Side Effects: none.

Usage:

```perl
    my $rec = App::Syslogd->parse_message('<34>su: root failed');
```

#### Example

```perl
    my $rec = App::Syslogd->parse_message("<34>su: 'su root' failed\n");
    # { facility => 4, severity => 2, message => "su: 'su root' failed", valid => 1 }

    $rec = App::Syslogd->parse_message("no pri\there");
    # { facility => 1, severity => 5, message => 'no pri\x09here', valid => 0 }
```

#### Api Specification

##### Input

```perl
    {
            datagram => { type => 'string', position => 0 },
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

None; malformed input is recorded, never rejected.

#### Formal Specification

```
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
```

#### Pseudocode

```
    strip trailing CR, LF and NUL
    if fewer than 2 characters remain: return undef
    if text is "<" PRI ">" BODY with PRI a canonical integer <= 191:
            valid = true
    else:
            PRI = 13, BODY = whole text, valid = false
    return { PRI div 8, PRI mod 8, escape_controls(BODY), valid }
```

### Process

Purpose: record one received datagram.

Args: the raw datagram, and the sender's packed `sockaddr` as returned by
`recv`.

Returns: `$self`, for chaining.

Side Effects: may perform a reverse DNS lookup (cached); appends one row to
the log; increments `count`.  A write failure is reported with `carp` and
the datagram is dropped, so a full disk does not kill the daemon.

Usage:

```perl
    my $peer = $socket->recv(my $data, 65535);
    $server->process($data, $peer);
```

#### Example

```perl
    use Socket qw(pack_sockaddr_in inet_aton);
    my $peer = pack_sockaddr_in(514, inet_aton('192.0.2.1'));
    $server->reopen_log()->process('<13>hello', $peer);
```

#### Api Specification

##### Input

```perl
    {
            datagram => { type => 'string', position => 0 },
            peer => { type => 'string', min => 1, position => 1 },
    }
```

##### Output

```perl
    { type => 'object', isa => 'App::Syslogd' }
```

#### Messages

```
    +-----------------------------+----------------------------+----------------------------+
    | Message                     | Meaning                    | Resolution                 |
    +-----------------------------+----------------------------+----------------------------+
    | process() was called before | No log file is open        | Call reopen_log() first    |
    |   reopen_log() succeeded    |   (croak)                  |                            |
    | Could not write to log file | write(2) failed, e.g. disk | Free space; the datagram   |
    |   F: ERROR                  |   full (carp)              |   was lost                 |
    +-----------------------------+----------------------------+----------------------------+
```

#### Formal Specification

```
    Process
      ΔServer
      d? : seq BYTE ; peer? : SOCKADDR
      ─────────
      logging
      ParseMessage(d?) = ⊥ ⇒ count' = count ∧ contents' = contents
      ParseMessage(d?) = r ≠ ⊥ ⇒
        count' = count + 1 ∧
        contents'(file) = contents(file) ⁀ ⟨csv(host(peer?), r)⟩
```

### Run

Purpose: the receive loop.

Args: none.

Returns: `$self`, after SIGTERM, SIGINT or `stop()`.

Side Effects: calls `open_socket()` and `reopen_log()` if they have not been
called; installs SIGHUP, SIGTERM and SIGINT handlers for its duration only
(the caller's handlers are restored on return); closes the socket and the
log on return.

Usage:

```
    $server->run();
```

#### Example

```perl
    my $server = App::Syslogd->new(port => 5514, file => '/var/log/remote.csv');
    $server->run();
    print $server->i18n('shutdown', { count => $server->count() }), "\n";
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
    +-------------------------------+----------------------------+-------------------------+
    | Message                       | Meaning                    | Resolution              |
    +-------------------------------+----------------------------+-------------------------+
    | Error receiving a datagram:   | recv(2) failed for a       | Usually transient;      |
    |   ERROR                       |   reason other than EINTR  |   logged and retried    |
    |                               |   (carp)                   |                         |
    | (any open_socket() or reopen_log() | Start-up or SIGHUP reopen  | See those methods       |
    |   message)                    |   failed (croak)           |                         |
    +-------------------------------+----------------------------+-------------------------+
```

#### Formal Specification

```
    Run ≙ (OpenSocket ⨾ ReopenLog) ⨾ Loop
    Loop ≙ μ L • (¬running ∧ Close) □
                 (running ∧ hup ∧ ReopenLog ⨾ L) □
                 (running ∧ ¬hup ∧ Receive ⨾ Process ⨾ L)
```

#### Pseudocode

```
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
```

### Stop

Purpose: ask `run()` to return after the current datagram.

Args: none.

Returns: `$self`.

Side Effects: clears the running flag.

Usage:

```
    $server->stop();
```

#### Example

```perl
    local $SIG{ALRM} = sub { $server->stop() };
    alarm 60;       # run for a minute
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

#### Formal Specification

```
    Stop
      ΔServer
      ─────────
      ¬running'
```

### i18n

Purpose: render a user-facing message in the server's language.

Args: a message key and an optional hashref of named arguments.  May be
called as a class method (e.g. for a usage message before `new()`), in which
case the language comes from the environment.

Returns: the rendered string.

Side Effects: none.

Usage:

```perl
    croak $self->i18n('open_failed', { file => $file, error => "$!" });
```

#### Example

```perl
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

```
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
```

#### Formal Specification

```
    I18n
      key? : KEY ; args? : NAME ⇸ VALUE ; out! : STRING
      ─────────
      out! = Text(handle(language), key?, args?)
```

## Limitations

- **The default log file is in /tmp.**  It is kept for compatibility with
earlier versions.  The server refuses symlinks, hard links and files owned
by anyone else, which closes the classic /tmp attacks, but an attacker can
still delete the file between rotations.  Use `--file` to put it somewhere
private such as `/var/log`.
- **The web viewer cannot read the log.**  The file is mode 0600 (owned
by whoever runs the daemon, usually root), but the VWF pages under `www/`
run as the web server user.  You must choose between privacy and the
viewer, for example with a shared group and a change to `$LOG_MODE`.
- **No privilege drop.**  Port 514 needs root (or CAP\_NET\_BIND\_SERVICE)
and the server keeps root for its whole life.  Prefer a high port with a
firewall redirect, or systemd socket activation passing the socket to
`new(socket => ...)`.
- **No receive timestamp.**  Rows hold only what the sender put in the
message.  Adding a column would break the header of existing files and
VWF::Data::syslog\_log, so it needs a migration and has not been done.
- **Reverse DNS is synchronous.**  The cache limits the damage, but the
first packet from a host with a slow resolver blocks the loop, and UDP
datagrams that arrive meanwhile can be dropped by the kernel.  Use
`--no-resolve` on busy servers.
- **UDP only.**  No TCP (RFC 6587) or TLS (RFC 5425) transport, so there
is no delivery guarantee and no authentication: anyone who can reach the
port can write to the log.
- **Messages are not parsed beyond PRI.**  RFC 3164 timestamps and
host names, and RFC 5424 structured data, stay in the `msg` column.
- **CSV formula injection.**  A message starting with `=`, `+`, `-`
or `@` may be run as a formula if the file is opened in a spreadsheet.
The data is stored unchanged on purpose; beware when opening it.
- **Backslashes are not escaped.**  A literal `\x0A` in a message
cannot be told apart from an escaped newline.
- **Not Object::Configure.**  `%DEFAULTS` is a flat hash of the kind
Object::Configure uses, but `configure()` is not called: it brings in a
global Log::Abstraction logger, which may log through syslog, and a
syslog server logging to itself can loop.

## Author

Nigel Horne, `<njh at nigelhorne.com>`

## License and Copyright

Copyright 2026 Nigel Horne.

This program is released under the GNU General Public License, version 2
(see the `LICENSE` file).  If you use it, please let me know.
