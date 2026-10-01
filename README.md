# Syslog Server

A small UDP syslog receiver written in Perl. It listens on a configurable
UDP port (default **514**), decodes the PRI field into facility and
severity, and appends one CSV row per message.

## Features
- Listens on a **user-defined UDP port and address** (IPv4 or IPv6).
- Decodes **facility** and **severity** from the PRI field (RFC 5424 limits:
  PRI 0-191). A message with no valid PRI is recorded as `user.notice`
  (PRI 13) with the whole datagram as its text, as RFC 3164 section 4.3.3 requires.
- Logs the sender's **host name** (via the system resolver, so `/etc/hosts`
  is honoured, with a cache), or its address with `--no-resolve`.
- Writes proper CSV: quotes are escaped, and control characters (including
  newlines) are written as `\xNN`, so every record is exactly one line.
- **SIGHUP** reopens the log file, for logrotate. **SIGTERM** / **SIGINT** stop it cleanly.
- The log file is created mode 0600. The server refuses to write through a
  symlink or a hard link, or to a file owned by another user.

## Layout
- `bin/syslogd`: the command-line program (it used to live at `etc/syslogd`).
- `lib/Syslogd/Server.pm`: the implementation, with full POD (`perldoc lib/Syslogd/Server.pm`).
- `t/`: tests (`prove -l t/`).
- `www/`: a VWF-based web viewer for the log.

## Requirements
Perl 5.14 or later, plus the modules in `cpanfile`:

```sh
cpanm --installdeps .
```

## Usage
```sh
bin/syslogd [--port 514] [--address 0.0.0.0] [--file /tmp/syslog.log] [--no-resolve] [--language en]
```

Port 514 needs root. Without `--file` the log goes to `/tmp/syslog.log`
for compatibility; choose somewhere private for real use.

Example logrotate stanza:

```
/var/log/remote-syslog.csv {
	weekly
	rotate 8
	postrotate
		pkill -HUP -f bin/syslogd
	endscript
}
```

See the LIMITATIONS section of `perldoc lib/Syslogd/Server.pm` before
relying on this in production.
