package App::Syslogd::I18N::en;

# English lexicon.  Square brackets are Maketext syntax; a literal bracket
# is written "~[" or "~]".  Argument order is defined by %ARGUMENT_ORDER in
# App::Syslogd::I18N, not here.

use strict;
use warnings;
use autodie qw(:all);

use parent -norequire, 'App::Syslogd::I18N';

our $VERSION = '0.02';

our %Lexicon = (
	usage => 'Usage: [_1] ~[--port <port_number>~] ~[--address <address>~] ~[--file <CSV file>~] ~[--no-resolve~] ~[--language <tag>~]',
	listening => 'Syslog server listening on [_1] UDP port [_2]',
	shutdown => 'Syslog server shutting down after recording [quant,_1,message,messages]',
	socket_failed => 'Could not create a UDP socket on [_1] port [_2]: [_3]',
	open_failed => 'Could not open log file [_1]: [_2]',
	unsafe_file => 'Refusing to log to [_1]: it must be a regular file, owned by this user, with exactly one link',
	write_failed => 'Could not write to log file [_1]: [_2]',
	recv_failed => 'Error receiving a datagram: [_1]',
	not_listening => 'run() was called before open_socket() succeeded',
	no_log_open => 'process() was called before reopen_log() succeeded',
);

1;
