# Dependencies of etc/syslogd and lib/App (the www/ viewer has its own,
# much larger, set: see the use lines in www/cgi-bin/page.fcgi)
requires 'perl', '5.014';
requires 'autodie';
requires 'CHI';
requires 'IO::Socket::IP';
requires 'IPC::System::Simple';	# needed by autodie qw(:all)
requires 'Locale::Maketext';
requires 'Params::Get', '0.17';
requires 'Params::Validate::Strict', '0.40';
requires 'Readonly';
requires 'Socket', '2.000';
requires 'Sub::Private', '0.05';
requires 'Sub::Protected', '0.02';
requires 'Text::CSV';

on 'test' => sub {
	requires 'Test::Most';
	requires 'Test::Needs';
	requires 'Test::Warn';
	recommends 'IP::Country::Fast';	# t/locales.t GeoIP subtests
	recommends 'CGI::ACL';
};
