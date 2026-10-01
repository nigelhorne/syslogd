# Generated from Makefile.PL using makefilepl2cpanfile

requires 'perl', '5.014';

requires 'CHI';
requires 'Carp';
requires 'Fcntl';
requires 'FindBin';
requires 'Getopt::Long';
requires 'IO::Handle';
requires 'IO::Socket::IP';
requires 'IPC::System::Simple';   # needed by autodie qw(:all)
requires 'Locale::Maketext';
requires 'Params::Get', '0.17';
requires 'Params::Validate::Strict', '0.40';
requires 'Readonly';
requires 'Socket', '2.000';   # getnameinfo and NIx_NOSERV
requires 'Sub::Private', '0.05';   # first version with enforce mode
requires 'Sub::Protected', '0.02';
requires 'Text::CSV';
requires 'autodie';
requires 'parent';

on 'test' => sub {
	requires 'Errno';
	requires 'File::Temp';
	requires 'POSIX';
	requires 'Test::Most';
	requires 'Test::Needs';
	requires 'Test::Warn';
	recommends 'CGI::ACL';
	recommends 'IP::Country::Fast';
};
