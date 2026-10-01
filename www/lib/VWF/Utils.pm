package VWF::Utils;

# VWF is licensed under GPL2.0 for personal use only
# njh@bandsman.co.uk

=head1 NAME

VWF::Utils - Random subroutines for VWF

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT = qw(create_disc_cache create_memory_cache distance);

use CHI;
use Data::Dumper;
use DBI;
use Error;
use Log::Any::Adapter;
use Math::Trig qw(great_circle_distance deg2rad pi);
use Params::Get;
use Readonly;

# Redis reconnection: retry for 60 seconds, every second (in microseconds)
Readonly my %REDIS_OPTIONS => (reconnect => 60, every => 1_000_000);

# 60 nautical miles per degree, 1.1515 statute miles per nautical mile, as
# a radius: the figures the original geodatasource.com code used
Readonly my $EARTH_RADIUS_MILES => 60 * 1.1515 * 180 / pi;

# Multipliers from statute miles to the other units distance() accepts
Readonly my %UNIT_FACTOR => (K => 1.609344, N => 0.8684);

BEGIN {
	Log::Any::Adapter->set('Log4perl');
}

=head1 SUBROUTINES/METHODS

=head2 create_disc_cache

Initialise a disc-based cache using the CHI module.
Supports multiple cache drivers, including BerkeleyDB, DBI, and Redis.

=cut

sub create_disc_cache {
	my $args = Params::Get::get_params(undef, @_);

	my $config = $args->{'config'};
	throw Error::Simple('config is not optional') unless($config);

	my $logger = $args->{'logger'};
	my $driver = $config->{disc_cache}->{driver};
	unless(defined($driver)) {
		my $root_dir = $ENV{'root_dir'} || $args->{'root_dir'} || $config->{disc_cache}->{root_dir} || $config->{'root_dir'};
		throw Error::Simple('root_dir is not optional') unless($root_dir);

		if($logger) {
			$logger->debug(Data::Dumper->new([$config])->Dump());
			$logger->info('disc_cache not defined in ', $config->{'config_path'}, ' falling back to BerkeleyDB');
		}
		return CHI->new(driver => 'BerkeleyDB', root_dir => $root_dir, namespace => $args->{'namespace'});
	}
	if($logger) {
		$logger->debug('disc cache via ', $config->{disc_cache}->{driver}, ', namespace: ', $args->{'namespace'});
	}

	my %chi_args = (
		on_get_error => 'warn',
		on_set_error => 'die',
		driver => $driver,
		namespace => $args->{'namespace'}
	);

	# Don't do this because it takes a lot of complex configuration
	# if($logger) {
		# $chi_args{'on_set_error'} = 'log';
		# $chi_args{'on_get_error'} = 'log';
	# }

	if($config->{disc_cache}->{server}) {
		_add_servers(\%chi_args, $config, 'disc_cache', $logger);
	} elsif($driver eq 'DBI') {
		# Use the cache connection details in the configuration file
		$chi_args{'dbh'} = DBI->connect($config->{disc_cache}->{connect});
		if(!defined($chi_args{'dbh'})) {
			if($logger) {
				$logger->error($DBI::errstr);
			}
			throw Error::Simple($DBI::errstr);
		}
		$chi_args{'create_table'} = 1;
	} elsif($driver eq 'Redis') {
		$chi_args{'redis_options'} = { %REDIS_OPTIONS };
	} elsif($driver ne 'Null') {
		$chi_args{'root_dir'} = $ENV{'root_dir'} || $args->{'root_dir'} || $config->{disc_cache}->{root_dir};
		throw Error::Simple('root_dir is not optional') unless($chi_args{'root_dir'});
		if($logger) {
			$logger->debug("root_dir: $chi_args{root_dir}");
		}
	}
	return CHI->new(%chi_args);
}

=head2 create_memory_cache

Initialise a memory-based cache using the CHI module.
Supports multiple cache drivers, including SharedMem, Memory, and Redis.

=cut

sub create_memory_cache {
	my $args = Params::Get::get_params(undef, @_);

	my $config = $args->{'config'};
	throw Error::Simple('config is not optional') unless($config);

	my $logger = $args->{'logger'};
	my $driver = $config->{'memory_cache'}->{driver};
	unless(defined($driver)) {
		if($logger) {
			$logger->debug(Data::Dumper->new([$config])->Dump());
			$logger->info('memory_cache not defined in ', $config->{'config_path'}, ' falling back to memory');
		}
		# return CHI->new(driver => 'Memcached', servers => [ '127.0.0.1:11211' ], namespace => $args->{'namespace'});
		# return CHI->new(driver => 'File', root_dir => '/tmp/cache', namespace => $args->{'namespace'});
		# return CHI->new(driver => 'SharedMem', max_size => 1024, shm_size => 16 * 1024, shm_key => 98766789, namespace => $args->{'namespace'});
		return CHI->new(driver => 'Memory', datastore => {});
	}
	if($logger) {
		$logger->debug('memory cache via ', $config->{memory_cache}->{driver}, ', namespace: ', $args->{'namespace'});
	}

	my %chi_args = (
		on_get_error => 'warn',
		on_set_error => 'die',
		driver => $driver,
		namespace => $args->{'namespace'}
	);

	if($logger) {
		$chi_args{'on_set_error'} = 'log';
		$chi_args{'on_get_error'} = 'log';
	}

	if($config->{memory_cache}->{server}) {
		_add_servers(\%chi_args, $config, 'memory_cache', $logger);
	} elsif($driver eq 'SharedMem') {
		$chi_args{'shm_key'} = $args->{'shm_key'} || $config->{memory_cache}->{shm_key};
		if(my $shm_size = ($args->{'shm_size'} || $config->{'memory_cache'}->{'shm_size'})) {
			$chi_args{'shm_size'} = $shm_size;
		}
		if(my $max_size = ($args->{'max_size'} || $config->{'memory_cache'}->{'max_size'})) {
			$chi_args{'max_size'} = $max_size;
		}
	} elsif($driver eq 'Redis') {
		# Must come before the root_dir branch below, which used to
		# catch Redis first and so made this branch unreachable
		$chi_args{'redis_options'} = { %REDIS_OPTIONS };
	} elsif(($driver ne 'Null') && ($driver ne 'Memory')) {
		$chi_args{'root_dir'} = $ENV{'root_dir'} || $args->{'root_dir'} || $config->{memory_cache}->{root_dir} || $config->{'root_dir'};
		throw Error::Simple('root_dir is not optional') unless($chi_args{'root_dir'});
		if($logger) {
			$logger->debug("root_dir: $chi_args{root_dir}");
		}
	}
	return CHI->new(%chi_args);
}

=head2 distance

Calculate the distance between two geographical points using latitude and longitude.
Supports distance in kilometres (K), nautical miles (N), or miles (anything else).

Uses L<Math::Trig/great_circle_distance> rather than the hand-written
spherical law of cosines this used to carry.  The earth radii are chosen so
that results match the previous code.

=cut

sub distance {
	my ($lat1, $lon1, $lat2, $lon2, $unit) = @_;

	# Math::Trig wants longitude and colatitude (90 - latitude) in radians
	my $miles = great_circle_distance(
		deg2rad($lon1), pi / 2 - deg2rad($lat1),
		deg2rad($lon2), pi / 2 - deg2rad($lat2),
		$EARTH_RADIUS_MILES
	);

	return $miles * ($UNIT_FACTOR{$unit // ''} // 1);
}

# Shared by create_disc_cache and create_memory_cache, which used to carry
# two copies of this.
# Purpose:	turn "server" / "port" from a cache section into CHI arguments.
# Entry:	$chi_args hashref to fill; $config; $section is 'disc_cache' or
#		'memory_cache' and has a "server" entry.
# Exit:		$chi_args; throws Error::Simple if a single server has no port.
# Side Effects:	sets $chi_args->{servers} (and {server} for one server).
sub _add_servers {
	my ($chi_args, $config, $section, $logger) = @_;
	my $server = $config->{$section}->{server};

	my @servers;
	if($server =~ /,/) {
		# A comma-separated list already carries its own ports
		@servers = split /,/, $server;
	} else {
		my $port = $config->{$section}->{port};
		throw Error::Simple('port is not optional in ' . $config->{'config_path'}) unless($port);
		@servers = ("$server:$port");
		$chi_args->{'server'} = $servers[0];
		if($logger) {
			$logger->debug("First server: $servers[0]");
		}
	}
	$chi_args->{'servers'} = \@servers;

	return $chi_args;
}

1;
