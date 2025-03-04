package VWF::Display::index;

use strict;
use warnings;

# Display the index page

use VWF::Display;
use String::Random;

our @ISA = ('VWF::Display');

sub html {
	my $self = shift;
	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $info = $self->{_info};
	die 'Missing _info in object' unless $info;

	# Define allowed parameters (use state to avoid redeclaring in subsequent calls)
	# state $allowed = {
	my $allow = {
		'person' => undef,
		'action' => 'login',
		'name' => undef,
		'page' => 'index',
		'password' => undef,
		'lang' => qr/^[A-Z]{2}$/i,
		'lint_content' => qr/^\d$/,
	};

	my $config = $args{'config'};
	my $logger = $args{'logger'};
	my $params = $info->params({ allow => $allow });

	if(!defined($params)) {
		# No parameters to process: display the main index page
		return $self->SUPER::html();
	}

	# Parameters to exclude from further processing
	# my @exclude_keys = qw(page lint_content lang fbclid gclid);
	# delete @params{@exclude_keys};
	delete $params->{'page'};
	delete $params->{'lint_content'};
	delete $params->{'lang'};
	delete $params->{'fbclid'};
	delete $params->{'gclid'};

	# Database handle
	my $syslog_log = $args{'syslog_log'};
	die "Missing 'syslog_log' handle" unless($syslog_log);

	return $self->SUPER::html(updated => $syslog_log->updated());
}

1;
