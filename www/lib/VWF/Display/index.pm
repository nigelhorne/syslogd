package VWF::Display::index;

use strict;
use warnings;

# Display the index page

use Carp qw(croak);
use VWF::Display;

our @ISA = ('VWF::Display');

sub html {
	my $self = shift;
	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $info = $self->{_info};
	croak('Missing _info in object') unless $info;

	# Reject requests with parameters other than these.  params() returns
	# undef both when there are none and when one is not allowed.
	my $allow = {
		'person' => undef,
		'action' => 'login',
		'name' => undef,
		'page' => 'index',
		'password' => undef,
		'lang' => qr/^[A-Z]{2}$/i,
		'lint_content' => qr/^\d$/,
	};

	if(!defined($info->params({ allow => $allow }))) {
		# No parameters to process: display the main index page
		return $self->SUPER::html();
	}

	# Database handle, passed in by page.fcgi
	my $syslog_log = $args{'syslog_log'};
	croak("Missing 'syslog_log' handle") unless($syslog_log);

	return $self->SUPER::html(updated => $syslog_log->updated());
}

1;
