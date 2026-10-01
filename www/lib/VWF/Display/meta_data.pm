package VWF::Display::meta_data;

use strict;
use warnings;

# Display the meta-data page - the internal status of the server and VWF system

use VWF::Display;
use Readonly;

our @ISA = ('VWF::Display');

# The browser types VWF::Display::_types() can report, in display order
Readonly my @BROWSER_TYPES => ('web', 'mobile', 'search', 'robot');

sub html
{
	my $self = shift;
	my %args = (ref($_[0]) eq 'HASH') ? %{$_[0]} : @_;

	my $vwf_log = $args{'vwf_log'};
	my $domain_name = $self->{'info'}->domain_name();

	# One {y, label} point per type for the chart in meta_data.tmpl
	my $datapoints = '';
	foreach my $type(@BROWSER_TYPES) {
		my @entries = $vwf_log->type({ domain_name => $domain_name, type => $type });
		$datapoints .= '{y: ' . scalar(@entries) . ", label: \"$type\"},\n";
		if($self->{'logger'}) {
			$self->{'logger'}->debug("$type = " . scalar(@entries));
		}
	}

	return $self->SUPER::html({ datapoints => $datapoints });
}

1;
