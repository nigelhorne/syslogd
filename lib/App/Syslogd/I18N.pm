package App::Syslogd::I18N;

# Message catalogue for App::Syslogd.
#
# This is a thin layer over Locale::Maketext (core Perl) rather than a
# home-grown catalogue.  Maketext already gives us language negotiation,
# [quant,...] pluralisation and [sprintf,...] formatting; all we add is
# named arguments (so callers never depend on positional order) and a
# [gender,...] bracket method.

use strict;
use warnings;
use autodie qw(:all);

use parent 'Locale::Maketext';

use Readonly;

our $VERSION = '0.02';

# Language used when nothing in the environment matches a lexicon we ship
Readonly my $FALLBACK_LANGUAGE => 'en';

# The order in which each message's named arguments become [_1], [_2], ...
# Translators of every language see the same positional slots, so this
# table is the single source of truth for every message's arguments.
Readonly my %ARGUMENT_ORDER => (
	usage => [qw(program)],
	listening => [qw(address port)],
	shutdown => [qw(count)],
	socket_failed => [qw(address port error)],
	open_failed => [qw(file error)],
	unsafe_file => [qw(file)],
	write_failed => [qw(file error)],
	recv_failed => [qw(error)],
	not_listening => [],
	no_log_open => [],
);

=encoding utf8

=head1 NAME

App::Syslogd::I18N - Localised messages for App::Syslogd

=head1 VERSION

Version 0.02

=head1 SYNOPSIS

	use App::Syslogd::I18N;

	my $lh = App::Syslogd::I18N->handle('en');
	print $lh->text('listening', { address => '0.0.0.0', port => 514 }), "\n";

=head1 DESCRIPTION

Each language lives in its own C<App::Syslogd::I18N::xx> package with a
C<%Lexicon> hash, in the usual L<Locale::Maketext> way.  Lexicon entries
use bracket notation, so a translation can use C<[quant,_1,file,files]>,
C<[sprintf,%05d,_1]> or C<[gender,_1,his,her,their]>.

=head1 METHODS

=head2 handle

Purpose: return a language handle, falling back to English.

Args: an optional language tag (e.g. C<de>, C<en-gb>); with none, the
language is detected from the environment (C<LANGUAGE>, C<LC_ALL>,
C<LC_MESSAGES>, C<LANG>).

Returns: a C<App::Syslogd::I18N> subclass object.  Never C<undef>.

Side Effects: none.

Usage:

	my $lh = App::Syslogd::I18N->handle();

=head3 EXAMPLE

	my $lh = App::Syslogd::I18N->handle('fr');	# no French yet...
	print ref($lh), "\n";				# ...App::Syslogd::I18N::en

=head3 API SPECIFICATION

=head4 INPUT

	{
		language => { type => 'string', optional => 1, position => 0 },
	}

=head4 OUTPUT

	{ type => 'object', isa => 'App::Syslogd::I18N' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Handle
	  lang? : LANGTAG
	  h! : HANDLE
	  ─────────
	  (lang? ∈ dom lexicons ⇒ language(h!) = lang?) ∧
	  (lang? ∉ dom lexicons ⇒ language(h!) = en)

=cut

sub handle
{
	my ($class, $language) = @_;

	# Locale::Maketext returns undef when no lexicon matches, which is
	# never useful to a caller that just wants a message printed
	my @tags = defined($language) ? ($language) : ();

	return $class->get_handle(@tags) || $class->get_handle($FALLBACK_LANGUAGE);
}

=head2 text

Purpose: render one message.

Args: a message key and an optional hashref of named arguments.

Returns: the rendered string.  An unknown key renders as the key followed by
its arguments rather than dying, because the most likely caller is an error
path and losing the original error would be worse than an untranslated one.

Side Effects: none.

Usage:

	my $msg = $lh->text('open_failed', { file => '/x', error => "$!" });

=head3 EXAMPLE

	my $lh = App::Syslogd::I18N->handle('en');
	print $lh->text('shutdown', { count => 1 }), "\n";	# "... 1 message"
	print $lh->text('shutdown', { count => 2 }), "\n";	# "... 2 messages"

=head3 API SPECIFICATION

=head4 INPUT

	{
		key => { type => 'string', min => 1, position => 0 },
		args => { type => 'hashref', optional => 1, position => 1 },
	}

=head4 OUTPUT

	{ type => 'string' }

=head3 MESSAGES

None of its own; see L<App::Syslogd/MESSAGES> for the catalogue.

=head3 FORMAL SPECIFICATION

	Text
	  key? : KEY
	  args? : NAME ⇸ VALUE
	  out! : STRING
	  ─────────
	  key? ∈ dom ARGUMENT_ORDER ⇒
	    out! = render(lexicon(key?), ⟨args?(n) | n ∈ ARGUMENT_ORDER(key?)⟩)
	  key? ∉ dom ARGUMENT_ORDER ⇒ key? ⊑ out!

=cut

sub text
{
	my ($self, $key, $args) = @_;

	$args ||= {};

	# Unknown keys still produce something readable; see POD above
	my $order = $ARGUMENT_ORDER{$key};
	if(!defined($order)) {
		my $detail = join(', ', map { "$_=" . ($args->{$_} // '') } sort keys %{$args});
		return length($detail) ? "$key ($detail)" : $key;
	}

	# Missing arguments become empty strings so a sloppy caller gets a
	# slightly odd message instead of "Use of uninitialized value" noise
	return $self->maketext($key, map { $args->{$_} // '' } @{$order});
}

=head2 gender

Bracket-notation method: C<[gender,_1,male form,female form,neutral form]>.

Purpose: choose a word by grammatical gender.  Anything other than C<male> or
C<female> (including C<undef>) selects the neutral form.

Returns: the chosen string.

=head3 EXAMPLE

	# In a lexicon: 'owner' => '[_1] changed [gender,_2,his,her,their] password'

=head3 API SPECIFICATION

=head4 INPUT

	{
		gender => { type => 'string', optional => 1, position => 0 },
		male => { type => 'string', position => 1 },
		female => { type => 'string', position => 2 },
		neutral => { type => 'string', position => 3 },
	}

=head4 OUTPUT

	{ type => 'string' }

=head3 MESSAGES

None.

=head3 FORMAL SPECIFICATION

	Gender
	  g? : STRING ; m?, f?, n?, out! : STRING
	  ─────────
	  (g? = male ⇒ out! = m?) ∧ (g? = female ⇒ out! = f?) ∧
	  (g? ∉ {male, female} ⇒ out! = n?)

=cut

sub gender
{
	my ($self, $gender, $male, $female, $neutral) = @_;

	# A single lookup table keeps this to one return statement
	my %form = (male => $male, female => $female);

	return defined($gender) && exists($form{lc $gender}) ? $form{lc $gender} : $neutral;
}

=head1 LIMITATIONS

Only English ships today.  Messages that embed C<$!> are only as localised
as Perl makes C<$!>: outside C<use locale> Perl reports OS errors in the
C locale, whatever C<LC_ALL> says.

=head1 AUTHOR

Nigel Horne, C<< <njh at nigelhorne.com> >>

=head1 LICENSE AND COPYRIGHT

Copyright 2026 Nigel Horne.

This program is released under the GNU General Public License, version 2
(see the F<LICENSE> file).  If you use it, please let me know.

=cut

1;
