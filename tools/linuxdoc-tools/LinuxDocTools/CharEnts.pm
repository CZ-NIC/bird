#
#  CharEnts.pm
#
#  $Id: CharEnts.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  SGML Character Entity utilities -- interface to Perl module
#  Text::EntityMap.
#
package LinuxDocTools::CharEnts;
use strict;

=head1 NAME

LinuxDocTools::CharEnts - Interface to Text::EntityMap

=head1 SYNOPSIS

  my $char_maps = load_char_maps ('.2ext', [ Text::EntityMap::sdata_dirs() ]);

  $value = parse_data ($value, $char_maps, $escape_sub);

=head1 DESCRIPTION

This module provides a simple interface to the entity map handling provided by
B<Text::EntityMap>.

=head1 FUNCTIONS

=over 4

=cut

use Text::EntityMap;
use Exporter;

use vars qw(@ISA @EXPORT $VERSION);
@ISA = qw(Exporter);
@EXPORT = qw(load_char_maps parse_data);
$VERSION = sprintf("%d.%02d", q$Revision: 1.1.1.1 $ =~ /(\d+)\.(\d+)/);

# `%warn_map' tracks entities that were not able to be mapped so they
# are only warned once.
my %warn_map = ();

=item parse_data ($data, $char_map, $escape_sub)

B<parse_data> takes a string of I<$data> in the output format of
B<nsgmls> (see SP's C<sgmlsout.htm> document) without the leading dash.
B<parse_data> calls I<$char_map>'s lookup method for each sdata
entity reference. If the entity reference is undefined, it is
left alone (without the (n)sgmls C<\|>). For all remaining data,
B<parse_data> calls back into I<$escape_sub> to properly escape
characters for the backend formatter. Strings returned from the
lookup method are assumed to be already escaped.

This routine is derived from David Megginson's SGMLSpm.

=cut

sub parse_data {
    my ($data, $char_map, $escape_sub) = @_;
    my ($result) = "";

    my $sdata_flag = 0;
    my $out = '';

    while ($data =~ /\\(\\|n|\||[0-7]{1,3})/) {
	$out .= $`;
	$data = $';

	if ($1 eq '|') {
	    # beginning or end of SDATA
	    if ("$out" ne '') {
		if ($sdata_flag) {
		    my ($mapping) = $char_map->lookup ($out);
		    if (defined $mapping) {
			# escape `\' in mapping for ASP
			$mapping =~ s/\\/\\\\/g;
			$result .= $mapping;
		    } else {
			if (!$warn_map{$out}) {
			    warn "parse_data: no entity map for \`$out'\n";
			    $warn_map{$out} = 1;
			}
			# output the entity reference inside of `{}'
			$result .= &$escape_sub ("{" . $out . "}");
		    }
		} else {
		    $result .= &$escape_sub ($out);
		}
		$out = '';
	    }
	    $sdata_flag = !$sdata_flag;

	} elsif ($1 eq 'n') {
	    # record end

	    # pass '\\n' through to ASP
	    $result .= &$escape_sub ($out) . '\\n';
	    $out = '';
	} elsif ($1 eq '\\') {
	    # backslash

	    $result .= &$escape_sub ($out);

	    $out = '[bsol  ]';	# bsol == entity name for backslash
	    my ($mapping) = $char_map->lookup ($out);
	    if (defined $mapping) {
		# escape `\' in mapping for ASP
		$mapping =~ s/\\/\\\\/g;
		$result .= $mapping;
	    } else {
		if (!$warn_map{$out}) {
		    warn "parse_data: no entity map for \`$out'\n";
		    $warn_map{$out} = 1;
		}
		# output the entity reference inside of `{}'
		$result .= &$escape_sub ("{" . $out . "}");
	    }
	    $out = '';
	} else {
	    # other octal character
	    $result .= &$escape_sub ($out . chr(oct($1)));
	    $out = '';
	}
    }
    $out .= $data;
    if ("$out" ne '') {
	$result .= &$escape_sub ($out);
    }

    return ($result);
}

=item load_char_maps ($format, $paths)

B<load_char_maps> takes an EntityMap format suffix and loads all of the
character entity replacement sets for that suffix into an EntityMapGroup.
It searches every directory in I<@{$path}>.

=cut

sub load_char_maps {
    my ($format, $paths) = @_;

    my (@char_maps) = ();
    my ($path, $file_name, $char_map);

    foreach $path (@{$paths}) {
	if (-d $path) {
	    opendir (SDATADIR, $path)
		|| die "load_char_map: opening directory \`$path' for reading: $!\n";
	    foreach $file_name (readdir (SDATADIR)) {
		next if ($file_name !~ /$format$/);
		eval {$char_map = Text::EntityMap->load ("$path/$file_name")}
  		    || die "load_char_map: loading \`$path/$file_name'\n$@\n";
		push (@char_maps, $char_map);
	    }
	    closedir (SDATADIR);
	}
    }

    warn "load_char_maps: no entity maps found\n"
	if ($#char_maps == -1);

    return (Text::EntityMap->group (@char_maps));
}

=back

=head1 AUTHOR

Ken MacLeod, C<E<lt>ken@bitsko.slc.ut.usE<gt>>

=cut
1;
