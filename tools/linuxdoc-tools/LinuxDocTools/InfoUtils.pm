# InfoUtils.pm
#
#  Some utils for the linuxdoc info backend.
#
#   * Create menus
#   * Normalize node names and associated text
#   * Point references to the associated node as needed
#
# Copyright (C) 2009 Agustín Martín Domingo, agmartin at debian org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
# --------------------------------------------------------------------


package LinuxDocTools::InfoUtils;

use base qw(Exporter);

# List all exported symbols here.
our @EXPORT_OK = qw(info_process_texi);

# Import :all to get everything.
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

=head1 NAME

  InfoUtils - Some utils for the linuxdoc info backend.

=head1 SYNOPSIS

use InfoUtils q{:all};

info_process_texi($infile, $outfile, $infoname)

=head1 DESCRIPTION

This module contains some utils to process the raw texinfo file
creating menus, normalizing node names and associated text and
pointing references to the associated node as needed.

=head1 FUNCTIONS

=over 4

=cut

# -------------------------------------------------------------------------
sub info_normalize_node_text {
# -------------------------------------------------------------------------
# Filter characters not allowed in section names
# -------------------------------------------------------------------------
  my $text = shift;

  $text =~ s/\s+/ /g;
  $text =~ s/\@[A-Za-z][A-Za-z0-9]*//g;
  $text =~ s/(\{|\})//g;
  $text =~ s/\,//g;
#  $text =~ s/\.+$//g;
  $text =~ s/\./-/g;
  $text =~ s/\s+$//g;

  return $text;
}

# -------------------------------------------------------------------------
sub info_normalize_node_name {
# -------------------------------------------------------------------------
# Filter characters not allowed in node names. Previous filtering of
# characters not allowed in section names is supposed.
# -------------------------------------------------------------------------
  my $text        = shift;
#  my $tmpnodedata = shift;

  $text =~ s/\://g;
  $text =~ s/\;//g;

#  die "Error: Reference \"$text\" already used"
#    if defined $tmpnodedata->{$text};

  return $text;
}

# -------------------------------------------------------------------------
sub info_parse_raw_file {
# -------------------------------------------------------------------------
# Parse raw texinfo file. It does not yet contain section names, menus,
# correct references or title.
# -------------------------------------------------------------------------
  my $inputfile = shift;
  my $INPUT;

  my @inputtext = (); # Copy of input file with some preprocessing
  my %nodedata  =     # A hash of hashes with all node info
    ( 'Top' =>
      { 'text'     => "Top",
	'depth'    => 0,
	'up'       => "",
	'next'     => '',
	'previous' => "",
	'sort'     => 0,
	'debug'    => "",
	'menu'     => []}
      );

  my %levellast = (0 => "Top");
  my %labels    = ();
  my %docdata   =   # Some misc data for the document
    ( 'title'    => "",
      'author'   => "",
      'subtitle' => ""
      );

  my $depth     = my $lastdepth = 0;
  my $lastnode  = "";
  my $sort      = 0;

  my $inauthor;
  my $authorline;

  open ($INPUT, "< $inputfile")
    or die "info-postASP: Could not open $inputfile for read. Aborting ...\n";

  while (<$INPUT>){
    chomp;
    if ( s/^\@SUB\s+// ){
      my $updepth   = $depth;
      my $uppernode = $levellast{$updepth};
      $depth++;
      $sort++;

      my @levelmenu = ();

      if ( defined $nodedata{$uppernode}->{'menu'} ){
	@levelmenu = @{ $nodedata{$uppernode}->{'menu'} };
      }

      my $nodetext = info_normalize_node_text($_);
      my $nodename = info_normalize_node_name($nodetext,\%nodedata);

      # Make first appearing node the next node for top node
      $nodedata{'Top'}->{'next'} = $nodename if ( $lastdepth eq 0);

      # Fill info for current node (and 'next' for last one in level)
      $nodedata{$nodename}->{'orig'}          = $_;
      $nodedata{$nodename}->{'text'}          = $nodetext;
      $nodedata{$nodename}->{'depth'}         = $depth;
      $nodedata{$nodename}->{'previous'}      =
	defined $levellast{$depth} ? $levellast{$depth} : "";
      $nodedata{$levellast{$depth}}->{'next'} = $nodename
	if defined $levellast{$depth};
      $nodedata{$nodename}->{'up'}            = $uppernode;
      $nodedata{$nodename}->{'sort'}          = $sort;
      $nodedata{$nodename}->{'debug'}         =
	"updepth: $updepth, lastdepth:  $lastdepth, up: $uppernode";

      # Keep this defined in case tbere is no next node in the same level.
      $nodedata{$nodename}->{'next'}          = "";

      push @inputtext, "\@SUB $nodename";   # Rewrite @SUB with the new name
      push @levelmenu, $nodename;           # Add $nodename to the level menu list

      # Prepare things for next @SUB entry found
      $levellast{$depth}   = $lastnode        = $nodename;
      $lastdepth                              = $depth;
      $nodedata{$uppernode}->{'menu'}         = \@levelmenu;

    } elsif ( s/^\@ENDSUB// ){
      $depth--;
      push @inputtext, $_;
    } elsif (s/^\@LABEL\s+//){
      # Keep record of node labels vs nodenames. Will use the last.
      $labels{$_} = $lastnode;
    } elsif (s/^\@title\s+//){
      $docdata{'title'} = $_;
    } elsif (/^\@ldt_endauthor/){
      $inauthor = '';
      my @authors;
      if ( @$docdata{'authors'} ){
	@authors = @$docdata{'authors'};
      }
      push @authors, $authorline;
      $docdata{'authors'} = \@authors;
      $authorline = "";
    } elsif ( s/^\@author\s+// ){
      $inauthor = 1;
      $authorline = $_;
    } elsif ( $inauthor ){
      next if m/^\s*$/;
      s/^\s+//;
      $authorline .= " $_ ";
    } elsif (s/^\@subtitle\s+//){
      $docdata{'subtitle'} = $_;
    } elsif (s/^\@ldt_translator\s+//){
      $docdata{'translator'} = $_;
    } elsif (s/^\@ldt_tdate\s+//){
      $docdata{'tdate'} = $_;
    } else {
      push @inputtext, $_;
    }
  }
  close $INPUT;

  $docdata{'nodedata'}  = \%nodedata;
  $docdata{'labels'}    = \%labels;
  $docdata{'inputtext'} = \@inputtext;

  return \%docdata;
}

# -------------------------------------------------------------------------
sub info_write_preprocessed_file {
# -------------------------------------------------------------------------
# Write processed texinfo file. Add section names, menus, correct
# references and title.
# -------------------------------------------------------------------------
  my $docdata  = shift;
  my $infoname = shift;
  my $texiout  = shift;

  die "InfoUtils.pm: No info file name $infoname.\n" unless $infoname;
  die "InfoUtils.pm: No output texi file $texiout\n" unless $texiout;

  my $nodedata  = $docdata->{'nodedata'};
  my $labels    = $docdata->{'labels'};
  my $inputtext = $docdata->{'inputtext'};

  my $OUTFILE;

  # info_check_parsed_data($nodedata);

  my %sections = ( 1 => "\@chapter",
		   2 => "\@section",
		   3 => "\@subsection",
		   4 => "\@subsubsection");

  my $lastdepth = 0;
  my $lastnode  = "Top";
  my $texinfo   = "\@c %** START OF HEADER
\@setfilename $infoname
\@c %** END OF HEADER\n";

  foreach ( @$inputtext ) {
    if ( s/^\@SUB\s+// ){
      my $key      = $_;
      my $depth    = $nodedata->{$key}->{'depth'};
      my $name     = $nodedata->{$key}->{'text'};

      if ( $depth le 4 ){
	my $next     = $nodedata->{$key}->{'next'};
	my $previous = $nodedata->{$key}->{'previous'};
	my $up       = $nodedata->{$key}->{'up'};
	# my $txt      = "\@comment nodename, next, previous, up\n";
	my $txt      = "";

	# $txt .= "\@node $key, $previous, $next, $up\n";
	$txt .= "\@node $key\n";
	$txt .= "$sections{$depth} $name\n";

	if ( $depth gt $lastdepth && defined $nodedata->{$lastnode}->{'menu'}){
	  $txt = "\n\@menu\n\* "
	    . join("::\n\* ",@{$nodedata->{$lastnode}->{'menu'}})
	    . "::\n\@end menu\n"
	    . "\n$txt";
	}

	$texinfo .= $txt;
	$lastdepth = $depth;
	$lastnode  = $key;
      } elsif ( $depth eq 5 ){
	$texinfo .= "\@subsubheading $nodedata->{$key}->{'text'}\n";
      } else {
	die "info-postASP: Entry \"$key\" has wrong depth $depth\n";
      }
    } elsif (s/^\@REF\s+//){
      if ( defined $labels->{$_} ){
	# If this reference is to a node, use its nodename
	$texinfo .= "\@ref{" . $labels->{$_}  . "}\n";
      } else {
	$texinfo .= "\@ref{$_}\n";
      }
    } elsif (s/^\@TOP//){
      $texinfo .= "\@node top\n"
	. "\@top " . $docdata->{'title'} . "\n"
	. "\@example\n";

      $texinfo .= join(' and ',@{$docdata->{'authors'}}) . "\n"
	if ( @{$docdata->{'authors'}} );

      $texinfo .= $docdata->{'subtitle'} . "\n"
	if ( defined $docdata->{'subtitle'} );

      $texinfo .= $docdata->{'translator'} . "\n"
	if ( defined $docdata->{'translator'} );

      $texinfo .= $docdata->{'tdate'} . "\n"
	if ( defined $docdata->{'tdate'} );

      $texinfo .= "\@end example\n";
    } else {
      $texinfo .= "$_\n";
    }
  }

  open ($OUTFILE, "> $texiout")
    or die "Could not open \"$texiout\" for write. Aborting ...\n";
  print $OUTFILE $texinfo;
  close $OUTFILE;
}

# -------------------------------------------------------------------------
sub info_check_parsed_data {
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
  my $tmpnodedata = shift;
  my @sections = sort {
    $tmpnodedata->{$a}->{'sort'} <=> $tmpnodedata->{$b}->{'sort'}
  } keys %$tmpnodedata;

  foreach ( @sections ){
    my $ref = $tmpnodedata->{$_};
    print STDERR "Node: $_\n";
    print STDERR "  orig: $ref->{'orig'}\n";
    print STDERR "  text: $ref->{'text'}\n";
    print STDERR "  debug: $ref->{'debug'}\n";
    print STDERR "  up: $ref->{'up'}\n";
    print STDERR "  depth: $ref->{'depth'}\n";
    print STDERR "  previous: $ref->{'previous'}\n";
    print STDERR "  next: $ref->{'next'}\n";
    print STDERR "  sort: $ref->{'sort'}\n";
    print STDERR "  menu:\n   * " . join("\n   * ",@{$ref->{'menu'}}) . "\n" if defined $ref->{'menu'};
  }
}

# -------------------------------------------------------------------------
sub info_process_texi {
# -------------------------------------------------------------------------
# info_process_texi($infile, $outfile, $infoname)
#
# Call the other functions.
# -------------------------------------------------------------------------
  my $infile   = shift;
  my $outfile  = shift;
  my $infoname = shift;

  info_write_preprocessed_file(info_parse_raw_file($infile),$infoname,$outfile);
}
