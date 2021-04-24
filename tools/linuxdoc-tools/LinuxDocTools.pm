#! /usr/bin/perl
#
#  LinuxDocTools.pm
#
#  LinuxDoc-Tools driver core. This contains all the basic functionality
#  we need to control all other components.
#
#  Copyright © 1996, Cees de Groot.
#  Copyright © 2000, Taketoshi Sano
#  Copyright © 2006-2018, Agustin Martin
# --------------------------------------------------------------------------------

package LinuxDocTools;

require 5.006;
use strict;

=head1 NAME

LinuxDocTools - SGML conversion utilities for LinuxDoc DTD.

=head1 SYNOPSIS

  use LinuxDocTools;
  LinuxDocTools::init;
  @files = LinuxDocTools::process_options ($0, @ARGV);
  for $curfile (@files) {
    LinuxDocTools::process_file ($curfile);
  }

=head1 DESCRIPTION

The LinuxDocTools package encapsulates all the functionality offered by
LinuxDoc-Tools. It is used, of course, by LinuxDoc-Tools;
but the encapsulation should provide for a simple interface for other users as well.

=head1 FUNCTIONS

=over 4

=cut

use File::Copy;
use File::Temp qw(tempdir);
use File::Basename qw(fileparse);
use LinuxDocTools::Lang;
use LinuxDocTools::Utils qw(usage cleanup trap_signals remove_tmpfiles create_temp);
use LinuxDocTools::Vars;

sub BEGIN
{
  #
  #  Make sure we're always looking here. Note that "use lib" adds
  #  on the front of the search path, so we first push dist, then
  #  site, so that site is searched first.
  #
  use lib "$main::DataDir/dist";
  use lib "$main::DataDir/site";
}

# -----------------------------------------------------------------------------------
sub ldt_searchfile {
# -----------------------------------------------------------------------------------
# Look for a readable file in the locations. Return first math.
# -----------------------------------------------------------------------------------
  my $files = shift;
  foreach my $file  ( @$files ){
    return $file if -r $file;
  }
}

# -----------------------------------------------------------------------------------
sub ldt_getdtd_v1 {
# -----------------------------------------------------------------------------------
# Get the dtd
# -----------------------------------------------------------------------------------
  my $file         = shift;
  my $error_header = "LinuxdocTools::ldt_getdtd_v1";
  my $dtd;

  open ( my $FILE, "< $file")
    or die "$error_header: Could not open \"$file\" for reading. Aborting ...\n";

  while ( <$FILE> ) {
    tr/A-Z/a-z/;
    # check for [<!doctype ... system] type definition
    if ( /<!doctype\s*(\w*)\s*system/ ) {
      $dtd = $1;
      last;
      # check for <!doctype ... PUBLIC ... DTD ...
    } elsif ( /<!doctype\s*\w*\s*public\s*.*\/\/dtd\s*(\w*)/mi ) {
      $dtd = $1;
      last;
      # check for <!doctype ...
      #          PUBLIC  ... DTD ...
      # (multi-line version)
    } elsif ( /<!doctype\s*(\w*)/ ) {
      $dtd = "precheck";
      next;
    } elsif ( /\s*public\s*.*\/\/dtd\s*(\w*)/ && $dtd eq "precheck" ) {
      $dtd = $1;
      last;
    }
  }
  close $FILE;

  return $dtd;
}

# -----------------------------------------------------------------------------------
sub ldt_getdtd_v2 {
# -----------------------------------------------------------------------------------
# Second way of getting dtd, fron nsgmls output.
# -----------------------------------------------------------------------------------
  my $preaspout    = shift;
  my $error_header = "LinuxdocTools::ldt_getdtd_v2";
  my $dtd2;

  open (my $TMP,"< $preaspout")
    or die "%error_header: Could not open $preaspout for reading. Aborting ...\n";
  while ( defined ($dtd2 = <$TMP>) && ! ( $dtd2 =~ /^\(/) ) { };
  close $TMP;
  $dtd2 =~ s/^\(//;
  $dtd2 =~ tr/A-Z/a-z/;
  chomp $dtd2;
  return $dtd2;
}

# -----------------------------------------------------------------------------------
sub ldt_latin1tosgml {
# -----------------------------------------------------------------------------------
# Convert latin1 chars in input filehandle to sgml entities in the returned string
# -----------------------------------------------------------------------------------
  my $FILE     = shift;
  my $sgmlout;

  while (<$FILE>){
    # Outline these commands later on - CdG
    #change latin1 characters to SGML
    #by Farzad Farid, adapted by Greg Hankins
    s/À/\&Agrave;/g;
    s/Á/\&Aacute;/g;
    s/Â/\&Acirc;/g;
    s/Ã/\&Atilde;/g;
    s/Ä/\&Auml;/g;
    s/Å/\&Aring;/g;
    s/Æ/\&AElig;/g;
    s/Ç/\&Ccedil;/g;
    s/È/\&Egrave;/g;
    s/É/\&Eacute;/g;
    s/Ê/\&Ecirc;/g;
    s/Ë/\&Euml;/g;
    s/Ì/\&Igrave;/g;
    s/Í/\&Iacute;/g;
    s/Î/\&Icirc;/g;
    s/Ï/\&Iuml;/g;
    s/Ñ/\&Ntilde;/g;
    s/Ò/\&Ograve;/g;
    s/Ó/\&Oacute;/g;
    s/Ô/\&Ocirc;/g;
    s/Õ/\&Otilde;/g;
    s/Ö/\&Ouml;/g;
    s/Ø/\&Oslash;/g;
    s/Ù/\&Ugrave;/g;
    s/Ú/\&Uacute;/g;
    s/Û/\&Ucirc;/g;
    s/Ü/\&Uuml;/g;
    s/Ý/\&Yacute;/g;
    s/Þ/\&THORN;/g;
    s/ß/\&szlig;/g;
    s/à/\&agrave;/g;
    s/á/\&aacute;/g;
    s/â/\&acirc;/g;
    s/ã/\&atilde;/g;
    s/ä/\&auml;/g;
    s/å/\&aring;/g;
    s/æ/\&aelig;/g;
    s/ç/\&ccedil;/g;
    s/è/\&egrave;/g;
    s/é/\&eacute;/g;
    s/ê/\&ecirc;/g;
    s/ë/\&euml;/g;
    s/ì/\&igrave;/g;
    s/í/\&iacute;/g;
    s/î/\&icirc;/g;
    s/ï/\&iuml;/g;
    s/µ/\&mu;/g;
    s/ð/\&eth;/g;
    s/ñ/\&ntilde;/g;
    s/ò/\&ograve;/g;
    s/ó/\&oacute;/g;
    s/ô/\&ocirc;/g;
    s/õ/\&otilde;/g;
    s/ö/\&ouml;/g;
    s/ø/\&oslash;/g;
    s/ù/\&ugrave;/g;
    s/ú/\&uacute;/g;
    s/û/\&ucirc;/g;
    s/ü/\&uuml;/g;
    s/ý/\&yacute;/g;
    s/þ/\&thorn;/g;
    s/ÿ/\&yuml;/g;
    $sgmlout .= $_;
  }
  return $sgmlout;
}

# ------------------------------------------------------------------------

=item LinuxDocTools::init

Takes care of initialization of package-global variables (which are actually
defined in L<LinuxDocTools::Vars>). The package-global variables are I<$global>,
a reference to a hash containing numerous settings, I<%Formats>, a hash
containing all the formats, and I<%FmtList>, a hash containing the currently
active formats for help texts.

Apart from this, C<LinuxDocTools::init> also finds all distributed and site-local
formatting backends and C<require>s them.

=cut

# -----------------------------------------------------------------------------------
sub init {
# -----------------------------------------------------------------------------------
  trap_signals;

  # Register the ``global'' pseudoformat. Apart from the global settings, we
  # also use $global to keep the global variable name space clean everything
  # that we need to provide to other modules is stuffed into $global.
  $global              = {};
  $global->{NAME}      = "global";
  $global->{HELP}      = "";
  $global->{OPTIONS}   = [
			  { option => "backend",
			    type => "l",
			    'values' => [ "html", "info", "latex", "lyx", "rtf", "txt", "check" ],
			    short => "B" },
			  { option => "papersize",
			    type => "l",
			    'values' => [ "a4", "letter" ],
			    short => "p" },
			  { option => "language",
			    type => "l",
			    'values' => [ @LinuxDocTools::Lang::Languages ],
			    short => "l" },
			  { option => "charset",   type => "l",
			    'values' => [ "latin", "ascii", "nippon", "euc-kr" ], short => "c" },
			  { option => "style",     type => "s", short => "S" },
			  { option => "tabsize",   type => "i", short => "t" },
			  # { option => "verbose",   type => "f", short => "v" },
			  { option => "debug",     type => "f", short => "d" },
			  { option => "define",    type => "s", short => "D" },
			  { option => "include",   type => "s", short => "i" },
			  { option => "pass",      type => "s", short => "P" }
			  ];
  $global->{backend}   = "linuxdoc";
  $global->{papersize} = "a4";
  $global->{language}  = "en";
  $global->{charset}   = "ascii";
  $global->{style}     = "";
  $global->{tabsize}   = 8;
  $global->{verbose}   = 0;
  $global->{define}    = "";
  $global->{debug}     = 0;
  $global->{include}   = "";
  $global->{pass}      = "";
  $global->{InFiles}   = [];
  $global->{fmtlist}   = "";            # List of loaded fmt files
  $Formats{$global->{NAME}} = $global;	# All formats we know.
  $FmtList{$global->{NAME}} = $global;  # List of formats for help msgs.

  $global->{sgmlpre}   = "$main::AuxBinDir/sgmlpre";
  my $error_header     = "LinuxdocTools::init";

  if ( -e "/etc/papersize" ){
    open (my $PAPERSIZE,"< /etc/papersize") ||
      die "$error_header: Count not open \"/etc/papersize\" for reading\n";
    chomp (my $paper = <$PAPERSIZE>);
    $global->{papersize} = "letter" if ( $paper eq "letter");
    close $PAPERSIZE;
  }

  # automatic language detection: disabled by default
  # {
  #    my $lang;
  #    foreach $lang (@LinuxDocTools::Lang::Languages)
  #     {
  #       if (($ENV{"LC_ALL"} =~ /^$lang/i) ||
  #           ($ENV{"LC_CTYPE"} =~ /^$lang/i) ||
  #           ($ENV{"LANG"} =~ /^$lang/i)) {
  #	    $global->{language}  = Any2ISO($lang);
  #       }
  #     }
  # }

  # --------------------------------------------------------------------------------
  $global->{preNSGMLS} = sub {
    # ------------------------------------------------------------------------------
    #  Define a fallback preNSGMLS. Used when the format is "global" (from sgmlcheck).
    # ------------------------------------------------------------------------------
    $global->{NsgmlsOpts}   .= " -s ";
    $global->{NsgmlsPrePipe} = "cat $global->{file}";
  };

  # We need to load all fmt files here, so the allowed options for all
  # format are put into $global and a complete usage message is built,
  # including options for all formats.
  my %locations = ();
  foreach my $path ("$main::DataDir/site",
		    "$main::DataDir/dist",
		    "$main::DataDir/fmt"){
    foreach my $location (<$path/fmt_*.pl>){
      my $fmt =  $location;
      $fmt    =~ s/^.*_//;
      $fmt    =~ s/\.pl$//;
      $locations{$fmt} = $location unless defined $locations{$fmt};
    }
  }

  foreach my $fmt ( keys %locations ){
    $global->{fmtlist}   .= "  Loading $locations{$fmt}\n";
    require $locations{$fmt};
  }
}

# ------------------------------------------------------------------------

=item LinuxDocTools::process_options ($0, @ARGV)

This function contains all initialization that is bound to the current
invocation of LinuxDocTools. It looks in C<$0> to deduce the backend that
should be used (ld2txt activates the I<txt> backend) and parses the
options array. It returns an array of filenames it encountered during
option processing.

As a side effect, the environment variable I<SGML_CATALOG_FILES> is
modified and, once I<$global->{format}> is known, I<SGMLDECL> is set.

=cut

# ------------------------------------------------------------------------
sub process_options {
# ------------------------------------------------------------------------
  my $progname = shift;
  my @tmpargs  = @_;
  my @args     = ();
  my $format   = '';

  # Try getting the format. We need to do this here so process_options
  # knows which is the format and which format options are allowed

  # First, see if we have an explicit backend option by looping over command line.
  # Do not shift in the while condition itself, 0 in options like '-s 0' will
  # otherwise stop looping
  while ( @tmpargs ){
    $_ = shift @tmpargs;
    if ( s/--backend=// ){
      $format = $_;
    } elsif ( $_ eq "-B" ){
      $format = shift @tmpargs;
    } else {
      push @args, $_;
    }
  }

  unless ( $format ){
    my ($tmpfmt, $dummy1, $dummy2) = fileparse($progname, "");
    if ( $tmpfmt =~ s/^sgml2// ) {       # Calling program through sgml2xx symlinks
      $format = $tmpfmt;
    } elsif ( $tmpfmt eq "sgmlcheck" ) { # Calling program through sgmlcheck symlink
      $format = "global";
    }
  }

  if ( $format ) {
    if ( $format eq "check" ){
      $format = "global";
    } elsif ( $format eq "latex" ){
      $format = "latex2e";
    }
    $FmtList{$format} = $Formats{$format} or
      usage("$format: Unknown format");
    $global->{format} = $format;
  } else {
    usage("");
  }

  # Parse all the options from @args, and return files.
  my @files    = LinuxDocTools::Utils::process_options(@args);

  # Check the number of given files
  $#files > -1 || usage("No filenames given");

  # Normalize language string
  $global->{language} = Any2ISO($global->{language});

  # Setup the SGML environment.
  my @sgmlcatalogs =
    (# SGML iso-entities catalog location in Debian sgml-data package
     "$main::isoentities_prefix/share/sgml/entities/sgml-iso-entities-8879.1986/catalog",
     # SGML iso-entities catalog location in ArchLinux, Fedora and Gentoo
     "$main::isoentities_prefix/share/sgml/sgml-iso-entities-8879.1986/catalog",
     # SGML iso-entities catalog location when installed from linuxdoc-tools
     "$main::isoentities_prefix/share/sgml/iso-entities-8879.1986/iso-entities.cat",
     # dtd/catalog for SGML-Tools
     "$main::DataDir/linuxdoc-tools.catalog",
     # The super catalog
     "/etc/sgml/catalog");

  @sgmlcatalogs = ($ENV{SGML_CATALOG_FILES}, @sgmlcatalogs) if defined $ENV{SGML_CATALOG_FILES};

  $ENV{SGML_CATALOG_FILES} = join(':', @sgmlcatalogs);

  # Set to one of these if readable, nil otherwise
  $ENV{SGMLDECL} = ldt_searchfile(["$main::DataDir/dtd/$global->{format}.dcl",
				   "$main::DataDir/dtd/$global->{style}.dcl",
				   "$main::DataDir/dtd/sgml.dcl"]);

  # Show the list of loaded fmt_*.pl files if debugging
  print STDERR $global->{fmtlist} if $global->{debug};

  # Return the list of files to be processed
  return @files;
}

# ------------------------------------------------------------------------

=item LinuxDocTools::process_file

With all the configuration done, this routine will take a single filename
and convert it to the currently active backend format. The conversion is
done in a number of steps in tight interaction with the currently active
backend (see also L<LinuxDocTools::BackEnd>):

=over

=item 1. Backend: set NSGMLS options and optionally create a pre-NSGMLS pipe.

=item 2. Here: Run the preprocessor to handle conditionals.

=item 3. Here: Run NSGMLS.

=item 4. Backend: run pre-ASP conversion.

=item 5. Here: Run SGMLSASP.

=item 6. Backend: run post-ASP conversion, generating the output.

=back

All stages are influenced by command-line settings, currently active format,
etcetera. See the code for details.

=cut

# ------------------------------------------------------------------------
sub process_file {
# ------------------------------------------------------------------------
  my $file            = $global->{origfile} = shift (@_);
  my $saved_umask     = umask;
  my $error_header    = "LinuxdocTools::process_file";

  print "Processing file $file\n";
  umask 0077;

  my ($filename, $filepath, $filesuffix) = fileparse($file, "\.sgml");
  $global->{filename} = $filename;
  $global->{filepath} = $filepath;
  $global->{file}     = ldt_searchfile(["$filepath/$filename.sgml",
					"$filepath/$filename.SGML"])
    or die "$error_header: Cannot find $file. Aborting ...\n";

  my $dtd = ldt_getdtd_v1("$global->{file}");
  print STDERR "DTD: " . $dtd . "\n" if $global->{debug};

  # Prepare temporary directory
  my $tmpdir    = $ENV{'TMPDIR'} || '/tmp';
  $tmpdir       = tempdir("linuxdoc-tools.XXXXXXXXXX", DIR => "$tmpdir");

  # Set common base name for temp files and temp file names
  my $tmpbase   = $global->{tmpbase} = $tmpdir . '/sgmltmp.' . $filename;
  my $precmdout = "$tmpbase.01.precmdout";
  my $nsgmlsout = "$tmpbase.02.nsgmlsout";   # Was $tmpbase.1
  my $preaspout = "$tmpbase.03.preaspout";   # Was $tmpbase.2
  my $aspout    = "$tmpbase.04.aspout";      # Was $tmpbase.3

  # Set up the preprocessing command. Conditionals have to be
  # handled here until they can be moved into the DTD, otherwise
  # a validating SGML parser will choke on them.

  # Check if output option for latex is pdf or not
  if ($global->{format} eq "latex2e") {
    if ($Formats{$global->{format}}{output} eq "pdf") {
      $global->{define} .= " pdflatex=yes";
    }
  }

  # Set the actual pre-processing command
  my($precmd) = "| $global->{sgmlpre} output=$global->{format} $global->{define}";

  # Make sure path of file to be processed is in SGML_SEARCH_PATH
  $ENV{"SGML_SEARCH_PATH"} .= ":$filepath";

  # You can hack $NsgmlsOpts here, etcetera.
  $global->{NsgmlsOpts}   .= "-D $main::prefix/share/sgml -D $main::DataDir";
  $global->{NsgmlsOpts}   .= "-i$global->{include}" if ($global->{include});

  # If a preNSGMLS function is defined in the fmt file, pipe its output to $FILE,
  # otherwise just open $global->{file} as $IFILE
  # ----------------------------------------------------------------------------
  my $IFILE;
  if ( defined $Formats{$global->{format}}{preNSGMLS} ) {
    $global->{NsgmlsPrePipe} = &{$Formats{$global->{format}}{preNSGMLS}};
    open ($IFILE,"$global->{NsgmlsPrePipe} |")
      || die "$error_header: Could not open pipe from $global->{NsgmlsPrePipe}. Aborting ...\n";
  } else {
    open ($IFILE,"< $global->{file}")
      || die "$error_header: Could not open $global->{file} for reading. Aborting ...\n";
  }

  # Create a temp file with $precmd output
  my $precmd_command    = "$precmd > $precmdout";

  open (my $PRECMDOUT, "$precmd_command")
    or die "$error_header: Could not open pipe to $precmdout. Aborting ...\n";

  if ($global->{charset} eq "latin") {
    print $PRECMDOUT ldt_latin1tosgml($IFILE);
  } else {
    copy($IFILE,$PRECMDOUT);
  }

  close $IFILE;
  close $PRECMDOUT;

  # Process with nsgmls.
  my $nsgmls_command = "$main::progs->{NSGMLS} $global->{NsgmlsOpts} $ENV{SGMLDECL} $precmdout > $nsgmlsout";
  system($nsgmls_command) == 0
    or die "Error: \"$nsgmls_command\" failed with exit status: ",$? >> 8,"\n";

  #  Special case: if format is global, we're just checking.
  cleanup if ( $global->{format} eq "global");

  #  If output file does not exists or is empty, something went wrong.
  if ( ! -e "$nsgmlsout" ) {
    die "$error_header: Can't create file $nsgmlsout. Aborting ...\n";
  } elsif ( -z "$nsgmlsout" ){
    die "$error_header: $nsgmlsout empty, SGML parsing error. Aborting ...\n";
  }

  print "- Nsgmls stage finished.\n" if $global->{debug};

  #  If a preASP stage is defined, let the format handle it.
  #  --------------------------------------------------------
  open (my $PREASP_IN, "< $nsgmlsout")
    or die "$error_header: Could not open $nsgmlsout for reading. Aborting ...\n";
  open (my $PREASP_OUT, "> $preaspout")
    or die "$error_header: Could not open $preaspout for writing. Aborting ...\n";

  if (defined $Formats{$global->{format}}{preASP}) {
    # Usage: preASP ($INHANDLE, $OUTHANDLE);
    &{$Formats{$global->{format}}{preASP}}($PREASP_IN, $PREASP_OUT) == 0
      or die "$error_header: Error pre-processing $global->{format}.\n";
  } else {
    copy ($PREASP_IN, $PREASP_OUT);
  }

  close $PREASP_IN;
  close $PREASP_OUT;

  die "$error_header: Can't create $preaspout file. Aborting ...\n"
    unless -e "$preaspout";

  print "- PreASP stage finished.\n" if ( $global->{debug} );

  # Run sgmlsasp, with an optional style if specified.
  # -----------------------------------------------------------
  my $dtd2 = ldt_getdtd_v2($preaspout)
    or die "$error_header: Could not read dtd from $preaspout. Aborting ...\n";

  unless ( $dtd eq $dtd2 ){
    print STDERR "Warning: Two different values for dtd, dtd1: $dtd, dtd2: $dtd2\n";
    $dtd = $dtd2;
  }

  $global->{'dtd'} = $dtd;

  #  Search order:
  #  - datadir/site/<dtd>/<format>
  #  - datadir/dist/<dtd>/<format>

  my $style = ($global->{style}) ?
    ldt_searchfile(["$main::DataDir/site/$dtd/$global->{format}/$global->{style}mapping",
		    "$main::DataDir/dist/$dtd/$global->{format}/$global->{style}mapping",
		    "$main::DataDir/mappings/$global->{format}/$global->{style}mapping"])
    :
    '';

  my $mapping = ldt_searchfile(["$main::DataDir/site/$dtd/$global->{format}/mapping",
				"$main::DataDir/dist/$dtd/$global->{format}/mapping",
				"$main::DataDir/mappings/$global->{format}/mapping"])
    or die "$error_header: Could not find mapping file for $dtd/$global->{format}. Aborting ...\n";

  $mapping = "$style $mapping" if $style;

  $global->{charset} = "nippon" if ($global->{language} eq "ja");

  # We don't have Korean groff so charset should be latin1.
  if ($global->{language} eq "ko") {
    if ($global->{format} eq "groff") {
      $global->{charset} = "latin1";
    } else {
      $global->{charset} = "euc-kr";
    }
  }

  if ($global->{format} eq "groff"){
    if ($dtd eq "linuxdoctr") {
      $mapping = "$main::DataDir/mappings/$global->{format}/tr-mapping";
    }
  }

  my $sgmlsasp_command = "$main::progs->{SGMLSASP} $mapping < $preaspout |
      expand -t $global->{tabsize} > $aspout";
  system ($sgmlsasp_command) == 0
    or die "$error_header: Error running $sgmlsasp_command. Aborting ...\n";

  die "$error_header: Can't create $aspout file. Aborting ...\n"
    unless -e "$aspout";

  print "- ASP stage finished.\n" if ( $global->{debug} );

  #  If a postASP stage is defined, let the format handle it.
  # ----------------------------------------------------------------
  umask $saved_umask;

  open (my $INPOSTASP, "< $aspout" )
    or die "$error_header: Could not open $aspout for reading. Aborting ...\n";
  if (defined $Formats{$global->{format}}{postASP}) {
    # Usage: postASP ($INHANDLE)
    # Should leave whatever it thinks is right based on $INHANDLE.
    &{$Formats{$global->{format}}{postASP}}($INPOSTASP) == 0
      or die "$error_header: Error post-processing $global->{format}. Aborting ...\n";
  }
  close $INPOSTASP;

  print "- postASP stage finished.\n" if ( $global->{debug} );

  #  All done, remove the temporaries.
  remove_tmpfiles($tmpbase) unless ( $global->{debug} );
}

=pod

=back

=head1 SEE ALSO

Documentation for various sub-packages of LinuxDocTools.

=head1 AUTHOR
SGMLTools are written by Cees de Groot, C<E<lt>cg@cdegroot.comE<gt>>,
and various SGML-Tools contributors as listed in C<CONTRIBUTORS>.
Taketoshi Sano C<E<lt>sano@debian.org<gt>> rename to LinuxDocTools.

=cut
1;
