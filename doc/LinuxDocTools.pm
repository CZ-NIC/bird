#! /usr/bin/perl 
#
#  LinuxDocTools.pm
#
#  $Id$
#
#  LinuxDoc-Tools driver core. This contains all the basic functionality
#  we need to control all other components.
#
#  � Copyright 1996, Cees de Groot.
#  � Copyright 2000, Taketoshi Sano
#
#  THIS VERSION HAS BEEN HACKED FOR BIRD BY MARTIN MARES
#
package LinuxDocTools;

require 5.004;
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

use DirHandle;
use File::Basename;
use File::Find;
use File::Copy;
use FileHandle;
use IPC::Open2;
use Cwd;
use LinuxDocTools::Lang;
use LinuxDocTools::Utils qw(process_options usage cleanup trap_signals remove_tmpfiles create_temp);
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

=item LinuxDocTools::init

Takes care of initialization of package-global variables (which are actually
defined in L<LinuxDocTools::Vars>). The package-global variables are I<$global>,
a reference to a hash containing numerous settings, I<%Formats>, a hash
containing all the formats, and I<%FmtList>, a hash containing the currently
active formats for help texts. 

Apart from this, C<LinuxDocTools::init> also finds all distributed and site-local
formatting backends and C<require>s them.

=cut

sub init
{
  trap_signals;

  #
  #  Register the ``global'' pseudoformat. Apart from the global settings,
  #  we also use $global to keep the global variable name space clean; 
  #  everything that we need to provide to other modules is stuffed
  #  into $global.
  #
  $global = {};
  $global->{NAME} = "global";
  $global->{HELP} = "";
  $global->{OPTIONS} = [
    { option => "backend", type => "l",
      'values' => [ "html", "info", "latex", 
			"lyx", "rtf", "txt", "check" ],
	 short => "B" },
    { option => "papersize", type => "l",
      'values' => [ "a4", "letter" ], short => "p" },
    { option => "language",  type => "l",
      'values' => [ @LinuxDocTools::Lang::Languages ], short => "l" },
    { option => "charset",   type => "l",
      'values' => [ "latin", "ascii", "nippon", "euc-kr" ], short => "c" },
    { option => "style",     type => "s", short => "S" },
    { option => "tabsize",   type => "i", short => "t" },
#    { option => "verbose",   type => "f", short => "v" },
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
  $Formats{$global->{NAME}} = $global;	# All formats we know.
  $FmtList{$global->{NAME}} = $global;  # List of formats for help msgs.

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

  #
  #  Used when the format is "global" (from sgmlcheck).
  #
  $global->{preNSGMLS} = sub {
    $global->{NsgmlsOpts} .= " -s ";
    $global->{NsgmlsPrePipe} = "cat $global->{file}";
  };

  #
  #  Build up the list of formatters.
  #
  my $savdir = cwd;
  my %Locs;
  chdir "$main::DataDir/dist";
  my $dir = new DirHandle(".");
  die "Unable to read directory $main::DataDir/dist: $!" unless defined($dir);
  foreach my $fmt (grep(/^fmt_.*\.pl$/, $dir->read()))
  {
    $Locs{$fmt} = "dist";
  }
  $dir->close();
  chdir "$main::DataDir/site";
  $dir = new DirHandle(".");
  die "Unable to read directory $main::DataDir/site: $!" unless defined($dir);
  foreach my $fmt (grep(/^fmt_.*\.pl$/, $dir->read()))
  {
    $Locs{$fmt} = "site";
  }
  $dir->close();
  foreach my $fmt (keys %Locs)
  {
    require $fmt;
  }
  chdir $savdir;
}

=item LinuxDocTools::process_options ($0, @ARGV)

This function contains all initialization that is bound to the current
invocation of LinuxDocTools. It looks in C<$0> to deduce the backend that
should be used (ld2txt activates the I<txt> backend) and parses the
options array. It returns an array of filenames it encountered during
option processing.

As a side effect, the environment variables I<SGMLDECL> and 
I<SGML_CATALOG_FILES> are modified.

=cut

sub process_options
{
  my $progname = shift;
  my @args = @_;

  #
  #  Deduce the format from the caller's file name
  #
  my ($format, $dummy1, $dummy2) = fileparse ($progname, "");
  $global->{myname} = $format;
  $format =~ s/sgml2*(.*)/$1/;

  #
  # check the option "--backend / -B"
  #
  if ($format eq "linuxdoc") {
      my @backends = @args;
      my $arg;
      while (@backends) {
         $arg = shift @backends;
         if ($arg eq "-B") {
                $arg = shift @backends;
                $format = $arg;
                last;
	 }
         if ( $arg =~ s/--backend=(.*)/$1/ ) {
                $format = $arg;
                last;
         }
      }
  }

  $format = "global" if $format eq "check";
  usage ("") if $format eq "linuxdoc";
  $format = "latex2e" if $format eq "latex";
  $FmtList{$format} = $Formats{$format} or 
     usage ("$global->{myname}: unknown format");
  $global->{format} = $format;

  #
  #  Parse all the options.
  #
  my @files = LinuxDocTools::Utils::process_options (@args);
  $global->{language} = Any2ISO ($global->{language});
  #
  # check the number of given files 
  $#files > -1 || usage ("no filenames given");

  #
  #  Setup the SGML environment.
  #  (Note that Debian package rewrite path to catalog of
  #   iso-entities using debian/rules so that it can use 
  #   entities from sgml-data pacakge.  debian/rules also
  #   removes iso-entites sub directory after doing make install.)
  #
  $ENV{SGML_CATALOG_FILES} .= (defined $ENV{SGML_CATALOG_FILES} ? ":" : "") .
     "$main::prefix/share/sgml/sgml-iso-entities-8879.1986/catalog:" .
     "$main::prefix/share/sgml/entities/sgml-iso-entities-8879.1986/catalog";
  $ENV{SGML_CATALOG_FILES} .= ":$main::DataDir/linuxdoc-tools.catalog";
  $ENV{SGML_CATALOG_FILES} .= ":$main::/etc/sgml.catalog";
  if (-f "$main::DataDir/dtd/$format.dcl")
    {
      $ENV{SGMLDECL} = "$main::DataDir/dtd/$format.dcl";
    }
  elsif (-f "$main::DataDir/dtd/$global->{style}.dcl")
    {
      $ENV{SGMLDECL} = "$main::DataDir/dtd/$global->{style}.dcl";
    }
  elsif (-f "$main::DataDir/dtd/sgml.dcl")
    {
      $ENV{SGMLDECL} = "$main::DataDir/dtd/sgml.dcl";
    }

  #
  #  OK. Give the list of files we distilled from the options
  #  back to the caller.
  #
  return @files;
}

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

sub process_file
{
  my $file = shift (@_);
  my $saved_umask = umask;

  print "Processing file $file\n";
  umask 0077;

  my ($filename, $filepath, $filesuffix) = fileparse ($file, "\.sgml");
  my $tmpnam = $filepath . '/' . $filename;
  $file = $tmpnam . $filesuffix;
  -f $file || $file =~ /.*.sgml$/ || ($file .= '.sgml');
  -f $file || ($file = $tmpnam . '.SGML');
  -f $file || die "Cannot find $file\n";
  $global->{filename} = $filename;
  $global->{file} = $file;
  $global->{filepath} = $filepath;

  my $tmp = new FileHandle "<$file";
  my $dtd;
  while ( <$tmp> )
    {
      tr/A-Z/a-z/;
      # check for [<!doctype ... system] type definition
      if ( /<!doctype\s*(\w*)\s*system/ )
        {
          $dtd = $1;
          last;
        }
      # check for <!doctype ... PUBLIC ... DTD ...
      if ( /<!doctype\s*\w*\s*public\s*.*\/\/dtd\s*(\w*)/mi )
        {
          $dtd = $1;
          last;
        }
      # check for <!doctype ...
      #          PUBLIC  ... DTD ...
      # (multi-line version)
      if ( /<!doctype\s*(\w*)/ )
        {
          $dtd = "precheck";
          next;
        }
      if ( /\s*public\s*.*\/\/dtd\s*(\w*)/ && $dtd eq "precheck" )
        {
          $dtd = $1;
          last;
        }
    }
  $tmp->close;
  if ( $global->{debug} )
    {
      print "DTD: " . $dtd . "\n";
    }
  $global->{dtd} = $dtd;

  # prepare temporary directory
  my $tmpdir = $ENV{'TMPDIR'} || '/tmp';
  $tmpdir = $tmpdir . '/' . 'linuxdoc-dir-' . $$;
  mkdir ($tmpdir, 0700) ||
   die " - temporary files can not be created, aborted - \n";

  my $tmpbase = $global->{tmpbase} = $tmpdir . '/sgmltmp.' . $filename;
  $ENV{"SGML_SEARCH_PATH"} .= ":$filepath";

  #
  # Set up the preprocessing command.  Conditionals have to be
  # handled here until they can be moved into the DTD, otherwise
  # a validating SGML parser will choke on them.
  #
  # check if output option for latex is pdf or not
  if ($global->{format} eq "latex2e")
    {
      if ($Formats{$global->{format}}{output} eq "pdf")
        {
          $global->{define} .= " pdflatex=yes";
        }
    }
  #

  local $ENV{PATH} = "$ENV{PATH}:/usr/lib/linuxdoc-tools";
  my($precmd) = "|sgmlpre output=$global->{format} $global->{define}";

  #
  #  You can hack $NsgmlsOpts here, etcetera.
  #
  $global->{NsgmlsOpts} .= "-D $main::prefix/share/sgml -D $main::DataDir";
  $global->{NsgmlsOpts} .= "-i$global->{include}" if ($global->{include});
  $global->{NsgmlsPrePipe} = "NOTHING";
  if ( defined $Formats{$global->{format}}{preNSGMLS} )
    {
      $global->{NsgmlsPrePipe} = &{$Formats{$global->{format}}{preNSGMLS}};
    }

  #
  #  Run the prepocessor and nsgmls.
  #
  my ($ifile, $writensgmls);

  if ($global->{NsgmlsPrePipe} eq "NOTHING")
    {
      $ifile = new FileHandle $file;
    }
  else
    {
      $ifile = new FileHandle "$global->{NsgmlsPrePipe}|";
    }

  create_temp("$tmpbase.1");
  $writensgmls = new FileHandle
      "$precmd|$main::progs->{NSGMLS} $global->{NsgmlsOpts} $ENV{SGMLDECL} >\"$tmpbase.1\"";
  if ($global->{charset} eq "latin")
    {
      while (<$ifile>) 
        {
	  # Outline these commands later on - CdG
	  #change latin1 characters to SGML
	  #by Farzad Farid, adapted by Greg Hankins
	  s/�/\&Agrave;/g;
	  s/�/\&Aacute;/g;
	  s/�/\&Acirc;/g;
	  s/�/\&Atilde;/g;
	  s/�/\&Auml;/g;
	  s/�/\&Aring;/g;
	  s/�/\&AElig;/g;
	  s/�/\&Ccedil;/g;
	  s/�/\&Egrave;/g;
	  s/�/\&Eacute;/g;
	  s/�/\&Ecirc;/g;
	  s/�/\&Euml;/g;
	  s/�/\&Igrave;/g;
	  s/�/\&Iacute;/g;
	  s/�/\&Icirc;/g;
	  s/�/\&Iuml;/g;
	  s/�/\&Ntilde;/g;
	  s/�/\&Ograve;/g;
	  s/�/\&Oacute;/g;
	  s/�/\&Ocirc;/g;
	  s/�/\&Otilde;/g;
	  s/�/\&Ouml;/g;
	  s/�/\&Oslash;/g;
	  s/�/\&Ugrave;/g;
	  s/�/\&Uacute;/g;
	  s/�/\&Ucirc;/g;
	  s/�/\&Uuml;/g;
	  s/�/\&Yacute;/g;
	  s/�/\&THORN;/g;
	  s/�/\&szlig;/g;
	  s/�/\&agrave;/g;
	  s/�/\&aacute;/g;
	  s/�/\&acirc;/g;
	  s/�/\&atilde;/g;
	  s/�/\&auml;/g;
	  s/�/\&aring;/g;
	  s/�/\&aelig;/g;
	  s/�/\&ccedil;/g;
	  s/�/\&egrave;/g;
	  s/�/\&eacute;/g;
	  s/�/\&ecirc;/g;
	  s/�/\&euml;/g;
	  s/�/\&igrave;/g;
	  s/�/\&iacute;/g;
	  s/�/\&icirc;/g;
	  s/�/\&iuml;/g;
	  s/�/\&mu;/g;
	  s/�/\&eth;/g;
	  s/�/\&ntilde;/g;
	  s/�/\&ograve;/g;
	  s/�/\&oacute;/g;
	  s/�/\&ocirc;/g;
	  s/�/\&otilde;/g;
	  s/�/\&ouml;/g;
	  s/�/\&oslash;/g;
	  s/�/\&ugrave;/g;
	  s/�/\&uacute;/g;
	  s/�/\&ucirc;/g;
	  s/�/\&uuml;/g;
	  s/�/\&yacute;/g;
	  s/�/\&thorn;/g;
	  s/�/\&yuml;/g;
          print $writensgmls $_;
	}
    }
  else
    {
      while (<$ifile>)
        {
          print $writensgmls $_;
	}
    }
  $ifile->close;
  $writensgmls->close;
        
  #
  #  Special case: if format is global, we're just checking.
  #
  $global->{format} eq "global" && cleanup;

  #
  #  If the output file is empty, something went wrong.
  #
  ! -e "$tmpbase.1" and die "can't create file - exiting";
  -z "$tmpbase.1" and die "SGML parsing error - exiting";
  if ( $global->{debug} )
    {
      print "Nsgmls stage finished.\n";
    }

  #
  #  If a preASP stage is defined, let the format handle it.
  #  
  #  preASP ($inhandle, $outhandle);
  #
  my $inpreasp = new FileHandle "<$tmpbase.1";
  my $outpreasp = new FileHandle "$tmpbase.2",O_WRONLY|O_CREAT|O_EXCL,0600;
  if (defined $Formats{$global->{format}}{preASP})
    {
      &{$Formats{$global->{format}}{preASP}}($inpreasp, $outpreasp) == 0 or
       die "error pre-processing $global->{format}.\n";
    }  
  else
    {
      copy ($inpreasp, $outpreasp);
    }
  $inpreasp->close;
  $outpreasp->close;
  ! -e "$tmpbase.2" and die "can't create file - exiting";

  if ( $global->{debug} )
    {
      print "PreASP stage finished.\n";
    }

  #
  #  Run sgmlsasp, with an optional style if specified.
  #
  #  Search order:
  #  - datadir/site/<dtd>/<format>
  #  - datadir/dist/<dtd>/<format>
  #  So we need to fetch the doctype from the intermediate.
  #
  #  Note: this is a very simplistic check - but as far as I know,
  #  it is correct. Am I right?
  #
  my $tmp = new FileHandle "<$tmpbase.2";
  my $dtd;
  while ( ($dtd = <$tmp>) && ! ( $dtd =~ /^\(/) ) { };
  $tmp->close;
  $dtd =~ s/^\(//;
  $dtd =~ tr/A-Z/a-z/;
  chop $dtd;
  $global->{dtd} = $dtd;

  my $style = "";
  if ($global->{style})
    {
      $style = "$main::DataDir/site/$dtd/$global->{format}/$global->{style}mapping";
      -r $style or
         $style = "$main::DataDir/dist/$dtd/$global->{format}/$global->{style}mapping";
    }
  my $mapping = "$main::DataDir/site/$dtd/$global->{format}/mapping";
  -r $mapping or $mapping = "$main::DataDir/dist/$dtd/$global->{format}/mapping";

  $global->{charset} = "nippon" if ($global->{language} eq "ja");
  #
  # we don't have Korean groff so charset should be latin1.
  #
  if ($global->{language} eq "ko")
    {
      if ($global->{format} eq "groff")
        {
          $global->{charset} = "latin1";
        }
      else
        {
          $global->{charset} = "euc-kr";
        }
    }
  
  if ($global->{format} eq "groff" or $global->{format} eq "latex2e")
    {
      if ($dtd eq "linuxdoctr")
        {
          $mapping = "$main::DataDir/dist/$dtd/$global->{format}/tr-mapping";
        }
    }

  create_temp("$tmpbase.3");
  system ("$main::progs->{SGMLSASP} $style $mapping <\"$tmpbase.2\" |
      expand -$global->{tabsize} >\"$tmpbase.3\"");
  ! -e "$tmpbase.3" and die "can't create file - exiting";


  if ( $global->{debug} )
    {
      print "ASP stage finished.\n";
    }

  #
  #  If a postASP stage is defined, let the format handle it.
  #  It should leave whatever it thinks is right based on $file.
  #
  #  postASP ($inhandle)
  #
  umask $saved_umask;
  my $inpostasp = new FileHandle "<$tmpbase.3";
  if (defined $Formats{$global->{format}}{postASP})
    {
      &{$Formats{$global->{format}}{postASP}}($inpostasp) == 0 or
	die "error post-processing $global->{format}.\n";
    }
  $inpostasp->close;

  if ( $global->{debug} )
    {
      print "postASP stage finished.\n";
    }

  #
  #  All done, remove the temporaries.
  #
  if( !$global->{debug} ) {
      remove_tmpfiles($tmpbase);
  }
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
