#
#  Utils.pm
#
#  $Id: Utils.pm,v 1.2 2001/08/31 22:39:44 sano Exp $
#
#  Utilities, split off from other modules in order to cut down file size.
#
#  © Copyright 1996, 1997, Cees de Groot
#
package LinuxDocTools::Utils;
use strict;

=head1 NAME

LinuxDocTools::Utils - various supporting routines

=head1 SYNOPSIS

  @files = process_options (@args);

  usage ($msg);

  trap_signals;

  cleanup;

  create_temp($tempfile)

=head1 DESCRIPTION

The B<LinuxDocTools::Utils> module contains a number of generic routines, mainly
split off from the main module in order to keep file size down.

=head1 FUNCTIONS

=over 4

=cut

use DirHandle;
use FileHandle;
use Cwd;
use File::Basename;
use Exporter;
use LinuxDocTools::Vars;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $in_signal);
@ISA = qw(Exporter);
@EXPORT = qw(usage process_options);
@EXPORT_OK = qw(cleanup trap_signals remove_tmpfiles create_temp);
$VERSION = sprintf("%d.%02d", q$Revision: 1.2 $ =~ /(\d+)\.(\d+)/);

use subs qw(usage);

# check whether options are unique
sub check_option_consistency
{
    my $owner = {};
    my ($fmt, $opt);
    foreach $fmt (keys %FmtList)
    {
	my $add = sub {		# add to options of $fmt
	    my $str = shift;
	    if ($owner->{$str}) {
		push(@{$owner->{$str}}, $fmt);
	    }
	    else {
		$owner->{$str} = [$fmt];
	    }
	};
	foreach $opt (@{$Formats{$fmt}{OPTIONS}})
	{
	    &$add("--$opt->{option}");
	    &$add("-$opt->{short}");
	}
    }
    my $error = 0;
    foreach $opt (keys %$owner)
    {
	if (scalar @{$owner->{$opt}} > 1)
	{
	    warn "duplicate option: $opt in " .
		join(', ', @{$owner->{$opt}}) . "\n";
	    $error = 1;
	}
    }
    die "Internal error detected" if $error;
}


=item process_options

This function processes the command line, and sets the variables associated
with the options along the way. When successful, it returns the arguments
on the command line it didn't interpret. Normally, this will be a list of
filenames.

=cut

sub process_options
{
  my @args = @_;
  my @retval;

  OPTPROC: while ($args[0]) 
    {
      my $long;
      my $curarg = $args[0];  
      if ($curarg =~ /^--.*/)
	{
	  #
	  #  Long option, --opt[==value]
	  #
	  $long = 1;
	}
      elsif ($curarg =~ /^-.*/)
	{
	  #
	  #  Short option, -o value
	  #
	  $long = 0;
	}
      else
	{
	  #
	  #  Filename
	  #
	  push @retval, $curarg;
	  next OPTPROC;
	}

      #
      #  Start looking for the option
      #
      foreach my $fmt (keys %FmtList)
	{
	  foreach my $opt (@{$Formats{$fmt}{OPTIONS}})
	    {
	      if (($long && $curarg =~ /^--$opt->{option}.*/) ||
		  $curarg =~ /^-$opt->{short}/)
		{
		  #
		  #  Found it! Get the argument and see whether all is OK
		  #  with the option.
		  #
		  my $optval = "";
		  if ($long)
		   {
		     if ($curarg =~ /^--$opt->{option}=.*/)
		       {
			 $optval = $curarg;
			 $optval =~ s/[^=]*=(.*)/$1/;
		       }
		   }
		  else
		   {
		     if ($args[1] =~ /^[^-].*/)
		       {
			 $optval = $args[1];
		       }
		   }
		  $opt->{type} eq "f" && do
		    {
		      #
		      #  "f" -> flag. Increment, so '-v -v' can work.
		      #
		      $Formats{$fmt}{$opt->{option}} += 1;
		      next OPTPROC;
		    };
		  #
		  #  All other types require a value (for now).
		  #
		  shift @args unless $long;
		  if ($optval eq "") 
		    {
		      usage "Option $curarg: value required";
		    }
		  ($opt->{type} eq "i" || $opt->{type} eq "s") && do
		    {
		      #
		      #  "i" -> numeric value.
		      #  "s" -> string value.
		      #
		      #  No type checking yet...
		      #
		      if ($opt->{option} eq "define")
			{
		          $Formats{$fmt}{$opt->{option}} .= " " . $optval;
			}
		      else
			{
			  $Formats{$fmt}{$opt->{option}} = $optval;
			}
		      next OPTPROC;
		    };
		  $opt->{type} eq "l" && do
		    {
		      #
		      #  "l" -> list of values.
		      #
		      foreach my $val (@{$opt->{'values'}})
			{
			  if ($val eq $optval)
			    {
			       $Formats{$fmt}{$opt->{option}} = $optval; 
			       next OPTPROC;
			    }
			}
		      usage "Invalid value '$optval' for '--$opt->{option}'";
		    };
		  usage "Unknown option type $opt->{type} in $fmt/$opt";
		}
	    } 
	}
      usage "Unknown option $curarg";
    }
  continue
    {
      shift @args;
    }
  return @retval;
}


=item usage

Prints out a generated help message about calling convention and allowed
options, then the argument string, and finally exits. 

=cut

sub usage
{
  my ($msg) = @_;

  print "LinuxDoc-Tools version " . `cat $main::DataDir/VERSION` . "\n";
  check_option_consistency;
  print "Usage:\n";
  print "  " . $global->{myname} . " [options] <infile>\n\n";
  my @helplist = sort(keys %Formats);
  @helplist = sort (keys %FmtList) if ($global->{format});
  foreach my $fmt (@helplist)
    {
      if ($fmt eq "global")
        {
	  print "General options:\n";
	}
      else
        {
          print "Format: " . $fmt . "\n";
	}
      print $Formats{$fmt}{HELP};
      for my $opt (@{$Formats{$fmt}{OPTIONS}})
        {
	  my $value = '';
	  if ($opt->{type} eq "i")
	    {
	      $value = "number";
	    }
          elsif ($opt->{type} eq "l")
	    {
	      $value = "{";
	      my $first = 1;
	      for my $val (@{$opt->{'values'}})
	        {
		  $first || ($value .= ",");
		  $first = 0;
		  $value .= $val;
		}
	      $value .= "}";
	    }
	  elsif ($opt->{type} eq "s")
            {
	      $value = "string";
	    }
	  print "  --$opt->{option}"; print "=$value" if $value;
	  print " -$opt->{short}"; print " $value" if $value;
	  print "\n";
	}
      print "\n";
    }

  $msg && print "Error: $msg\n\n";
  exit 1;
}


=item cleanup

This function cleans out all temporary files and exits. The unlink step
is skipped if debugging is turned on.

=cut

sub cleanup
{
    my ($signame) = @_;

    if( $signame ) {
        if ( $in_signal ) {
            if( $global->{debug} ) {
                print STDERR "Caught SIG$signame during cleanup -- aborting\n";
            }
            exit -1;
       }
       else {
           if( $global->{debug} ) {
               print STDERR "Caught SIG$signame -- cleaning up\n";
           }
           $in_signal = 1;
       }
    }

    if( !$global->{debug} && $global->{tmpbase} ) {
        remove_tmpfiles($global->{tmpbase});
    }
    exit 0;
}

=item remove_tmpfiles( $tmpbase )

This function cleans out all temporary files, using the argument $tmpbase to
determine the directory and pattern to use to find the temporary files.

=cut

sub remove_tmpfiles($) {
    my $tmpbase = shift;
    my ($name,$tmpdir) = fileparse($tmpbase,"");
    my $namelength = length $name;
    my $savdir = cwd;

    chdir($tmpdir);
    my $dir = new DirHandle(".");
    
    if (!defined($dir) ) {
        warn "Couldn't open temp directory $tmpdir: $!\n";
    } else {
        foreach my $tmpfile ($dir->read()) {
	    if (substr ($tmpfile, 0, $namelength) eq $name) {
	      unlink ($tmpfile) || warn "Couldn't unlink $tmpfile: $! \n";
	    }
        }
        $dir->close();
    }

    chdir($savdir);
    rmdir($tmpdir) || return -1;
}

=item trap_signals

This function traps all known signals, making sure that the B<cleanup>
function is executed on them. It should be called once at initialization
time.

=cut

sub trap_signals
{
  foreach my $sig ( 'HUP',  'INT',  'QUIT', 'ILL',
                    'TRAP', 'IOT',  'BUS',  'FPE',
                    'USR1', 'SEGV', 'USR2',
                    'PIPE', 'ALRM', 'TERM', )
    {
      $SIG{$sig} = \&cleanup;
    }
}

=item create_temp ( $tmpfile )

This function creates an empty temporary file with the required
permission for security reasons.

=cut

sub create_temp($) {
  my $tmpnam = shift;
  my $fh = new FileHandle($tmpnam,O_CREAT|O_EXCL|O_WRONLY,0600);
  $fh or die "$0: failed to create temporary file: $!";
  $fh->close;
}

=back

=head1 AUTHOR

Cees de Groot,  C<E<lt>cg@pobox.comE<gt>>.

=cut

1;
