#
#  BackEnd.pm
#
#  $Id: BackEnd.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  Dummy module containing backend specification.
#
#  © Copyright 1997, Cees de Groot
#
package LinuxDocTools::BackEnd;

die "This is a documentation package only!";

=head1 NAME

LinuxDocTools::BackEnd - LinuxDocTools back-end specification

=head1 SYNOPSIS

  require LinuxDocTools::BackEnd;
  $BackEnd->{...};

=head1 DESCRIPTION

LinuxDoc-Tools backend modules need to conform to a certain interface which is
detailed in this document. The interface makes sure that new backend modules
(or customer overrides) are compatible with what the main B<LinuxDocTools>
package expects. Note that this interface is still subject to change, you
should check this document on new releases of LinuxDoc-Tools.

=head1 INTERFACE

The interface between the main package and individual backends is very
minimal - only one global variable is modified, everything else is local. It
relies heavily on references and complex datatypes, so you want to make
sure that you're up-to-date with Perl5.

Every backend creates a reference to a hash and stores this reference in
the global I<%Formats> hash:

  my $BackEnd = {};
  $Formats{"BackEnd"} = $BackEnd;

The rest of this document will deal with the entries in the local hash
referenced by I<$BackEnd>.

=head1 HASH ENTRIES

=over 4

=item NAME

Specify the name of the backend, for help messages etcetera.

  $BackEnd->{NAME} = "BackEnd";

=item HELP

Specify an optional extra help message printed when the default usage
function is executed (see L<LinuxDocTools::Utils>).

  $BackEnd->{HELP} = "This is just and example message";

=item OPTIONS

This specifies the local set of options, which is added to the global set
of options (available in I<$global>). The options are specified as an
array of hashes containing a number of keys:

=over 4

=item option

The long option name

=item type

The type of the option, one of B<f> (flag), B<l> (list of allowed values),
B<s> (string), or B<i> (integer).

=item values

An array of allowed values, in case the option is of the list type.

=item short

A short (single-letter) version of the option name.

=back

Options can be specified as long options:

  --papersize=a4

or as short options:

  -p a4

Note that both the long options as the short options must not conflict with
the global options (an override is not - yet - possible) and should not
conflict with other backends.

  $BackEnd->{OPTIONS} = [
     { option => "split", type => "l", 
       'values' => [ "0", "1", "2" ], short => "s" },
     { option => "dosnames", type => "f", short => "D" },
     { option => "imagebuttons", type => "f", short => "I"}
  ];

The long names themselves function as hash keys; a default can be given
here and the option processing function will store any values found
at the same place:

  $BackEnd->{'split'}  = 1;
  $BackEnd->{dosnames}  = 0;
  $BackEnd->{imagebuttons}  = 0;

=item preNSGMLS

If defined, this should contain a subroutine that normally does two things: it
can modify the global value C<$global-E<gt>{NsgmlsOpts}> and it can set the
global value C<$global-E<gt>{NsgmlsPrePipe}>. The first variable contains
the option string passed to B<nsgmls>, and the second variable can contain
a command that generates the input for B<nsgmls>, presumably using the
current input file in some way (the current input file can be found
in C<$global-E<gt>{file}>).

  $BackEnd->{preNSGMLS} = sub {
    $global->{NsgmlsOpts} .= " -ifmtBackEnd ";
    $global->{NsgmlsPrePipe} = "sed 's/\@/\@\@/g' $global->{file}";
  };

=item preASP

If defined, this should contain a subroutine accepting an input and an output
file descriptor. The input file descriptor contains the raw output from
B<nsgmls>, and the output file descriptor should be filled with input 
to B<sgmlsasp>. This stage is often used to munch character entities
before they're fed to B<sgmlsasp>, see L<LinuxDocTools::CharEnts>. If the routine
doesn't return C<0>, LinuxDocTools aborts.

  $BackEnd->{preASP} = sub
  {
    my ($infile, $outfile) = @_;

    while (<$infile>)
      {
         s/([^\\])\\n/$1 \\n/g;
	 print $outfile $_;
      }
    return 0;
  };

=item postASP

This entry should always be defined, because it needs to contain a routine
that receives the output from B<sgmlsasp> which normally needs finalization.
LinuxDocTools itself doesn't know about file-naming conventions, etcetera, of
the backend so writing the final file is left to the backend. The subroutine
receives a reference to a filehandle (containing B<sgmlsasp> output) and
should do whatever it likes with this datastream.

  $BackEnd->{postASP} = sub
  {
    my $infile = shift;

    copy ($infile, "$global->{filename}.ext");
    return 0;
  };

=back

=head1 SEE ALSO

L<LinuxDocTools> and subpackages.

=head1 AUTHOR

SGML-Tools are written by Cees de Groot, C<E<lt>cg@cdegroot.comE<gt>>, 
and various SGML-Tools contributors as listed in C<CONTRIBUTORS>.
Taketoshi Sano C<E<lt>sano@debian.org<gt>> rename it to LinuxDocTools,
and do some bug-fixes and updates on it.

=cut
1; 
