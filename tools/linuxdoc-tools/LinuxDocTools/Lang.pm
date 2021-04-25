#
#  Lang.pm
#
#  $Id: Lang.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  Language support.
#
#  � Copyright 1997, Cees de Groot
#

package LinuxDocTools::Lang;

use strict;
use vars qw($VERSION @ISA @EXPORT @Languages $translations);

require 5.0004;
use Exporter;
use LinuxDocTools::Vars;

$VERSION = sprintf("%d.%02d", q$Revision: 1.1.1.1 $ =~ /(\d+)\.(\d+)/);
@ISA     = qw(Exporter);
@EXPORT  = qw(Any2ISO ISO2Native ISO2English Xlat);

=head1 NAME

LinuxDocTools::Lang - language name and translation functions

=head1 SYNOPSIS

  $isoname = Any2ISO ('deutsch');
  $native  = ISO2Native ('de');
  $engname = ISO2English ('nederlands');
  
  $global->{language} = 'nl';
  $dutch = Xlat ('Table of Contents');

=head1 DESCRIPTION

B<LinuxDocTools::Lang> gives a simple interface to various forms of language
names, and provides a translation service. Languages can be specified in
three different ways: by their native name, by their english name, and
by their 2-letter ISO code. For example, you can specify the German
language as C<deutsch>, as C<german> or as C<de>.

=head1 FUNCTIONS

=over 4

=cut

@Languages = qw(
  en english english
  de deutsch german
  nl nederlands dutch
  fr fran�ais french
  es espa�ol spanish
  da dansk danish
  no norsk norwegian
  se svenska swedish
  pt portuges portuguese
  ca catal� catalan
  it italiano italian
  ro rom�n� romanian
  ja japanese japanese
  pl polski polish
  ko korean korean
  fi suomi finnish
);


=item Any2ISO

Maps any of the three forms of languages to the ISO name. So either of
these invocations:

  Any2ISO ('dutch');
  Any2ISO ('nederlands');
  Any2ISO ('nl');

will return the string C<"nl">.

=cut

sub Any2ISO
{
  my $lang = shift (@_);
  
  my $i = 0;
  foreach my $l (@Languages)
    {
      ($l eq $lang) && last;
      $i++;
    }
  return $Languages[(int $i / 3) * 3];
}


=item ISO2Native

Maps the ISO code to the native name of the language.

=cut

sub ISO2Native
{
  my $iso = shift (@_);

  my $i = 0;
  foreach my $l (@Languages)
    {
      ($l eq $iso) && last;
      $i++;
    }
  return $Languages[$i + 1];

}


=item ISO2English

Maps the ISO code to the english name of the language.

=cut

sub ISO2English
{
  my $iso = shift (@_);

  my $i = 0;
  foreach my $l (@Languages)
    {
      ($l eq $iso) && last;
      $i++;
    }
  return $Languages[$i + 2];
}

=item Xlat

Translates its (English) argument to the language specified by the
current value of C<$gobal-E<gt>{language}>. The module, in its source
file, contains a data structure, indexed by the English strings, that
has all available translations. 

=cut

sub Xlat
{
  my ($txt) = @_;

  return $txt if ($global->{language} eq "en");
  return $translations->{$txt}{$global->{language}};
};


#
#  By the time this grows big, we'll make up something else.
#
$translations = {
  "Previous" => {
     "nl" => "Terug",
     "de" => "Zur�ck",
     "es" => "P�gina anterior",
     "fr" => "Page pr�c�dente",
     "da" => "Forrige",
     "no" => "Forrige",
     "se" => "F�reg�ende",
     "pt" => "P�gina anterior",
     "ca" => "P�gina anterior",
     "it" => "Indietro",
     "ro" => "�napoi",
     "ja" => "���Υڡ���",
     "pl" => "Poprzedni",
     "ko" => "����",
     "fi" => "Edellinen"
  },
  "Next" => {
     "nl" => "Verder",
     "de" => "Weiter",
     "es" => "P�gina siguiente",
     "fr" => "Page suivante",
     "da" => "N�ste",
     "no" => "Neste",
     "se" => "N�sta",
     "pt" => "P�gina seguinte",
     "ca" => "P�gina seg�ent",
     "it" => "Avanti",
     "ro" => "�nainte",
     "ja" => "���Υڡ���",
     "pl" => "Nastny",
     "ko" => "����",
     "fi" => "Seuraava"
  },
  "Contents" => {
     "nl" => "Inhoud",
     "de" => "Inhalt",
     "es" => "�ndice general",
     "fr" => "Table des mati�res",
     "da" => "Indhold",
     "no" => "Innhold",
     "se" => "Inneh�llsf�rteckning",
     "pt" => "�ndice",
     "ca" => "�ndex",
     "it" => "Indice",
     "ro" => "Cuprins",
     "ja" => "�ܼ���",
     "pl" => "Spis Trei",
     "ko" => "����",
     "fi" => "Sis�llys"
  },
  "Table of Contents" => {
     "nl" => "Inhoudsopgave",
     "de" => "Inhaltsverzeichnis",
     "es" => "�ndice general",
     "fr" => "Table des mati�res",
     "da" => "Indholdsfortegnelse",
     "no" => "Innholdsfortegnelse",
     "se" => "Inneh�llsf�rteckning",
     "pt" => "�ndice geral",
     "ca" => "�ndex general",
     "it" => "Indice Generale",
     "ro" => "Cuprins",
     "ja" => "�ܼ�",
     "pl" => "Spis Trei",
     "ko" => "����",
     "fi" => "Sis�llysluettelo"
  }
};

=back

=head1 AUTHOR

Cees de Groot, C<E<lt>cg@pobox.comE<gt>>

=cut

1;
