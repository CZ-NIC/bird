#
#  Lang.pm
#
#  $Id: Lang.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  Language support.
#
#  © Copyright 1997, Cees de Groot
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
  fr français french
  es español spanish
  da dansk danish
  no norsk norwegian
  se svenska swedish
  pt portuges portuguese
  ca català catalan
  it italiano italian
  ro românã romanian
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
     "de" => "Zurück",
     "es" => "Página anterior",
     "fr" => "Page précédente",
     "da" => "Forrige",
     "no" => "Forrige",
     "se" => "Föregående",
     "pt" => "Página anterior",
     "ca" => "Pàgina anterior",
     "it" => "Indietro",
     "ro" => "Înapoi",
     "ja" => "Á°¤Î¥Ú¡¼¥¸",
     "pl" => "Poprzedni",
     "ko" => "ÀÌÀü",
     "fi" => "Edellinen"
  },
  "Next" => {
     "nl" => "Verder",
     "de" => "Weiter",
     "es" => "Página siguiente",
     "fr" => "Page suivante",
     "da" => "Næste",
     "no" => "Neste",
     "se" => "Nästa",
     "pt" => "Página seguinte",
     "ca" => "Pàgina següent",
     "it" => "Avanti",
     "ro" => "Înainte",
     "ja" => "¼¡¤Î¥Ú¡¼¥¸",
     "pl" => "Nastny",
     "ko" => "´ÙÀ½",
     "fi" => "Seuraava"
  },
  "Contents" => {
     "nl" => "Inhoud",
     "de" => "Inhalt",
     "es" => "Índice general",
     "fr" => "Table des matières",
     "da" => "Indhold",
     "no" => "Innhold",
     "se" => "Innehållsförteckning",
     "pt" => "Índice",
     "ca" => "Índex",
     "it" => "Indice",
     "ro" => "Cuprins",
     "ja" => "ÌÜ¼¡¤Ø",
     "pl" => "Spis Trei",
     "ko" => "Â÷·Ê",
     "fi" => "Sisällys"
  },
  "Table of Contents" => {
     "nl" => "Inhoudsopgave",
     "de" => "Inhaltsverzeichnis",
     "es" => "Índice general",
     "fr" => "Table des matières",
     "da" => "Indholdsfortegnelse",
     "no" => "Innholdsfortegnelse",
     "se" => "Innehållsförteckning",
     "pt" => "Índice geral",
     "ca" => "Índex general",
     "it" => "Indice Generale",
     "ro" => "Cuprins",
     "ja" => "ÌÜ¼¡",
     "pl" => "Spis Trei",
     "ko" => "Â÷·Ê",
     "fi" => "Sisällysluettelo"
  }
};

=back

=head1 AUTHOR

Cees de Groot, C<E<lt>cg@pobox.comE<gt>>

=cut

1;
