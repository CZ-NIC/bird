#!/usr/bin/perl

use common::sense;
use Data::Dump;
use List::Util;

my @GROUP_BY = qw/VERSION PEERS TOTAL_ROUTES/;
my @VALUES = qw/RSS SZ VSZ TIMEDIF/;

my ($FILE, $TYPE) = @ARGV;

### Load data ###
my %data;
open F, "<", $FILE or die $!;
my @header = split /;/, <F>;
chomp @header;

my $line = undef;
while ($line = <F>)
{
  chomp $line;
  my %row;
  @row{@header} = split /;/, $line;
  push @{$data{join ";", @row{@GROUP_BY}}}, { %row } if $row{TYPE} eq $TYPE;
}

### Do statistics ###
sub avg {
  return List::Util::sum(@_) / @_;
}

sub stdev {
  my $avg = shift;
  return 0 if @_ <= 1;
  return sqrt(List::Util::sum(map { ($avg - $_)**2 } @_) / (@_-1));
}

my %output;
my %vers;

STATS:
foreach my $k (keys %data)
{
  my %cols = map { my $vk = $_; $vk => [ map { $_->{$vk} } @{$data{$k}} ]; } @VALUES;

  my %avg = map { $_ => avg(@{$cols{$_}})} @VALUES;
  my %stdev = map { $_ => stdev($avg{$_}, @{$cols{$_}})} @VALUES;

  foreach my $v (@VALUES) {
    next if $stdev{$v} / $avg{$v} < 0.035;

    for (my $i=0; $i<@{$cols{$v}}; $i++)
    {
      my $dif = $cols{$v}[$i] - $avg{$v};
      next if $dif < $stdev{$v} * 2 and $dif > $stdev{$v} * (-2);
=cut
      printf "Removing an outlier for %s/%s: avg=%f, stdev=%f, variance=%.1f%%, val=%f, valratio=%.1f%%\n",
	$k, $v, $avg{$v}, $stdev{$v}, (100 * $stdev{$v} / $avg{$v}), $cols{$v}[$i], (100 * $dif / $stdev{$v});
=cut
      splice @{$data{$k}}, $i, 1, ();
      redo STATS;
    }
  }

  $vers{$data{$k}[0]{VERSION}}++;
  $output{"$data{$k}[0]{PEERS};$data{$k}[0]{TOTAL_ROUTES}"}{$data{$k}[0]{VERSION}} = { %avg };
}

### Export the data ###

say "PEERS;TOTAL_ROUTES;" . join ";", ( map { my $vk = $_; map { "$_/$vk" } keys %vers; } @VALUES );

sub keysort {
  my ($pa, $ta) = split /;/, $_[0];
  my ($pb, $tb) = split /;/, $_[1];

  return (int $ta) <=> (int $tb) if $pa eq $pb;
  return (int $pa) <=> (int $pb);
}
  
foreach my $k (sort { keysort($a, $b); } keys %output)
{
  say "$k;" . join ";", ( map { my $vk = $_; map { $output{$k}{$_}{$vk}; } keys %vers; } @VALUES );
}
