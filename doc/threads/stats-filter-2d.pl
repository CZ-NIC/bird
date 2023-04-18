#!/usr/bin/perl

use common::sense;
use Data::Dump;
use List::Util;

my @GROUP_BY = qw/VERSION PEERS TOTAL_ROUTES/;
my @VALUES = qw/TIMEDIF/;

my ($FILE, $TYPE, $OUTPUT) = @ARGV;

### Load data ###
my %data;
open F, "<", $FILE or die $!;
my @header = split /;/, <F>;
chomp @header;

my $line = undef;
while ($line = <F>)
{
  chomp $line;
  $line =~ s/;;(.*);;/;;\1;/;
  $line =~ s/v2\.0\.8-1[89][^;]+/bgp/;
  $line =~ s/v2\.0\.8-[^;]+/sark/ and next;
  $line =~ s/master;/v2.0.8;/;
  my %row;
  @row{@header} = split /;/, $line;
  push @{$data{join ";", @row{@GROUP_BY}}}, { %row } if $row{TYPE} eq $TYPE;
}

### Do statistics ###
sub avg {
  return List::Util::sum(@_) / @_;
}

sub getinbetween {
  my $index = shift;
  my @list = @_;

  return $list[int $index] if $index == int $index;

  my $lower = $list[int $index];
  my $upper = $list[1 + int $index];

  my $frac = $index - int $index;

  return ($lower * (1 - $frac) + $upper * $frac);
}

sub stats {
  my $avg = shift;
  return [0, 0, 0, 0, 0] if @_ <= 1;

  #  my $stdev = sqrt(List::Util::sum(map { ($avg - $_)**2 } @_) / (@_-1));

  my @sorted = sort { $a <=> $b } @_;
  my $count = scalar @sorted;

  return [
    getinbetween(($count-1) * 0.25, @sorted),
    $sorted[0],
    $sorted[$count-1],
    getinbetween(($count-1) * 0.75, @sorted),
  ];
}

my %output;
my %vers;
my %peers;
my %stplot;

STATS:
foreach my $k (keys %data)
{
  my %cols = map { my $vk = $_; $vk => [ map { $_->{$vk} } @{$data{$k}} ]; } @VALUES;

  my %avg = map { $_ => avg(@{$cols{$_}})} @VALUES;
  my %stloc = map { $_ => stats($avg{$_}, @{$cols{$_}})} @VALUES;

  $vers{$data{$k}[0]{VERSION}}++;
  $peers{$data{$k}[0]{PEERS}}++;
  $output{$data{$k}[0]{VERSION}}{$data{$k}[0]{PEERS}}{$data{$k}[0]{TOTAL_ROUTES}} = { %avg };
  $stplot{$data{$k}[0]{VERSION}}{$data{$k}[0]{PEERS}}{$data{$k}[0]{TOTAL_ROUTES}} = { %stloc };
}

#(3 == scalar %vers) and $vers{sark} and $vers{bgp} and $vers{"v2.0.8"} or die "vers size is " . (scalar %vers) . ", items ", join ", ", keys %vers;
(2 == scalar %vers) and $vers{bgp} and $vers{"v2.0.8"} or die "vers size is " . (scalar %vers) . ", items ", join ", ", keys %vers;

### Export the data ###

open PLOT, "|-", "gnuplot" or die $!;

say PLOT <<EOF;
set logscale

set term pdfcairo size 20cm,15cm

set xlabel "Total number of routes" offset 0,-1.5
set xrange [10000:3000000]
set xtics offset 0,-0.5
#set xtics (10000,15000,30000,50000,100000,150000,300000,500000,1000000)

set ylabel "Time to converge (s)"
set yrange [0.5:10800]

set grid

set key left top

set output "$OUTPUT"
EOF

my @colors = (
  [ 1, 0.9, 0.3 ],
  [ 0.7, 0, 0 ],
  #  [ 0.6, 1, 0.3 ],
  #  [ 0, 0.7, 0 ],
  [ 0, 0.7, 1 ],
  [ 0.3, 0.3, 1 ],
);

my $steps = (scalar %peers) - 1;

my @plot_data;
foreach my $v (sort keys %vers) {
  my $color = shift @colors;
  my $endcolor = shift @colors;
  my $stepcolor = [ map +( ($endcolor->[$_] - $color->[$_]) / $steps ), (0, 1, 2) ];

  foreach my $p (sort { int $a <=> int $b } keys %peers) {
    my $vnodot = $v; $vnodot =~ s/\.//g;
    say PLOT "\$data_${vnodot}_${p} << EOD";
    foreach my $tr (sort { int $a <=> int $b } keys %{$output{$v}{$p}}) {
      say PLOT "$tr $output{$v}{$p}{$tr}{TIMEDIF}";
    }
    say PLOT "EOD";

    say PLOT "\$data_${vnodot}_${p}_stats << EOD";
    foreach my $tr (sort { int $a <=> int $b } keys %{$output{$v}{$p}}) {
      say PLOT join " ", ( $tr, @{$stplot{$v}{$p}{$tr}{TIMEDIF}} );
    }
    say PLOT "EOD";

    my $colorstr = sprintf "linecolor rgbcolor \"#%02x%02x%02x\"", map +( int($color->[$_] * 255 + 0.5)), (0, 1, 2);
    push @plot_data, "\$data_${vnodot}_${p} using 1:2 with lines $colorstr linewidth 2 title \"$v, $p peers\"";
    push @plot_data, "\$data_${vnodot}_${p}_stats with candlesticks $colorstr linewidth 2 notitle \"\"";
    $color = [ map +( $color->[$_] + $stepcolor->[$_] ), (0, 1, 2) ];
  }
}

push @plot_data, "2 with lines lt 1 dashtype 2 title \"Measurement instability\"";

say PLOT "plot ", join ", ", @plot_data;
close PLOT;


