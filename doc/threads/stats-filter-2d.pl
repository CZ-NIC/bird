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
  $line =~ s/v2\.0\.8-[^;]+/sark/;
  $line =~ s/master;/v2.0.8;/;
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
my %peers;

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
  $peers{$data{$k}[0]{PEERS}}++;
  $output{$data{$k}[0]{VERSION}}{$data{$k}[0]{PEERS}}{$data{$k}[0]{TOTAL_ROUTES}} = { %avg };
}

(3 == scalar %vers) and $vers{sark} and $vers{bgp} and $vers{"v2.0.8"} or die "vers size is " . (scalar %vers) . ", items ", join ", ", keys %vers;

### Export the data ###

open PLOT, "|-", "gnuplot" or die $!;

say PLOT <<EOF;
set logscale

set term pdfcairo size 20cm,15cm

set xlabel "Total number of routes" offset 0,-1.5
set xrange [10000:1500000]
set xtics offset 0,-0.5
set xtics (10000,15000,30000,50000,100000,150000,300000,500000,1000000)

set ylabel "Time to converge (s)"
set yrange [0.5:10800]

set grid

set key right bottom

set output "$OUTPUT"
EOF

my @colors = (
  [ 1, 0.3, 0.3 ],
  [ 1, 0.7, 0 ],
  [ 0.3, 1, 0 ],
  [ 0, 1, 0.3 ],
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

    my $colorstr = sprintf "linecolor rgbcolor \"#%02x%02x%02x\"", map +( int($color->[$_] * 255 + 0.5)), (0, 1, 2);
    push @plot_data, "\$data_${vnodot}_${p} using 1:2 with lines $colorstr linewidth 2 title \"$v, $p peers\"";
    $color = [ map +( $color->[$_] + $stepcolor->[$_] ), (0, 1, 2) ];
  }
}

push @plot_data, "2 with lines lt 1 dashtype 2 title \"Measurement instability\"";

say PLOT "plot ", join ", ", @plot_data;
close PLOT;


