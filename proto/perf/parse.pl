#!/usr/bin/perl

use File::Temp ();

package row;

use Moose;

has 'exp' => ( is => 'ro', 'isa' => 'Num' );
has 'gen' => ( is => 'ro', 'isa' => 'Num' );
has 'temp' => ( is => 'ro', 'isa' => 'Num' );
has 'update' => ( is => 'ro', 'isa' => 'Num' );
has 'withdraw' => ( is => 'ro', 'isa' => 'Num' );

sub reduce {
  my $self = shift;

  my $N = 1 << $self->exp;
  return row->new(
    exp => $self->exp,
    gen => $self->gen / $N,
    temp => $self->temp / $N,
    update => $self->update / $N,
    withdraw => $self->withdraw / $N
  );
}

sub dump {
  my ($self, $fh) = @_;

  print $fh join ",", $self->exp, $self->gen, $self->temp, $self->update, $self->withdraw;
  print $fh "\n";
}

package results;

use Moose;

has 'name' => (
  is => 'ro',
  isa => 'Str',
  required => 1,
);

has 'date' => (
  is => 'ro',
  isa => 'Str',
  required => 1,
);

has 'reduced' => (
  is => 'ro',
  isa => 'Bool',
  default => 0,
);

has 'rows' => (
  is => 'ro',
  isa => 'ArrayRef[row]',
  default => sub { [] },
);

has 'stub' => (
  is => 'ro',
  isa => 'Str',
  lazy => 1,
  builder => '_build_stub',
);

sub _build_stub {
  my $self = shift;

  my $date = $self->date;
  my $name = $self->name;

  my $reduced = "-reduced" if $self->reduced;

  my $stub = $date . "-" . $name . $reduced;

  $stub =~ tr/a-zA-Z0-9_-/@/c;
  return $stub;
}

sub add {
  my $self = shift;
  push @{$self->rows}, row->new(@_);
}

sub reduce {
  my $self = shift;

  return $self if $self->reduced;

  return results->new(
    name => $self->name,
    date => $self->date,
    reduced => 1,
    rows => [
      map { $_->reduce } @{$self->rows}
    ],
  );
}

sub dump {
  my $self = shift;
  my $fn = $self->stub . ".csv";

  open my $CSV, ">", $fn;
  map {
    $_->dump($CSV);
    } @{$self->rows};

  close $CSV;
  return $fn;
}

sub draw {
  my $self = shift;

  my $csv = $self->dump();
  my $svg = $self->stub . ".svg";

  my $title = $self->name;
  $title =~ s/_/ /g;

  open PLOT, "|-", "gnuplot -p";
  print PLOT "set terminal svg;\n";
  print PLOT "set output '$svg';\n";
  print PLOT "set title '$title';\n";
  print PLOT "set datafile separator ',';\n";
  print PLOT "set jitter over 0.3 spread 0.3;\n";
  print PLOT "plot '$csv' using 1:2 title 'gen', '$csv' using 1:3 title 'temp', '$csv' using 1:4 title 'update', '$csv' using 1:5 title 'withdraw';\n";
  close PLOT;
}

package main;

my %results;
my @done;

while (<>) {
  if (m/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*?Perf (.+) starting$/) {
    my $date = $1;
    my $name = $2;
    die "Garbled input data" if exists $results{$name};
    $results{$name} = results->new(name => $name, date => $date);
    next;
  }

  if (m/Perf (.+) done with exp=(\d+)$/) {
    my $name = $1;
    die "Garbled input data" unless exists $results{$name};
    push @done, $results{$name};
    delete $results{$name};
    next;
  }

  my ($name, $exp, $gen, $temp, $update, $withdraw) = m/Perf (.+) exp=(\d+) times: gen=(\d+) temp=(\d+) update=(\d+) withdraw=(\d+)$/ or next;

  exists $results{$name} or die "Garbled input data";

  $results{$name}->add(exp => $exp, gen => $gen, temp => $temp, update => $update, withdraw => $withdraw);
}

scalar %results and die "Incomplete input data";

foreach my $res (@done) {
  $res->reduce->draw();
}
