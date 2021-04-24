# -*- perl -*-
#
# Copyright (C) 1996 Ken MacLeod
# See the file COPYING for distribution terms.
#
# This file is preprocessed during the build to fix-up the references
# in `sdata_dirs'.
#
# $Id: EntityMap.pm.in,v 1.1.1.1 2001/05/24 15:57:40 sano Exp $
#

package Text::EntityMap;

use strict;

=head1 NAME

Text::EntityMap - map character entities to output formats

=head1 SYNOPSIS

use Text::EntityMap;

$tex_iso_lat1 = Text::EntityMap->load ("ISOlat1.2tex");
$tex_iso_lat2 = Text::EntityMap->load ("ISOlat2.2tex");
$ent_group = Text::EntityMap->group ($tex_iso_lat1, $tex_iso_lat2);

$ent_group->lookup ('[copy  ]');

@dirs = Text::EntityMap->sdata_dirs ();

=head1 DESCRIPTION

Text::EntityMap is a module that can look-up an output-format
equivalent for special character or other entities.  This was inspired
by SGML character entities but can be used in any scenario where
output formatting codes are different for special characters.

The C<load()> function takes a file name of a mapping table and
returns an Text::EntityMap object.

The C<group()> function takes a ordered list of Text::EntityMap and
returns an Text::EntityMapGroup object.  Looking up entities in a
group object returns the entity replacement returned by the first
EntityMap object.  This can be used both to group sets of mapping
files into one object as well as overriding entity replacements.  A
EntityMapGroup may contain other EntityMapGroup's.

The C<lookup()> function can be used with either a EntityMap or
EntityMapGroup object.  It takes an entity name and returns the
output-format equivalent.

C<sdata_dirs()> returns an array containing the local site directory
and ``this'' version of EntityMap's installed directory that contain
the entity maps.  Callers can use these paths when looking for tables
to pass to C<load()>.

=head1 AUTHOR

Ken MacLeod E<lt>ken@bitsko.slc.ut.usE<gt>

=cut

sub sdata_dirs {
    return ("/usr/share/entity-map", "/usr/share/entity-map/0.1.0");
}

sub load {
    my ($type, $file_name) = @_;

    my ($self) = {};
    bless ($self, $type);

    open (FILE, "$file_name")
	|| die "Can't open \`$file_name' for reading: $!\n";
    while (<FILE>) {
	chop;
	m/(^[^\t]+)\t(.*)/;
	$self->{"$1"} = $2;
    }
    close (FILE);

    return ($self);
}

sub group {
    my ($type) = shift;

    my ($self) = [{}, @_];
    bless ($self, 'Text::EntityMapGroup');

    return ($self);
}

sub lookup {
    my ($self, $entity) = @_;

    return ($self->{$entity});
}

package Text::EntityMapGroup;

sub lookup {
    my ($self, $entity) = @_;

    my ($replacement) = $self->[0]{$entity};
    return $replacement if defined $replacement;

    my ($ii);
    for ($ii = 1; $ii <= $#{$self}; $ii ++) {
	$replacement = $self->[$ii]->lookup($entity);
	if (defined $replacement) {
	    $self->[0]{$entity} = $replacement;
	    return ($replacement);
	}
    }

    return (undef);
}

1;
