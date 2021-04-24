#
#  FixRef.pm
#
#  $Id: FixRef.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  Start conversion from parsed linuxdoc-sgml to html.
#        - Identify references and file count
#
#  Rules based on fixref.l
#
package LinuxDocTools::FixRef;

# Externally visible variables
$fixref = {};

# Initialize: set splitlevel before using rules
# Usage: &{$fixref->{init}}(<split level>);
	# 0 - super page mode
	# 1 - big page mode
	# 2 - small page mode
$fixref->{init} = sub {
    $splitlevel = shift;
};

# Outputs: Read after using rules
$fixref->{filenum} = 0;			# Count of files we will create
$fixref->{lrec} = {};			# label -> filenum

# Package variables
$chapter_mode = 0;	# <report> vs. <article>
$splitlevel = 0;	# See $fixref->{init} above;
			# Automatically reduced by 1 for chapter mode

# Finalize parsing
$fixref->{finish} = sub { };		# Do nothing when we're done

# Ruleset
$fixref->{rules} = {};			# Individual parsing rules
$fixref->{defaultrule} = sub { };	# If line does not match any rules

# Set the rules
# <@@ssect> - split file if necessary
$fixref->{rules}->{'^<@@ssect>.*$'} = sub { &splitfile(2); };

# <@@sect> - split file if necessary
$fixref->{rules}->{'^<@@sect>.*$'} = sub { &splitfile(1); };

# <@@chapt> - set chapter mode; reduce splitlevel if needed; split file
$fixref->{rules}->{'^<@@chapt>.*$'} = sub { 
    $splitlevel-- if (!$chapter_mode);
    $chapter_mode = 1; &splitfile(0);
};

# <@@label> - Identify label location
$fixref->{rules}->{'^<@@label>(.*)$'} = sub { 
    $fixref->{lrec}->{$1} = $fixref->{filenum};
};

#==============================
# Split the file (-split option; level in parentheses):
#  non-chapter mode: -0 -> don't split
#                    -1 -> split at sect (1)
#                    -2 -> split at sect (1) and ssect (2)
#  chapter mode: -0 -> split at chapt (0)
#                -1 -> split at chapt (0)
#                -2 -> split at chapt (0) and sect (1)
sub splitfile
{
    my ($level) = @_;
    if (($level == 0) || ($splitlevel >= $level)) {
        $fixref->{filenum}++;
    }
}

1;

