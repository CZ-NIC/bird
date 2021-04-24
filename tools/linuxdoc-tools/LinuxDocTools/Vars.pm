#
#  Vars.pm
#
#  $Id: Vars.pm,v 1.1.1.1 2001/05/24 15:57:41 sano Exp $
#
#  Shared variables.
#
#  © Copyright 1996, 1997, Cees de Groot
#
package LinuxDocTools::Vars;
use strict;

use Exporter;

use vars qw($VERSION @ISA @EXPORT);
@ISA = qw(Exporter);
@EXPORT = qw(%Formats $global %FmtList);
$VERSION = sprintf("%d.%02d", q$Revision: 1.1.1.1 $ =~ /(\d+)\.(\d+)/);

use vars @EXPORT;

1;
