# Migrating from BIRD 2 to BIRD 3

With proper multithreading, we had to change not only the internal architecture,
but also some user-visible behavior, mostly because these changes were needed
either for development, or the original features stopped making sense at all
with the new internal architecture.

We tried to keep these changes as small as possible but as this major upgrade is
a good opportunity to do backwards-incompatible changes, we obviously had to do
that to fix some historically inaccurate concepts.

## Threads

Number of working threads is now configured by `threads <num>;` on toplevel.
By default, this is 1, which actually means 2 running threads. The main one and
the worker one. When BFD is configured, you get another one for BFD.

Every instance of BGP, BFD, Pipe and RPKI gets its own *loop* which is a packed
unit transferrable between the working threads.

## Logging

Log files have a slightly different format, indicating by `[abcd]` the actual
thread logging the message. This enables the user to better comprehend what's
actually going on between interleaved messages from different threads,
especially when detailed route tracing is on.

There is also a new logging option, a fixed-size circular logfile. This is handy
if you need to switch on detailed tracing but you don't want to overfill your disk.
Also this option is by far the fastest one.

## Tables

It's now possible to set the `debug` option to trace events happening directly
inside the table.

Also settle timers were changed; there is a configurable idle-state timeout
before any route export is announced after import is done. This helps to
coalesce the routes on export and improves BIRD's overall performance.

There is also an explicit back-pressure feature, called cork, to avoid memory
bloating with route flaps. This feature basically forces the readers to flush
the table journal before more imports are added. Parameters of the cork are
configurable.

ROA settle timers were moved into channels.

## Channels

ROA settle timers are set separately per-channel now. Also by default, only
the possibly affected routes get autoreloaded, contrary to BIRD 2.

Export is now done by blocks which are by default quite large. This may hamper
responsiveness of single protocols and therefore cause other issues. With
complex export filters, you may want to drop this value from 16K down. But you
shouldn't have complex export filters anyway.

Export supports also `export in` form, allowing to export only subprefixes of
the given prefix. Experimental.

Reload of filters is now done by `reload filters` command, contrary to just `reload` in BIRD 2.

## Filters

We have removed the exception for `case` where multiple commands could be written
after the case label without braces. This caused unneeded complexity in the parser.

## Route attributes

All protocol attributes have been renamed in CLI to align with the filter language tokens.

Output of `show route all` also shows more information, including some internal
data for easier debugging and route tracing.

The `onlink` route attribute has been temporarily disabled until we find out
how to implement it properly.

The `scope` route attribute has been removed. Use custom route attributes instead.

## Protocols common

There is now a guard against too frequent restarts due to limits, called
`restart time`, set by default to 5 seconds. To disable, set this to 1 us.

## Pipe

It's now impossible to check immediately whether the route has entered a pipe
loop. Instead of that, every Pipe pass increases the route's `generation`
internal attribute, and when it is too high, the route is discarded.

## BGP

The export table now shows the state immediately before sending on the wire,
thus without custom attributes and after all updates done by BGP. This should
help with performance a little, while also being more accurate.

When changing the export filter the export table is used in BIRD 3, but ignored in BIRD 2.
This means that BIRD 2 sends all routes again, regardless of having export table enabled. 
BIRD 3 is smarter and uses the export table to filter out routes when export filter has changed.
