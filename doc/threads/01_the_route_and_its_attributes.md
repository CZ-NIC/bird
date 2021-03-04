# BIRD Journey to Threads. Chapter 1: The Route and its Attributes

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. We're doing a significant amount of
BIRD's internal structure changes to make it possible to run in multiple
threads in parallel. This chapter covers necessary changes of data structures
which store every single routing data.

*If you want to see the changes in code, look (basically) into the
`route-storage-updates` branch. Not all of them are already implemented, anyway
most of them are pretty finished as of end of March, 2021.*

## How routes are stored

BIRD routing table is just a hierarchical noSQL database. On top level, the
routes are keyed by their destination, called *net*. Due to historic reasons,
the *net* is not only *IPv4 prefix*, *IPv6 prefix*, *IPv4 VPN prefix* etc.,
but also *MPLS label*, *ROA information* or *BGP Flowspec record*. As there may
be several routes for each *net*, an obligatory part of the key is *src* aka.
*route source*. The route source is a tuple of the originating protocol
instance and a 32-bit unsigned integer. If a protocol wants to withdraw a route,
it is enough and necessary to have the *net* and *src* to identify what route
is to be withdrawn.

The route itself consists of (basically) a list of key-value records, with
value types ranging from a 16-bit unsigned integer for preference to a complex
BGP path structure. The keys are pre-defined by protocols (e.g. BGP path or
OSPF metrics), or by BIRD core itself (preference, route gateway).
Finally, the user can declare their own attribute keys using the keyword
`attribute` in config.

## Attribute list implementation

Currently, there are three layers of route attributes. We call them *route*
(*rte*), *attributes* (*rta*) and *extended attributes* (*ea*, *eattr*).

The first layer, *rte*, contains the *net* pointer, several fixed-size route
attributes (mostly preference and protocol-specific metrics), flags, lastmod
time and a pointer to *rta*.

The second layer, *rta*, contains the *src* (a pointer to a singleton instance),
a route gateway, several other fixed-size route attributes and a pointer to
*ea* list.

The third layer, *ea* list, is a variable-length list of key-value attributes,
containing all the remaining route attributes.

Distribution of the route attributes between the attribute layers is somehow
arbitrary. Mostly, in the first and second layer, there are attributes that
were thought to be accessed frequently (e.g. in best route selection) and
filled in in most routes, while the third layer is for infrequently used
and/or infrequently accessed route attributes.

## Attribute list deduplication

When protocols originate routes, there are commonly more routes with the
same attribute list. BIRD could ignore this fact, anyway if you have several
tables connected with pipes, it is more memory-efficient to store the same
attribute lists only once.

Therefore, the two lower layers (*rta* and *ea*) are hashed and stored in a 
BIRD-global database. Routes (*rte*) contain a pointer to *rta* in this
database, maintaining a use-count of each *rta*. Attributes (*rta*) contain
a pointer to normalized (sorted by numerical key ID) *ea*.

## Attribute list rework

The first thing to change is the distribution of route attributes between
attribute list layers. We decided to make the first layer (*rte*) only the key
and other per-record internal technical information. Therefore we move *src* to
*rte* and preference to *rta* (beside other things). *This is already done.*

We also found out that the nexthop (gateway), originally one single IP address
and an interface, has evolved to a complex attribute with several sub-attributes;
not only considering multipath routing but also MPLS stacks and other per-route
attributes. This has led to a too complex data structure holding the nexthop set.

We decided finally to squash *rta* and *ea* to one type of data structure,
allowing for completely dynamic route attribute lists. This is also supported
by adding other *net* types (BGP FlowSpec or ROA) where lots of the fields make
no sense at all, yet we still want to use the same data structures and implementation
as we don't like duplicating code. *Multithreading doesn't depend on this change,
anyway this change is going to happen soon anyway.*

## Route storage

The process of route import from protocol into a table can be divided into several phases:

1. (In protocol code.) Create the route itself (typically from
   protocol-internal data) and choose the right channel to use.
2. (In protocol code.) Create the *rta* and *ea* and obtain an appropriate
   hashed pointer. Allocate the *rte* structure and fill it in. 
3. (Optionally.) Store the route to the *import table*.
4. Run filters. If reject, free everything.
5. Check whether this is a real change (it may be idempotent). If not, free everything and do nothing more.
6. Run the best route selection algorithm.
7. Execute exports if needed.

We found out that the *rte* structure allocation is done too early. BIRD uses
global optimized allocators for fixed-size blocks (which *rte* is) to reduce
its memory footprint, therefore the allocation of *rte* structure would be a
synchronization point in multithreaded environment.

The common code is also much more complicated when we have to track whether the
current *rte* has to be freed or not. This is more a problem in export than in
import as the export filter can also change the route (and therefore allocate
another *rte*). The changed route must be therefore freed after use. All the
route changing code must also track whether this route is writable or
read-only.

We therefore introduce a variant of *rte* called *rte_storage*. Both of these
hold the same, the layer-1 route information (destination, author, cached
attribute pointer, flags etc.), anyway *rte* is always local and *rte_storage*
is intended to be put in global data structures.

This change allows us to remove lots of the code which only tracks whether any
*rte* is to be freed as *rte*'s are almost always allocated on-stack, naturally
limiting their lifetime. If not on-stack, it's the responsibility of the owner
to free the *rte* after import is done.

This change also removes the need for *rte* allocation in protocol code and
also *rta* can be safely allocated on-stack. As a result, protocols can simply
allocate all the data on stack, call the update routine and the common code in
BIRD's *nest* does all the storage for them.

Allocating *rta* on-stack is however not required. BGP and OSPF use this to
import several routes with the same attribute list. In BGP, this is due to the
format of BGP update messages containing first the attributes and then the
destinations (BGP NLRI's). In OSPF, in addition to *rta* deduplication, it is
also presumed that no import filter (or at most some trivial changes) is applied
as OSPF would typically not work well when filtered.

*This change is already done.*

## Route cleanup and table maintenance

In some cases, the route update is not originated by a protocol/channel code.
When the channel shuts down, all routes originated by that channel are simply
cleaned up. Also routes with recursive routes may get changed without import,
simply by changing the IGP route. 

This is currently done by a `rt_event` (see `nest/rt-table.c` for source code)
which is to be converted to a parallel thread, running when nobody imports any
route. *This change is freshly done in branch `guernsey`.*

## Parallel protocol execution

The long-term goal of these reworks is to allow for completely independent
execution of all the protocols. Typically, there is no direct interaction
between protocols; everything is done thought BIRD's *nest*. Protocols should
therefore run in parallel in future and wait/lock only when something is needed
to do externally.

We also aim for a clean and documented protocol API.

*It's still a long road to the version 2.1. This series of texts should document
what is needed to be changed, why we do it and how. In the next chapter, we're
going to describe how the route is exported from table to protocols and how this
process is changing. Stay tuned!*
