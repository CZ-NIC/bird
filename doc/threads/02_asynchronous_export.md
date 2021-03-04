# BIRD Journey to Threads. Chapter 2: Asynchronous route export

Route export is a core algorithm of BIRD. This chapter covers how we are making
this procedure multithreaded. Desired outcomes are mostly lower latency of
route import, flap dampening and also faster route processing in large
configurations with lots of export from one table.

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. We're doing a significant amount of
BIRD's internal structure changes to make it possible to run in multiple
threads in parallel.

## How routes are propagated through BIRD

In the [previous chapter](https://en.blog.nic.cz/2021/03/23/bird-journey-to-threads-chapter-1-the-route-and-its-attributes/), you could learn how the route import works. We should
now extend that process by the route export.

1. (In protocol code.) Create the route itself and propagate it through the
   right channel by calling `rte_update`.
2. The channel runs its import filter.
3. New best route is selected.
4. For each channel:
    1. The channel runs its preexport hook and export filter.
    2. (Optionally.) The channel merges the nexthops to create an ECMP route.
    3. The channel calls the protocol's `rt_notify` hook.
5. After all exports are finished, the `rte_update` call finally returns and
   the source protocol may do anything else.

Let's imagine that all the protocols are running in parallel. There are two
protocols with a route prepared to import. One of those wins the table lock,
does the import and then the export touches the other protocol which must
either:

* store the route export until it finishes its own imports, or
* have independent import and export parts.

Both of these conditions are infeasible for common use. Implementing them would
make protocols much more complicated with lots of new code to test and release
at once and also quite a lot of corner cases. Risk of deadlocks is also worth
mentioning.

## Asynchronous route export

We decided to make it easier for protocols and decouple the import and export
this way:

1. The import is done.
2. Best route is selected.
3. Resulting changes are stored.

Then, after the importing protocol returns, the exports are processed for each
exporting channel. In future, this will be possible in parallel: Some protocols
may process the export directly after it is stored, other protocols will wait
until they finish another job.

This eliminates the risk of deadlocks and all protocols' `rt_notify` hooks can
rely on their independence. There is only one question. How to store the changes?

## Route export modes

To find a good data structure for route export storage, we shall first know the
readers. The exporters may request different modes of route export.

### Export everything

This is the most simple route export mode. The exporter wants to know about all
the routes as they're changing. We therefore simply store the old route until
the change is fully exported and then we free the old stored route.

To manage this, we can simply queue the changes one after another and postpone 
old route cleanup after all channels have exported the change. The queue member
would look like this:

```
struct {
  struct rte_storage *new;
  struct rte_storage *old;
};
```

### Export best

This is another simple route export mode. We check whether the best route has
changed; if not, no export happens. Otherwise, the export is propagated as the
old best route changing to the new best route. 

To manage this, we could use the queue from the previous point by adding new
best and old best pointers. It is guaranteed that both the old best and new
best pointers are always valid in time of export as all the changes in them
must be stored in future changes which have not been exported yet by this
channel and therefore not freed yet.

```
struct {
  struct rte_storage *new;
  struct rte_storage *new_best;
  struct rte_storage *old;
  struct rte_storage *old_best;
};
```

Anyway, we're getting to the complicated export modes where this simple
structure is simply not enough.

### Export merged

Here we're getting to some kind of problems. The exporting channel requests not
only the best route but also all routes that are good enough to be considered
ECMP-eligible (we call these routes *mergable*). The export is then just one
route with just the nexthops merged.  Export filters are executed before
merging and if the best route is rejected, nothing is exported at all.

To achieve this, we have to re-evaluate export filters any time the best route
or any mergable route changes. Until now, the export could just do what it wanted
as there was only one thread working. To change this, we need to access the
whole route list and process it.

### Export first accepted

In this mode, the channel runs export filters on a sorted list of routes, best first.
If the best route gets rejected, it asks for the next one until it finds an
acceptable route or exhausts the list. This export mode requires a sorted table.
BIRD users will know this export mode as `secondary` in BGP.

For now, BIRD stores two bits per route for each channel. The *export bit* is set
if the route has been really exported to that channel. The *reject bit* is set
if the route was rejected by the export filter.

When processing a route change for accepted, the algorithm first checks the
export bit for the old route. If this bit is set, the old route is that one
exported so we have to find the right one to export. Therefore the sorted route
list is walked best to worst to find a new route to export, using the reject
bit to evaluate only routes which weren't rejected in previous runs of this
algorithm.

If the old route bit is not set, the algorithm walks the sorted route list best
to worst, checking the position of new route with respect to the exported route.
If the new route is worse, nothing happens, otherwise the new route is sent to
filters and finally exported if passes.

### Export by feed

To resolve problems arising from previous two export modes (merged and first accepted),
we introduce a way to process a whole route list without locking the table
while export filters are running. To achieve this, we follow this algorithm:

1. The exporting channel sees a pending export.
2. *The table is locked.*
3. The channel counts all the routes for the given destination.
4. The channel stores pointers to that routes to a local array.
5. *The table is unlocked.*
6. The channel processes the local array of route pointers.
7. The pending export is marked as processed by this channel.

After unlocking the table, the pointed-to routes are implicitly guarded by the
sole fact that the pending export has not yet been processed by all channels
and the cleanup routine never frees any resource related to a pending export.

## Pending export data structure

As the two complicated export modes use the export-by-feed algorithm, the
pending export data structure may be quite minimalistic.

```
struct rt_pending_export {
  struct rt_pending_export * _Atomic next;	/* Next export for the same destination */
  struct rte_storage *new;			/* New route */
  struct rte_storage *new_best;			/* New best route in unsorted table */
  struct rte_storage *old;			/* Old route */
  struct rte_storage *old_best;			/* Old best route in unsorted table */
  _Atomic u64 seq;				/* Sequential ID (table-local) of the pending export */
};
```

To allow for squashing outdated pending exports (e.g. for flap dampening
purposes), there is a `next` pointer to the next export for the same
destination. This is also needed for the export-by-feed algorithm: if there are
several exports for one net at once, all of them are processed by one
export-by-feed automatically marked as done.

We should also add several items into `struct channel`.

```
  struct coroutine *export_coro;			/* Exporter and feeder coroutine */
  struct bsem *export_sem;				/* Exporter and feeder semaphore */
  struct rt_pending_export * _Atomic last_export;	/* Last export processed */
  struct bmap export_seen_map;				/* Keeps track which exports were already processed */
  u64 flush_seq;					/* Table export seq when the channel announced flushing */
```

To run the exports in parallel, `export_coro` is run and `export_sem` is
used for signalling new exports to it. The exporter coroutine also marks all
seen sequential IDs in its `export_seen_map` to make it possible to skip over
them if seen again.

There is also a table cleaner routine
(see [previous chapter](https://en.blog.nic.cz/2021/03/23/bird-journey-to-threads-chapter-1-the-route-and-its-attributes/))
which must cleanup also the pending exports after all the channels are finished with them.
To signal that, there is `last_export` working as a release point: the channel
guarantees that it doesn't touch the pointed-to pending export, nor any data
from it.

The last tricky point is channel flushing. When any channel stops, all its
routes are automatically freed and withdrawals are exported if appropriate.
Until now, the routes could be flushed synchronously, anyway now flush has
several phases:

1. Flush started (here the channel stores the `seq` of last current pending export).
2. All routes unlinked yet not freed, withdrawals pending.
3. Pending withdrawals processed and cleaned up. Channel may safely stop and free its structures.

Finally, some additional information has to be stored in tables:

```
  _Atomic byte export_used;				/* Export journal cleanup scheduled */ \
  struct rt_pending_export * _Atomic first_export;	/* First export to announce */ \
  byte export_scheduled;				/* Export is scheduled */
  list pending_exports;					/* List of packed struct rt_pending_export */
  struct fib export_fib;				/* Auxiliary fib for storing pending exports */
  u64 next_export_seq;					/* The next export will have this ID */
```

The exports are:
1. Assigned the `next_export_seq` sequential ID, incrementing this item by one.
2. Put into `pending_exports` and `export_fib` for both sequential and by-destination access.
3. Signalled by setting `export_scheduled` and also `first_export` if not `NULL`.

After processing several exports, `export_used` is set and route table maintenance
coroutine is woken up to possibly do cleanup.

The `struct rt_pending_export` seems to be best allocated by requesting a whole
memory page, containing a common list node, a simple header and packed all the
structures in the rest of the page. This may save a significant amount of memory.
In case of congestion, there will be lots of exports and every spare kilobyte
counts. If BIRD is almost idle, the optimization does nothing on the overall performance.

## Export algorithm

As we have explained at the beginning, the current export algorithm is
table-driven. The table walks the channel list and propagates the update.
The now export algorithm is channel-driven. The table just indicates that it
has something new in export queue and the channel decides what to do with that and when.

### Pushing an export

When a table has something to export, it enqueues an appropriate instance of
`struct rt_pending_export`. Then it pings its maintenance coroutine
(`rt_event`) to notify the exporting channels about a new route. This coroutine
runs with only the table locked so the protocol may e.g. prepare the next route inbetween.
The maintenance coroutine, when it wakes up, walks the list of channels and
wakes their export coroutines.

These two levels of asynchronicity are here for two reasons.

1. There may be lots of channels (hundreds of them) and we don't want to
   inefficiently iterate the list for each export.
2. The notification is going to wait until the route author finishes, hopefully
   importing more routes and therefore allowing more exports to be processed at once.

The table also stores the first and last exports for every destination. These
come handy mostly for cleanup purposes and for channel feeding.

### Processing an export

After these two pings, the channel finally knows that there is an export pending.
The channel checks whether there is a `last_export` stored. If yes, it proceeds
with the next one, otherwise it takes `first_export` from the table (which is
atomic for this reason).

1. The channel checks its `export_seen_map` whether this export has been
   already processed. If so, it skips to the next export. No action is needed.
2. The export chain is scanned for the current first and last export. This is
   done by following the `next` pointer in the exports as accessing the
   auxiliary export fib needs locking.
3. In the best-only and all-routes export mode, the changes are processed
   without further table locking.
4. If export-by-feed is used, the current state of routes in table are fetched.
   Then the table is unlocked and the changes are processed without further locking.
5. All processed exports are marked as seen.
6. The channel stores the `last_export` and returns to beginning.to wait for next export.

## The full route life-cycle

Until now, we're always assuming that the channels *just exist*. In real life,
any channel may go up or down and we must handle it, flushing the routes
appropriately and freeing all the memory just in time to avoid both
use-after-free and memory leaks. It should be noted here explicitly that BIRD
is written in C which has no garbage collector or other modern features alike.

### Protocols and channels as viewed from a route

BIRD consists effectively of protocols and tables. **Protocols** are active parts,
kind-of subprocesses manipulating routes and other data. **Tables** are passive,
serving as a database of routes. To connect a protocol to a table, a
**channel** is created.

Every route has its `sender` storing the channel which has put the route into
the current table. This comes handy when the channel goes down to know which
routes to flush.

Every route also has its `src`, a route source allocated by the protocol which
originated it first. This is kept when a route is passed through a *pipe*.

Both `src` and `sender` must point to active protocols and channels as inactive
protocols and channels may be deleted in any time.

### Protocol and channel lifecycle

In the beginning, all channels and protocols are down. Until they fully start,
no route from them is allowed to any table. When the protocol and channel is up,
they may originate routes freely. However, the transitions are worth mentioning.

### Channel startup and feed

When protocols and channels start, they need to get the current state of the
appropriate table. Therefore, after a protocol and channel start, also the
export-feed coroutine is initiated.

Tables can contain millions of routes. It may lead to long import latency if a channel
was feeding itself in one step. The table structure is (at least for now) too
complicated to be implemented as lockless, thus even read access needs locking.
To mitigate this, the feeds are split to allow for regular route propagation
with a reasonable latency.

When the exports were synchronous, we simply didn't care and just announced the
exports to the channels from the time they started feeding. When making exports
asynchronous, it was crucial to avoid most of the possible race conditions
which could arise from simultaneous feed and export. As the feeder routines had
to be rewritten, it was a good opportunity to make this precise.

Therefore, when a channel goes up, it also starts exports:

1. Start the feed-export coroutine.
2. *Lock the table.*
3. Store the last export in queue.
4. Read a limited number of routes to local memory together with their pending exports.
5. If there are some routes to process:
   1. *Unlock the table.*
   2. Process the loaded routes.
   3. Set the appropriate pending exports as seen.
   4. *Lock the table*
   5. Go to 4. to continue feeding.
6. If there was a last export stored, load the next one to be processed. Otherwise take the table's `first_export`.
7. *Unlock the table.*
8. Run the exporter loop.

*Note: There are some nuances not mentioned here how to do things in right
order to avoid missing some events while changing state. Precise description
would be too detailed for this text.*

When the feeder loop finishes, it continues smoothly to process all the exports
that have been queued while the feed was running. Step 5.3 ensures that already
seen exports are skipped, steps 3 and 6 ensure that no export is missed.

### Channel flush

Protocols and channels need to stop for a handful of reasons, All of these
cases follow the same routine.

1. (Maybe.) The protocol requests to go down or restart.
2. The channel requests to go down or restart.
3. The channel requests to stop export.
4. In the feed-export coroutine:
   1. At a designated cancellation point, check cancellation.
   2. Clean up local data.
   3. *Lock main BIRD context locked*
   4. If shutdown requested, switch the channel to *flushing* state and request table maintenance.
5. In the table maintenance coroutine:
   1. Walk across all channels and check them for *flushing* state.
   2. Walk across the table (split to allow for low latency updates) and
      generate a withdrawal for each route sent by the flushing channels.
   3. Wait until all the withdrawals are processed.
   4. Mark the flushing channels as *down* and eventually proceed to the protocol shutdown or restart.

There is also a separate routine that handles bulk cleanup of `src`'s which
contain a pointer to the originating protocol. This routine may get reworked in
future, yet for now it is good enough.

### Route export cleanup

Last but not least is the export cleanup routine. Until now, the withdrawn
routes were exported synchronously and freed directly after the import was
done. This is not possible anymore. The export is stored and the import returns
to let the importing protocol continue its work. We therefore need a routine to
cleanup the withdrawn routes and also the processed exports.

First of all, this routine refuses to cleanup when any export is feeding or
shutting down. This may change in future, anyway for now we aren't sure about
possible race conditions.

Anyway, when all the exports are in a steady state, the routine works as follows:

1. Walk the active exports and find a minimum (oldest export) between their `last_export` values.
2. If there is nothing to clear between the actual oldest export and channels' oldest export, do nothing.
3. Find the table's new `first_export` and set it. Now there is nobody pointing to the old exports.
4. Free the withdrawn routes.
5. Free the old exports, removing them also from the first-last list of exports for the same destination.

## Results of these changes

This step is a first major step to move forward. Using just this version may be
still as slow as the single-threaded version, at least if your export filters are trivial.
Anyway, the main purpose of this step is not an immediate speedup. It is more
of a base for the next steps:

* Unlocking of pipes should enable parallel execution of all the filters on
  pipes, limited solely by the principle *one thread for every direction of
  pipe*.
* Conversion of CLI's `show route` to the new feed-export coroutines should
  enable faster table queries. Moreover, this approach will allow for
  better splitting of model and view in CLI with a good opportunity to
  implement more output formats, e.g. JSON.
* Unlocking of kernel route synchronization should fix latency issues induced
  by long-lasting kernel queries.
* Partial unlocking of BGP packet processing should finally allow for parallel
  execution in almost all phases of BGP route propagation.

The development is now being done mostly in the branch `alderney`. If you asked
why such strange branch names like `jersey`, `guernsey` and `alderney`, here is
a kind-of reason. Yes, these names could be named `mq-async-export`,
`mq-async-export-new`, `mq-async-export-new-new`, `mq-another-async-export` and
so on. That's so ugly, isn't it? 

Also why so many branches? The development process is quite messy. BIRD's code
heavily depends on single-threaded approach. This is exceptionally good for
performance, as long as you have one thread only. On the other hand, lots of
these assumptions are not documented so in many cases one desired
change yields a chain of other unforeseen changes which must precede. This brings
lots of backtracking, branch rebasing and other Git magic. There is always a
can of worms somewhere in the code.

*It's still a long road to the version 2.1. This series of texts should document
what is needed to be changed, why we do it and how. The
[previous chapter](https://en.blog.nic.cz/2021/03/23/bird-journey-to-threads-chapter-1-the-route-and-its-attributes/)
showed the necessary changes in route storage. In the next chapter, we're going
to describe how the coroutines are implemented and what kind of locking system
are we employing to prevent deadlocks. Stay tuned!*
