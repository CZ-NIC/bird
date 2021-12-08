# BIRD Journey to Threads. Chapter 3: Parallel execution and message passing.

Parallel execution in BIRD uses an underlying mechanism of dedicated IO loops
and hierarchical locks. The original event scheduling module has been converted
to do message passing in multithreaded environment. These mechanisms are
crucial for understanding what happens inside BIRD and how the protocol API changes.

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. We're doing a significant amount of
BIRD's internal structure changes to make it run in multiple threads in parallel.

## Locking and deadlock prevention

Most of BIRD data structures and algorithms are thread-unsafe and not even
reentrant. Checking and possibly updating all of these would take an
unreasonable amount of time, thus the multithreaded version uses standard mutexes
to lock all the parts which have not been checked and updated yet.

The authors of original BIRD concepts wisely chose a highly modular structure
which allows to create a hierarchy for locks. The main chokepoint was between
protocols and tables which has been solved by implementing asynchronous exports
as described in the [previous chapter](https://en.blog.nic.cz/2021/06/14/bird-journey-to-threads-chapter-2-asynchronous-route-export/).

Locks in BIRD (called domains, as they always lock some defined part of BIRD)
are partially ordered. Every *domain* has its *type* and all threads are
strictly required to lock the domains in the order of their respective types.
The full order is defined in `lib/locking.h`. It's forbidden to lock more than
one domain of a type (these domains are uncomparable) and recursive locking as well.

The locking hiearchy is (as of December 2021) like this:

1. The BIRD Lock (for everything not yet checked and/or updated)
2. Protocols (as of December 2021, it is BFD, RPKI and Pipe)
3. Routing tables
4. Global route attribute cache
5. Message passing
6. Internals

There are heavy checks to ensure proper locking and to help debugging any
problem when any code violates the hierarchy rules. This impedes performance
depending on how much that domain is contended and in some cases I have already
implemented lockless (or partially lockless) data structures to overcome this.

You may ask, why are these heavy checks then employed in production builds?
Risks arising from dropping some locking checks include:

* deadlocks; these are deadly in BIRD anyway so it should just fail with a meaningful message, or
* data corruption; it either kills BIRD anyway, or it results into a slow and vicious death,
  leaving undebuggable corefiles behind.

To be honest, I believe in principles like "there is also one more bug somewhere"
and I just don't trust my future self or anybody else to write bugless code when
it comes to proper locking. I believe that if a lock becomes a bottle-neck,
then we should think about what is locked inside and how to optimize that, instead
of dropping thorough consistency checks.

## IO Loop

There has been a protocol, BFD, running in its own thread since 2013. This
separation has a good reason; it needs low latency and the main BIRD loop just
walks round-robin around all the available sockets which may last for a long
time. BFD had its own IO loop implementation and simple message passing
routines. This code could be easily updated for general use so I did it.

To understand the internal principles, we should say that in the `master`
branch, there is a big loop centered around a `poll()` call, dispatching and
executing everything as needed. There are several means how to get something dispatched from the main loop.

1. Requesting to read from a socket makes the main loop call your hook when there is some data received.
   The same happens when a socket refuses to write data. Then the data is buffered and you are called when
   the buffer is free. There is also a third callback, an error hook, for obvious reasons.

2. Requesting to be called back after a given amount of time. The callback may
   be delayed by any amount of time, anyway when it exceeds 5 seconds (default,
   configurable) at least the user gets a warning. This is called *timer*.

3. Requesting to be called back when possible. This is useful to run anything
   not reentrant which might mess with the caller's data, e.g. when a protocol
   decides to shutdown due to some inconsistency in received data. This is called *event*.

4. Requesting to do some work when possible. These are also events, there is only
   a difference where this event is enqueued; in the main loop, there is a
   special *work queue* with an execution limit, allowing sockets and timers to be
   handled with a reasonable latency while still doing all the work needed.

All these, sockets, timers and events, are tightly bound to some domain.
Sockets typically belong to a protocol, timers and events to a protocol or table.
With the modular structure of BIRD, the easy and convenient approach to multithreading
is to get more IO loops bound to specific domains, running their events, timers and
socket hooks in their threads.

## Message passing and loop entering

To request some work in another module, the standard way is to pass a message.
For this purpose, events have been modified to be sent to a given loop without
locking that loop's domain. In fact, every event queue has its own lock with a
low priority, allowing to pass messages from almost any part of BIRD, and also
an assigned loop which executes the events enqueued. When a message is passed
to a queue executed by another loop, that target loop must be woken up so we
must know what loop to wake up to avoid unnecessary delays.

The other way is faster but not always possible. When the target loop domain
may be locked from the original loop domain, we may simply *enter the target loop*,
do the work and then *leave the loop*. Route import uses this approach to
directly update the best route in the target table. In the other direction,
loop entering is not possible and events must be used to pass messages.

Asynchronous message passing is expensive. It involves sending a byte to a pipe
to wakeup a loop from `poll` to execute the message. If we had to send a ping
for every route we import to every channel to export it, we'd spend more time
pinging than computing the best route. The route update routines therefore
employ a double-indirect delayed route announcement:

1. When a channel imports a route by entering a loop, it sends an event to its
   own loop (no ping needed in such case). This operation is idempotent, thus
   for several routes, only one event is enqueued.
2. After all packet parsing is done, the channel import announcement event is
   executed, sending another event to the table's loop. There may have been
   multiple imports in the same time but the exports have to get a ping just once.
3. The table's announcement event is executed from its loop, enqueuing export
   events for all connected channels, finally initiating route exports.

This may seem overly complicated, yet it also allows the incoming changes to
settle down before exports are finished, reducing also cache invalidation
between importing and exporting threads.

## Choosing the right locking order

When considering the locking order of protocols and route tables, the answer was quite easy.
If route tables could enter protocol loops, they would have to either directly
execute protocol code, one export after another, or send whole routes by messages.
Setting this other way around (protocol entering route tables), protocols do
everything on their time, minimizing table time. Tables are contention points.

The third major lock level is The BIRD Lock, containing virtually everything
else. It is also established that BFD is after The BIRD Lock, as BFD is
low-latency and can't wait until The BIRD gets unlocked. Thus it would be
convenient to have all protocols on the same level, getting The BIRD Lock on top.

The BIRD Lock also runs CLI, reconfiguration and other high-level tasks,
requiring access to everything. Having The BIRD Lock anywhere else, these
high-level tasks, scattered all around BIRD source code, would have to be split
out to some super-loop.

## Route tables

BFD could be split out thanks to its special nature. There are no BFD routes,
therefore no route tables are accessed. To split out any other protocol, we
need the protocol to be able to directly access routing tables. Therefore
route tables have to be split out first, to make space for protocols to go
between tables and The BIRD main loop.

Route tables are primarily data structures, yet they have their maintenance
routines. Their purpose is (among others) to cleanup export buffers, update
recursive routes and delete obsolete routes. This all may take lots of time
occasionally so it makes sense to have a dedicated thread for these.

In previous versions, I had a special type of event loop based on semaphores,
contrary to the loop originating in BFD, based on `poll`. This was
unnecessarily complicated, thus I rewrote that finally to use the universal IO
loop, just with no sockets at all.

There are some drawbacks of this, notably the number of filedescriptors BIRD
now uses. The user should also check the maximum limit on threads per process.

This change also means that imports and exports are started and stopped
asynchronously. Stopping an import needs to wait until all its routes are gone.
This induced some changes in the protocol state machine.

## Protocols

After tables were running in their own loops, the simplest protocol to split
out was Pipe. There are still no sockets, just events. This also means that
every single filter assigned to a pipe is run in its own thread, not blocking
others. (To be precise, both directions of a pipe share the same thread.)

When RPKI is in use, we want it to load the ROAs as soon as possible. Its table
is independent and the protocol itself is so simple that it could be put into
its own thread easily.

Other protocols are pending (Kernel) or in progress (BGP).

I tried to make the conversion also as easy as possible, implementing most of
the code in the generic functions in `nest/proto.c`. There are some
synchronization points in the protocol state machine; we can't simply delete
all protocol data when there is another thread running. Together with the
asynchronous import/export stopping, it is quite messy and it might need some
future cleanup. Anyway, moving a protocol to its own thread should be now as simple
as setting its locking level in its `config.Y` file and stopping all timers
before shutting down.
(See commits `4f3fa1623f66acd24c227cf0cc5a4af2f5133b6c`
and `3fd1f46184aa74d8ab7ed65c9ab6954f7e49d309`.)

## Cork

In the old versions with synchronous route propagation, all the buffering
happened after exporting routes to BGP. When a packet arrived, all the work was
done in BGP receive hook – parsing, importing into a table, running all the
filters and possibly sending to the peers. No more routes until the previous
was done. This doesn't work any more.

Route table import now returns immediately after inserting the route into a
table, creating a buffer there. These buffers have to be processed by other protocols'
export events, typically queued in the *global work queue* to be limited for lower latency.
There is therefore no inherent limit for table export buffers which may lead
(and occasionally leads) to memory bloating. This is even worse in configurations with pipes,
as these multiply the exports by propagating them all the way down to other tables.

There is therefore a cork to make this stop. Every table is checking how many
exports it has pending, and when adding a new route, it may apply a cork,
saying simply "please stop the flow for a while". When the exports are then processed, it uncorks.

On the other side, there may be events and sockets with a cork assigned. When
trying to enqueue an event and the cork is applied, the event is instead put
into the cork's queue and released only when the cork is released. In case of
sockets, when `poll` arguments are recalculated, the corked socket is not
checked for received packets, effectively keeping them in the TCP queue and
slowing down the flow.

Both events and sockets have some delay before they get to the cork. This is
intentional; the purpose of cork is to slow down and allow for exports.

The cork implementation is probably due to some future changes after BGP gets
split out of the main loop, depending on how it is going to perform. I suppose
that the best way should be to implement a proper table API to allow for
explicit backpressure on both sides:

* (table to protocol) please do not import
* (table to protocol) you may resume imports
* (protocol to table) not processing any exports
* (protocol to table) resuming export processing

Anyway, for now it is good enough as it is.

*It's still a long road to the version 2.1. This series of texts should document
what is needed to be changed, why we do it and how. The
[previous chapter](https://en.blog.nic.cz/2021/06/14/bird-journey-to-threads-chapter-2-asynchronous-route-export/)
showed how the route export had to change to allow parallel execution. In the next chapter, we're most likely going
to show performance difference between BIRD v2.0.8 and the parallelized implementation. Stay tuned!*
