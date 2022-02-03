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
one domain of a type (these domains are uncomparable) and recursive locking is
forbidden as well.

The locking hiearchy is (roughly; as of February 2022) like this:

1. The BIRD Lock (for everything not yet checked and/or updated)
2. Protocols (as of February 2022, it is BFD, RPKI, Pipe and BGP)
3. Routing tables
4. Global route attribute cache
5. Message passing
6. Internals and memory management

There are heavy checks to ensure proper locking and to help debugging any
problem when any code violates the hierarchy rules. This impedes performance
depending on how much that domain is contended and in some cases I have already
implemented lockless (or partially lockless) data structures to overcome this.

You may ask, why are these heavy checks then employed in production builds?
Risks arising from dropping some locking checks include:

* deadlocks; these are deadly in BIRD anyway so it should just fail with a meaningful message, or
* data corruption; it either kills BIRD anyway, or it results into a slow and vicious death,
  leaving undebuggable corefiles behind.

To be honest, I believe in principles like *"every nontrivial software has at least one bug"*
and I also don't trust my future self or anybody else to always write bugless code when
it comes to proper locking. I also believe that if a lock becomes a bottle-neck,
then we should think about what is locked inside and how to optimize that,
possibly implementing a lockless or waitless data structure instead of dropping
thorough consistency checks, especially in a multithreaded environment.

### Choosing the right locking order

When considering the locking order of protocols and route tables, the answer
was quite easy. We had to make either import or export asynchronous (or both).
Major reasons for asynchronous export have been stated in the previous chapter,
therefore it makes little sense to allow entering protocol context from table code.

As I write further in this text, even accessing table context from protocol
code leads to contention on table locks, yet for now, it is good enough and the
lock order features routing tables after protocols to make the multithreading
goal easier to achieve.

The major lock level is still The BIRD Lock, containing not only the
not-yet-converted protocols (like Babel, OSPF or RIP) but also processing CLI
commands and reconfiguration. This involves an awful lot of direct access into
other contexts which would be unnecessarily complicated to implement by message
passing. Therefore, this lock is simply *"the director"*, sitting on the top.

The lower lock levels are mostly for shared global data structures accessed
from everywhere. We'll address some of these later.

## IO Loop

There has been a protocol, BFD, running in its own thread since 2013. This
separation has a good reason; it needs low latency and the main BIRD loop just
walks round-robin around all the available sockets which may last for a long
time. BFD had its own IO loop implementation and simple message passing
routines. This code could be easily updated for general use so I did it.

To understand the internal principles, we should say that in the `master`
branch, there is a big loop centered around a `poll()` call, dispatching and
executing everything as needed. There are several means how to get something dispatched from a loop.

1. Requesting to read from a socket makes the main loop call your hook when there is some data received.
   The same happens when a socket refuses to write data. Then the data is buffered and you are called when
   the buffer is free. There is also a third callback, an error hook, for obvious reasons.

2. Requesting to be called back after a given amount of time. This is called *timer*.

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
must know what loop to wake up to avoid unnecessary delays. Then the target
loop opens its mailbox and processes the task in its context.

The other way is a direct access of another domain. This approach blocks the
appropriate loop from doing anything and we call it *entering a birdloop* to
remember that the task must be fast and *leave the birdloop* as soon as possible.
Route import is done via direct access from protocols to tables; in large
setups with fast filters, this is a major point of contention (after filters
have been parallelized) and will be addressed in future optimization efforts.
Reconfiguration and interface updates also use direct access; more on that later.
In general, this approach should be avoided unless there are good reasons to use it.

Even though direct access is bad, sending lots of messages may be even worse.
Imagine one thousand post(wo)men, coming one by one every minute, ringing your
doorbell and delivering one letter each to you. Horrible! Asynchronous message
passing works exactly this way. After queuing the message, the source sends a
byte to a pipe to wakeup the target loop to process the task. We could also
periodically poll for messages instead of waking up the targets, yet it would
add quite a lot of latency which we also don't like.

Messages in BIRD don't typically suffer from the problem of amount and the
overhead is negligible compared to the overall CPU consumption. With one notable
exception: route import/export.

### Route export message passing

If we had to send a ping for every route we import to every exporting channel,
we'd spend more time pinging than doing anything else. Been there, seen
those unbelievable 80%-like figures in Perf output. Never more.

Route update is quite a complicated process. BIRD must handle large-scale
configurations with lots of importers and exporters. Therefore, a
triple-indirect delayed route announcement is employed:

1. First, when a channel imports a route by entering a loop, it sends an event
   to its own loop (no ping needed in such case). This operation is idempotent,
   thus for several routes in a row, only one event is enqueued. This reduces
   several route imports (even hundreds in case of massive BGP withdrawals) to
   one single event.
2. When the channel is done importing (or at least takes a coffee break and
   checks its mailbox), the scheduled event in its own loop is run, sending
   another event to the table's loop, saying basically *"Hey, table, I've just
   imported something."*. This event is also idempotent and further reduces
   route imports from multiple sources to one single event.
3. The table's announcement event is then executed from its loop, enqueuing export
   events for all connected channels, finally initiating route exports. As we
   already know, imports are done by direct access, therefore if protocols keep
   importing, export announcements must wait.

This may seem overly complicated, yet it should work and it seems to work. In
case of low load, all these notifications just come through smoothly. In case
of high load, it's common that multiple updates come for the same destination.
Delaying the exports allows for the updates to settle down and export just the
final result, reducing CPU load and export traffic.

## Cork

Route propagation is involved in yet another problem which has to be addressed.
In the old versions with synchronous route propagation, all the buffering
happened after exporting routes to BGP. When a packet arrived, all the work was
done in BGP receive hook – parsing, importing into a table, running all the
filters and possibly sending to the peers. No more routes until the previous
was done. This self-regulating mechanism doesn't work any more.

Route table import now returns immediately after inserting the route into a
table, creating a buffer there. These buffers have to be processed by other protocols'
export events. In large-scale configurations, one route import has to be
processed by hundreds, even thousands of exports. Unlimited imports are a major
cause of buffer bloating. This is even worse in configurations with pipes,
as these multiply the exports by propagating them all the way down to other
tables, eventually eating about twice the amount of memory than the single-threaded version.

There is therefore a cork to make this stop. Every table is checking how many
exports it has pending, and when adding a new export to the queue, it may apply
a cork, saying simply "please stop the flow for a while". When the exports are
then processed, it uncorks.

On the other side, there may be events and sockets with a cork assigned. When
trying to enqueue an event and the cork is applied, the event is instead put
into the cork's queue and released only when the cork is released. In case of
sockets, when `poll` arguments are recalculated, the corked socket is not
checked for received packets, effectively keeping them in the TCP queue and
slowing down the flow.

The cork implementation is quite crude and rough and fragile. It may get some
rework while stabilizing the multi-threaded version of BIRD or we may even
completely drop it for some better mechanism. One of these candidates is this
kind of API:

* (table to protocol) please do not import
* (table to protocol) you may resume imports
* (protocol to table) not processing any exports
* (protocol to table) resuming export processing

Anyway, cork works as intended in most cases at least for now.

*It's a long road to the version 2.1. This series of texts should document what
is changing, why we do it and how. The
[previous chapter](https://en.blog.nic.cz/2021/06/14/bird-journey-to-threads-chapter-2-asynchronous-route-export/)
shows how the route export had to change to allow parallel execution. In the next chapter, some memory management
details are to be explained together with the reasons why memory management matters. Stay tuned!*
