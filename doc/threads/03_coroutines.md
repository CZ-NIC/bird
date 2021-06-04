# BIRD Journey to Threads. Chapter 3: Coroutines and Locking

Parallel execution in BIRD uses an underlying mechanism of coroutines and
locks. This chapter covers these two internal modules and their principles.
Knowing this is a need if you want to create any non-trivial extension to
future BIRD.

## BIRD's internal logical structure

The authors of original BIRD concepts wisely chose a highly modular structure.
We can therefore use this structure with minimal rework needed. This structure is roughly:

1. Reconfiguration routines
2. Protocols
3. BFD
4. Private routing tables
5. Standalone routing tables
6. Route attribute cache

This order is important for locking. Most actions in BIRD are called
top-to-bottom in this list, e.g. a reconfiguration triggers protocol action,
this triggers BFD update, then a routing table update which in turn calls route
attribute cache. The major locking decision for BIRD is enforcement of this order.

We're not sure yet about where the interface list and `protocol device` should
be. For now, it is somewhere between 1 and 2, as the interface updates are
synchronous. It may move in future to 2+5 after implementing asynchronous
interface updates.

## Locking

BIRD is split into so-called *domains*. These consist of data structures
logically bound together. These domains should have their own lock guarding
access to them. These domains are divided into the categories mentioned above.

Currently, lots of domains don't have their own lock. Last changes in branch
`alderney` assigned locks to routing tables and route attribute cache (4, 5 and 6).
BFD has had its own lock since it was added to BIRD as it needs much lower
latency than BIRD typically allows. The rest of BIRD (reconfiguration,
protocols and CLI) has one common lock, called `the_bird_lock`. This is going to change later.

Locking and unlocking is heavily checked. BIRD always stores the thread's
locking stack at one place for debug and consistency checking purposes. The
locking stack is limited to the number of categories. All domains must be
locked top-to-bottom in this order and unlocked bottom-to-top. No thread is
allowed to lock more than one domain in each category.

This brings some possible problems in communication between tables (recursive
nexthop updates had to be thoroughly checked) and it also needs the last big
change, the asynchronous export. If any data needs to be handed from down to
up, it must use some kind of asynchronicity to unlock the lower domain before
accesing the higher level. On the other hand, data flow from up to down is
straightforward as it is possible to just lock and call the appropriate function.

## Coroutines

There are three principal types of coroutines. One-shot tasks, workers
and IO handlers. They all share one coroutine data type, anyway the
synchronization mechanisms are different.

### One-shot tasks

The simplest coroutine type is a one-shot task. Some part of BIRD requests a
one-time CPU-intensive work. This is used in reconfiguration rework. When
reconfig is requested, BIRD starts a reconfig coroutine which first parses the
file (which can take tens of seconds if you have a gigabyte of config files).
Then this coroutine locks everything and applies the parsed configuration.

One-shot tasks simply start when they are requested and stop when they are
done. To cancel them prematurely, it is typically enough to set/check an atomic
variable.

### Workers

In lots of cases, a module has to wait for some supplied data. This is used in
the channel feed-export coroutine. When feed-export is requested, BIRD starts a
coroutine which waits on semaphore to get exports, processes the exports and
then jumps back to wait on semaphore for more work.

These coroutines must be woken up by their semaphore after setting the
cancellation variable. Then the coroutine cleans up and calls what is required
next after its cleanup, until finally exiting.

### IO handlers

BIRD needs IO. It is possible to handle almost all IO events in parallel and
these coroutines will take care of that. There is currently only one such
thread, it is a low-latency BFD thread handling its own socket.

IO coroutines are also possibly timer coroutines as the `poll` call typically
has a timeout option. In future, there should be independent IO coroutines for
each protocol instance to handle IO bottlenecks. It should be noted that e.g.
in BGP, the protocol synchronously advertises and withdraws routes directly
from the receive handler.

These coroutines sometimes have to be updated (protocol shuts down, timer is
modified), therefore every IO coroutine needs its own *fifo* which it polls for
read. On any update, one byte is sent to this fifo, effectively waking up the
poll. The fifo is always checked first for changes; if there are some, the poll
is reloaded before looking at anything else.

### The Main Loop

Currently, BIRD executes everything (with exception of those parts already
moved to their threads) in one single loop. There are all the sockets with a
magic round-robin selection of what socket we're going to read from next. This
loop also runs all the timers and other "asynchronous" events to handle the
risk that some code would tamper with the caller's data structures badly.

This loop should gradually lose its work to do when more and more routines get
moved to their own domains and coroutines. After all, possibly the last task
for the main loop would be signal handling and maybe basic CLI handling.

The main loop dismantling is a long term goal. Before that, we have to do lots of
changes, allowing for more and more code to run independently. Since [route
exports are now asynchronous](TODO), there is no more obstacle in adopting the
locking order as shown here.

*This chapter is last at least for a while. There will be more posts on BIRD
internals in future, you may expect e.g. protocol API description and maybe
also a tutorial how to create your own protocol. Thank you all for your support.
It helps us make your BIRD run smooth and fast.*
