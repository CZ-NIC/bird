# BIRD Journey to Threads. Chapter 4: Memory and other resource management.

BIRD is mostly a large specialized database engine, storing mega/gigabytes of
Internet routing data in memory. To keep accounts of every byte of allocated data,
BIRD has its own resource management system which must be adapted to the
multithreaded environment. The resource system has not changed much, yet it
deserves a short chapter.

BIRD is a fast, robust and memory-efficient routing daemon designed and
implemented at the end of 20th century. We're doing a significant amount of
BIRD's internal structure changes to make it run in multiple threads in parallel.

## Resources

Inside BIRD, (almost) every piece of allocated memory is a resource. To achieve this,
every such memory block includes a generic `struct resource` header. The node
is enlisted inside a linked list of a *resource pool* (see below), the class
pointer defines basic operations done on resources.

```
typedef struct resource {
  node n;				/* Inside resource pool */
  struct resclass *class;		/* Resource class */
} resource;

struct resclass {
  char *name;				/* Resource class name */
  unsigned size;			/* Standard size of single resource */
  void (*free)(resource *);		/* Freeing function */
  void (*dump)(resource *);		/* Dump to debug output */
  resource *(*lookup)(resource *, unsigned long);	/* Look up address (only for debugging) */
  struct resmem (*memsize)(resource *);	/* Return size of memory used by the resource, may be NULL */
};

void *ralloc(pool *, struct resclass *);
```

Resource cycle begins with an allocation of a resource. To do that, you should call `ralloc()`,
passing the parent pool and the appropriate resource class as arguments. BIRD
allocates a memory block of size given by the given class member `size`.
Beginning of the block is reserved for `struct resource` itself and initialized
by the given arguments. Therefore, you may sometimes see an idiom where a structure
has a first member `struct resource r;`, indicating that this item should be
allocated as a resource.

The counterpart is resource freeing. This may be implicit (by resource pool
freeing) or explicit (by `rfree()`). In both cases, the `free()` function of
the appropriate class is called to cleanup the resource before final freeing.

To account for `dump` and `memsize` calls, there are CLI commands `dump
resources` and `show memory`, using these to dump resources or show memory
usage as perceived by BIRD.

The last, `lookup`, is quite an obsolete way to identify a specific pointer
from a debug interface. You may call `rlookup(pointer)` and BIRD should dump
that resource to the debug output. This mechanism is probably incomplete as no
developer uses it actively for debugging.

Resources can be also moved between pools by `rmove` when needed.

## Resource pools

The first internal resource class is a recursive resource – a resource pool. In
the singlethreaded version, this is just a simple structure:

```
struct pool {
  resource r;
  list inside;
  struct birdloop *loop;  /* In multithreaded version only */
  const char *name;
};
```

Resource pools are used for grouping resources together. There are pools everywhere
and it is a common idiom inside BIRD to just `rfree` the appropriate pool when
e.g. a protocol or table is going down. Everything left there is cleaned up.

There are anyway several classes which must be freed with care. In the
singlethreaded version, the *slab* allocator (see below) must be empty before
it may be freed and this is kept to the multithreaded version while other
restrictions have been added.

There is also a global pool, `root_pool`, containing every single resource BIRD
knows about, either directly or via another resource pool.

### Thread safety in resource pools

In the multithreaded version, every resource pool is bound to a specific IO
loop and therefore includes an IO loop pointer. This is important for allocations
as the resource list inside the pool is thread-unsafe. All pool operations
therefore require the IO loop to be entered to do anything with them, if possible.
(In case of `rfree`, the pool data structure is not accessed at all so no
assert is possible. We're currently relying on the caller to ensure proper locking.
In future, this may change.)

Each IO loop also has its base resource pool for its allocations. All pools
inside the IO loop pool must belong to the same loop or to a loop with a
subordinate lock (see the previous chapter for lock ordering). If there is a
need for multiple IO loops to access one shared data structure, it must be
locked by another lock and allocated in such a way that is independent on these
accessor loops.

The pool structure should follow the locking order. Any pool should belong to
either the same loop as its parent or its loop lock should be after its parent
loop lock in the locking order. This is not enforced explicitly, yet it is
virtually impossible to write some working code violating this recommendation.

### Resource pools in the wilderness

Root pool contains (among others):

* route attributes and sources
* routing tables
* protocols
* interfaces
* configuration data

Each table has its IO loop and uses the loop base pool for allocations.
The same holds for protocols. Each protocol has its pool; it is either its IO
loop base pool or an ordinary pool bound to main loop.

## Memory allocators

BIRD stores data in memory blocks allocated by several allocators. There are 3
of them: simple memory blocks, linear pools and slabs.

### Simple memory block

When just a chunk of memory is needed, `mb_alloc()` or `mb_allocz()` is used
to get it. The first with `malloc()` semantics, the other is also zeroed.
There is also `mb_realloc()` available, `mb_free()` to explicitly free such a
memory and `mb_move()` to move that memory to another pool.

Simple memory blocks consume a fixed amount of overhead memory (32 bytes on
systems with 64-bit pointers) so they are suitable mostly for big chunks,
taking advantage of the default *stdlib* allocator which is used by this
allocation strategy. There are anyway some parts of BIRD (in all versions)
where this allocator is used for little blocks. This will be fixed some day.

### Linear pools

Sometimes, memory is allocated temporarily. When the data may just sit on
stack, we put it there. Anyway, many tasks need more structured execution where
stack allocation is incovenient or even impossible (e.g. when callbacks from
parsers are involved). For such a case, a *linpool* is the best choice.

This data structure allocates memory blocks of requested size with negligible
overhead in functions `lp_alloc()` (uninitialized) or `lp_allocz()` (zeroed).
There is anyway no `realloc` and no `free` call; to have a larger chunk, you
need to allocate another block. All this memory is freed at once by `lp_flush()`
when it is no longer needed.

You may see linpools in parsers (BGP, Linux netlink, config) or in filters.

In the multithreaded version, linpools have received an update, allocating
memory pages directly by `mmap()` instead of calling `malloc()`. More on memory
pages below.

### Slabs

To allocate lots of same-sized objects, a [slab allocator](https://en.wikipedia.org/wiki/Slab_allocation)
is an ideal choice. In versions until 2.0.8, our slab allocator used blocks
allocated by `malloc()`, every object included a *slab head* pointer and free objects
were linked into a single-linked list. This led to memory inefficiency and to
contra-intuitive behavior where a use-after-free bug could do lots of damage
before finally crashing.

Versions from 2.0.9, and also all the multithreaded versions, are coming with
slabs using directly allocated memory pages and usage bitmaps instead of
single-linking the free objects. This approach however relies on the fact that
pointers returned by `mmap()` are always divisible by page size. Freeing of a
slab object involves zeroing (mostly) 13 least significant bits of its pointer
to get the page pointer where the slab head resides.

This update helps with memory consumption by about 5% compared to previous
versions; exact numbers depend on the usage pattern.

## Raw memory pages

Until 2.0.8 (incl.), BIRD allocated all memory by `malloc()`. This method is
suitable for lots of use cases, yet when gigabytes of memory should be
allocated by little pieces, BIRD uses its internal allocators to keep track
about everything. This brings some ineffectivity as stdlib allocator has its
own overhead and doesn't allocate aligned memory unless asked for.

Slabs and linear pools are backed by blocks of memory of kilobyte sizes. As a
typical memory page size is 4 kB, it is a logical step to drop stdlib
allocation from these allocators and to use `mmap()` directly. This however has
some drawbacks, most notably the need of a syscall for every memory mapping and
unmapping. For allocations, this is not much a case and the syscall time is typically 
negligible compared to computation time. When freeing memory, this is much
worse as BIRD sometimes frees gigabytes of data in a blink of eye.

To minimize the needed number of syscalls, there is a per-thread page cache,
keeping pages for future use:

* When a new page is requested, first the page cache is tried.
* When a page is freed, the per-thread page cache keeps it without telling the kernel.
* When the number of pages in any per-thread page cache leaves a pre-defined range,
  a cleanup routine is scheduled to free excessive pages or request more in advance.

This method gives the multithreaded BIRD not only faster memory management than
ever before but also almost immediate shutdown times as the cleanup routine is
not scheduled on shutdown at all.

## Other resources

Some objects are not only a piece of memory; notable items are sockets, owning
the underlying mechanism of I/O, and *object locks*, owning *the right to use a
specific I/O*. This ensures that collisions on e.g. TCP port numbers and
addresses are resolved in a predictable way.

All these resources should be used with the same locking principles as the
memory blocks. There aren't many checks inside BIRD code to ensure that yet,
nevertheless violating this recommendation may lead to multiple-access issues.

*It's still a long road to the version 2.1. This series of texts should document
what is needed to be changed, why we do it and how. The
[previous chapter](TODO)
showed the locking system and how the parallel execution is done.
The next chapter will cover a bit more detailed explanation about route sources
and route attributes and how lockless data structures are employed there. Stay tuned!*
