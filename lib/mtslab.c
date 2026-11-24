/*
 * Imagine we have a page of pointers to data pages. Head of this page and data page look like this:
 *  Head of page containing pointers to data pages (metapage)
 *  - index in mother metapage
 *  - pointer to motherpage
 *  - number of allocated pages
 *  - level - 0 if children are datapages, root has the greatest number
 *  - bitefield full_or_owned - bit set for each page, which is owned by a thread or is full of data.
 *    At level 0, you are NOT ALLOWED TO EVEN TOUCH ITS POINTER unless it is yours OR you have
 *    to free data from it.
 *  - bitefield exists - bit set for each page which is fully set and working. Again, you can change
 *    this bit if and only if you managed to set the full_or_owned bit in the first place.
 *  - the actual pointers to the pages
 *  - full_heads_count - used to determine if we can still allocate its heads - increased before
 *    any attempt to grab a data head, decreased if attempt unsuccesful or if a datapage is deleted.
 *  - heads_count - used to determine if we can free this head - increase when new data head
 *    is allocated, decrease when a head is freed
 * 
 *  Head of page containing the data (datapage)
 *  - num_full - count of allocated chunks of data. If the head is being deleted, it is increased by 1000.
 *  - index in metapage
 *  - pointer to metapage
 *  - owned_last_leaved flag - triple flag guarding races between allocating thread and freeing thread.
 *    Bit owned is set if the head is owned by an allocating thread (It used to be important before the algorithm
 *    changed, but it still can be usefull for debugging or can be removed). Last is set if freeing thread freed
 *    last item, leaved if full_or_owned is needed to unset when freeing next time.
 *  - used_bits bitfield - keep track of allocated chunks of memory
 *
 * Rules:
 * 1) Never access a datapage, if you are not freeing its items or managed to set its full_or_owned.
 * 2) Before you touch a metapage in the tree and the whole time you access it, you have to make sure that
 *    at least one statement is true:
 *    a) you are in rcu lock
 *    b) your page or one of its children pages have num_full > 0 and can't reach num_full == 0
 * 
 * Datapages
 * =========
 * How this works:
 * (Still not explaining moving in the tree of pages, there will be separate section.)
 * 
 * Grabing a partialy filled abandoned head
 * 1) Find a head with bit exists set, full_or_owned unset.
 * 2) Set bit full_or_owned. This must be done atomicaly and checked we won the race. If we lost, go back to 1)
 * 3) Set owned_leaving to 0x10.
 * 4) Start allocating, head is yours!
 *    - but remember - due to race with free, it is possible that num_full has not been lowered soon enough.
 *      The space for allocating does exists for sure, so this is hopefully harmless.
 * 
 * Allocating new head from given page of data heads:
 * 0) Check there are no partialy empty abandoned heads (bit exists set, full_or_owned unset).
 * 1) Find a place with bit full_or_owned unset and bit exists unset. IF exists IS UNSET AND full_or_owned SET,
 *    DO NOT TOUCH IT.
 *    - We can not check both bitfields atomic * mpagally. But remember, if we succed to set full_or_owned and found out
 *      that exists has been already set, it means we own a partially filled head, no need to allocate it.
 * 2) Set bit full_or_owned. This must be done atomicaly and checked we won the race. If we lost, go back to 0)
 * 3) We own the space now and nobody should be waiting for us. Allocate the page, set its bitefield,
 *    set its owned_leaving to 0x10, and set exists bit.
 * 4) Start allocating.
 * 
 * Allocating from owned head
 * 1) Check if num_full is already at the maximum number of items.
 *    If yes:
 *    - Atomic exchange on owned_last_leaving - 0x100 -> 0x001 (first bit - we do not want to own it,
 *      third - we want next freeing thread to unset full_or_owned, and, the middle 0 means we do not expect
 *      the page to have or had been empty)
 *    - If we succeed, the head is no longer ours and we are not allowed to use the pointer to the head
 *    - If last (the middle bit) was set, num_full was increased for us by a freeing thread. The freeing thread managed to
 *      set the last bit, that means it knows we will use the increasing. Right now it is not possible to decrease
 *      the num_full enough to start new attempt to free this page, we have time to set leaving bit back to 0.
 *      We can allocate now. Once new item is allocated, freeing threads might attempt to free the page again.
 *    If not - just increase the num_full.
 * 2) Go through used_bits, set a bit, return pointer (normal allocation)
 * 
 * Free an item
 * 1) Unset corresponding bit in used_bits.
 * 2) unset leaving, remember owned_last_leaving value
 * 3) If leaving was set, assert full_or_owned, unset it.
 * 4) load num_full and use atomic_exchange_explicit to decrease by 1 while not success and it is > 1. If we would
 *    decrease num_full to 0, we stop decreasing and start freeing the datapage.
 * Free a datapage
 * If we didn't manage to decrease num_full before it dropped to 1, no one else will even try to remove the page.
 * 5) set full_or_owned
 *     - if not success - it means someone is allocating from it. Try to set owned_last_leaving 0x100->0x110.
 *       - if success, we are done. Allocating thread will notice the set last bit and it will not increase num_full.
 *       - if not success, assert the middle bit (bit leaving) was not set. Go to 2) (yeah, we can do that - no one 
 *         can delete the page until we decrease num_full or signalise to the allocating thread to manage it.)
 * 6) unset exists bit (assert we unset it)
 * 7) RELOAD POINTER TO THE PAGE
 * ( 8) assert not owned (cant be owned - we got full_or_owned) )
 * 9) free the page, unset full_or_owned
 * 10) (to be continued in next section - Free a metapage)
 * 
 * Metapages
 * =========
 * On the beggining, there is one metapage. Once it is full, next metapages are build above it in a tree structure
 * and the original metapage remains as the first leaf.
 * 
 * Looking for a datapage
 * 1) Enter rcu critical section.
 * 2) Start from the root:
 *    I) If it is level 0, continue to 3)
 *    II) Find a child with full_or_owned unset and exist set.
 *        - increase heads_count
 *          - if heads_count was lower than maximum number of heads,
 *            leave rcu, try to set full_or_owned at a place with exist unset. It must be possible, there can not be more
 *            competiting threads than free places at any time. Once succeed, allocate metapage, init it (level 0), and when all is
 *            ready, set its exist bit. Allocate new datapage and first portion of data from it.
 *         - if it was higher:Free an item ended at 10) and value of num_full is 0 now. If not, leave rcu critica
 *              - leave rcu - current page can not be deleted, we increased heads_count.
 *              - if we are root or mother page level > current level + 1, try to add middle layer:
 *                - allocate the page, set it up, let current page be our child (with respect to its index)
 *                - atomic compare exchange on on mother, allocate new metapage, set it up as child and allocate from it. 
 *              - heads_count which we increased. If needed (and we do have the new page now),
 *                delete the page (the same way as free does).
 *              - if not success, repeat from 1)
 * 
 * 3) Increase heads_count, leave rcu section
 * 4) Increase full_heads_count. If it is too big, set bit full_or_owned in mother page and increase its full_heads_count.
 *    Repeat as long as usecounts are too big or until we reach the root or there is level difference between parent and child greater than 1.
 * 5) Try to get partial head - Grabing a partialy filled abandoned head
 * 6) If 4) was no success, allocate new head - Allocating new head from given page of data heads
 * 7) If 4) was success, decrease heads_count (and assert it was > 1)
 * 
 * Free a metapage
 * It is possible to remove only pages with no children.
 * 
 * 1) Keep triing to decrease num_full of parent metapage by atomic compare exchange by 1 until
 *    success or num_full == 1.
 * 2) If num_full succesfuly decreased, return.
 * 3) set full_or_owned for current metapage.
 *    - if full_or_owned was already set, go to 1)
 * 4) rcu_sync
 * 5) RELOAD POINTER TO THE PAGE
 * 6) if num_full > 0 leave
 * 7) set exist to 0, free the page and repeate on parent if num_full is zero
 */