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
 *  - num_full - number of allocated items.
 *    lower part is count of allocated chunks of data.
 *  - index in metapage
 *  - pointer to metapage
 *  - last_abandoned flag - double flag guarding races between allocating thread and freeing thread.
 *    Last is set if freeing thread freed was the last who made change (nothing allocated since last free).
 *    Allocating thread can not leave page, if last is set.
 *    Leaved is set if full_or_owned is needed to unset when freeing next time. (Allocating thread left.)
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
 * 1) Find a head with bit exists set, full_or_owned unset. If there is no such bit, look for different metapage.
 * 2) Set bit full_or_owned. This must be done atomicaly and checked we won the race.
 *    - If we lost, go back to 1)
 * 3) Set last_abandoned to 0x00.
 * 4) Start allocating, head is yours!
 * 
 * Allocating new data page from meta page:
 * 0) Check there are no partialy empty abandoned heads (bit exists set, full_or_owned unset).
 * 1) Find a place with bit full_or_owned unset and bit exists unset. IF exists IS UNSET AND full_or_owned SET,
 *    DO NOT TOUCH IT.
 * 2) Set bit full_or_owned. This must be done atomicaly and checked we won the race. If we lost, go back to 0)
 *    - If we succed to set full_or_owned and found out that exists has been already set, it means we own
 *      a partially filled head, no need to allocate it. Just set last_abandoned to 0x00, and start allocating.
 * 3) We own the space now and nobody should be waiting for us. Allocate the page, set its bitefield,
 *    set its last_abandoned to 0x00, and set exists bit.
 * 4) Start allocating.
 * 
 * Allocating from owned head
 * 1) Check if num_full is already at the maximum number of items.
 *    If yes:
 *    - Atomic exchange on last_abandoned - 0x00 -> 0x01 (first bit means we do not expect free was the last operation
 *      on the head, second - we want next freeing thread to unset full_or_owned)
 *    - If we succeed, the head is no longer ours and we are not allowed to use the pointer to the head, Find an other.
 *    - If last (the first bit) was set, continue to 2)
 * 2) Set last_abandoned to 0x00. (Bit last says the last operation was free. We are the only thread actually reading the value
 *    of last. Abandoned can not be set. (Only we can set it and we did not do that.))
 * 3) Increase the num_full.
 * 4) Go through used_bits, set a bit, return pointer (normal allocation)
 * 
 * 
 * Free an item
 * 1) Unset corresponding bit in used_bits.
 * 2) In last_abandoned set last and unset abandoned (0x10), remember old last_abandoned value
 * 3) If abandoned was set, assert full_or_owned, unset it.
 * 4) Decrease num_full.
 * 5) If num_full was > 1, return
 * 6) Try to set full_or_owned. If it was already taken, leave.
 * 7) If exist unset, someone already freed the page. Leave.
 * 8) Refresh pointer to the page. (It would be NULL is we skip 7).)
 * 9) Check the num_full (of the refreshed page) is 0.
 *    - If num_full > 0: Increase num_full, unset full_or_owned. Then we are in the exact same situation as at 4). Start
 *      from there again.
 * 10) No one can get the page, no one can increase num_full, no one can free from it.
 * 11) Set exists to 0.
 * 12) Actually free the page
 * 13) Unset full_or_owned
 * 10) We need to decrease the number of heads count in mother page -> to be continued in next section - Free a metapage
 * 
 * 
 * Why does this work?
 * Picking page x Picking page
 * - only one thread can set the full_or_owned bit. That thread wins the page / place to store the page.
 * 
 * Picking page x Allocating
 * - can never race, because only one of them set full_or_owned.
 * 
 * Picking page x Free
 * Actual free can be done only after full_or_owned is set. If free wins, page is freed, if picking wins, it can allocate.
 * 
 * Allocating x Free
 * Allocating thread keeps full_or_owned - the page can not be freed when allocating.
 * 
 * Allocating thread can never leave a page, which is not full or being freed. First thread, which frees an item
 * from abandoned page, unsets full_or_owned.
 *  - That is what is last_abandoned for. Each time freeing thread frees an item, it sets last. Allocating thread unsets
 *    last each time it allocates.
 *    Leaving a full head is done by setting bit abandoned. Allocating thread compare exchanxe the whole last_leaved
 *    flag from 0x00 to 0x01. This way we make sure bit last was not set since full head was detected, and if
 *    this bit was not detected, it means freeing threads did not manage to remove everithing (or remove anything
 *    if allocating thread first unset bit abandoned and then increased the num_full). That is why allocating
 *    thread never leaves an empty head.
 *
 * Allocating x Allocating
 * Can never occur on one head.
 * 
 * Free first item x free last item
 * If last item free is faster at full_or_own - Last item free fails to set full_or_own, but it is ok, because there is at least
 *   the first item free thread freeing as well. 
 * If first item free is fater and unsets full_or_own - That is the normal case. After first item free unsets full_or_own,
 *   it becomas normal freeing thread.
 * 
 * Free last item x Free
 * After a free thread decreases num_full, it does not touch anything from the page. Before that it the num_full is surely not 0.
 * 
 * Free last item x Free last item
 * All threads which decreases num_full to 0 try to free the page. First, the try to get full_or_owned. If they do not succeed,
 * it is ok to leave, because the full_or_owned is either:
 *   a) owned by allocating thread. Allocating thread can not leave the page if it is empty
 *   b) waits to be unset by first freeing thread. At least that thread will decrease num_full after us again.
 *   c) owned by an other free last thread. That thread is already working on that free.
 * One freeing thread got full_or_owned. What can it find:
 *   a) exists is unset and pointer to the page disappeared. The page we wanted to free is already gone, solved.
 *   b) pointer to the page changed. We got full_or_owned, so we have to take care. But we take care the same way
 *      as in c) and d):
 *   c) num_full is 0. Great, no one can touch the page. Lets free it. If a sleeping thread wakes up later, it will find a)
 *   d) num_full is not 0. No one is allocating, but there is rest of data. Bad situation, but we own the page, so we can
 *      safely increase the num_full to 1. After that, we get rid of full_or owned. This way we got into the same state we
 *      any thread is before decreasing num_full and the same reasons apply.
 * 
 * 
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
 * 1) Keep triing to decrease heads_count of parent metapage by atomic compare exchange by 1 until
 *    success or heads_count == 1.
 * 2) If heads_count succesfuly decreased, return.
 * 3) set full_or_owned for current metapage.
 *    - if full_or_owned was already set, go to 1)
 * 4) rcu_sync
 * 5) RELOAD POINTER TO THE PAGE
 * 6) if heads_count > 0 leave
 * 7) set exist to 0, free the page and repeate on parent if heads_count is zero
 */ 