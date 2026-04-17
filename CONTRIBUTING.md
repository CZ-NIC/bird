## Quick navigation

### Contribute to BIRD

See section [Contributing to BIRD](#contributing-to-bird) for more information.

### Security vulnerability disclosure

View the document [SECURITY.md](SECURITY.md) to find latest information.

### Issue tracker status

See section [Issue tracker](#issue-tracker) for more information.

### LLMs in contributions

See section [Using LLMs for contributions](#using-llms-for-contributions) for more information.

### Commit message format

See section [Commit messages](#commit-messages) for more information.

### Code style guide

See section [Coding style](#coding-style) for more information.

---

<br>

## Contributing to BIRD

We welcome a broad range of contributions to BIRD with some limitations and
caveats. This document is rather long but worth reading.

BIRD is highly optimized for performance in both memory and computation time.
We generally don't accept obviously inefficient code and even though the
quality of the existing codebase quite varies, there should be good reasons
why to commit something slow or greedy.

There are several basic rules for contributing:

- your branch must have [understandable commit messages](#commit-messages)
- your branch must be either:
  - rooted in the current thread-next, aiming for inclusion in BIRD 3
  - or rooted in the master branch; in this case, we may refuse your patch
    if it's completely unmergeable with thread-next
- when incorporating proposed fixes, you may have to rebase your branch
- please [add automatic tests](#testing)
- upfront and continuous consultation with the development team gives you a
  fast track for merging
- don't forget to update documentation

## How to contribute

You can either send a patch (prepared by git format-patch) to our mailing-list
bird-users@network.cz, or you can send just a link to your repository and the
commit hash you're contributing. **We do not grant access to CZ.NIC gitlab.**
See section [Issue tracker](#issue-tracker) for reasons why.

### What if your contribution isn't mergable

If your code needs minor updates to align with our standards / taste, we'll
just do these modifications ourselves and either add these as a separate commit
or just update your commit noting this fact in the commit message.

If your code has some major flaws, misses the point or introduces another
problem (e.g. performance issues), we'll refuse your patch. Then we'll either
try to tell you how we prefer to reach the goal, or we may reimplement your
ideas ourselves. We'll mention your original contribution in the commit message.

We generally aim to avoid merge commits, apart from merging BIRD 2 to BIRD 3.
We are going to cherry-pick and rebase your work atop our main branches,
and if you do it yourself, it's more convenient for us.

## Specific kinds of contributions

### Substantial updates

If you feel like the BIRD internals need some major changes and you wish to
implement it, please contact the development team first. We're (as of May 2024)
developing two versions at once and we have some raw thoughts about BIRD's future
which we haven't published yet.

Beware that BIRD is more convoluted inside than it looks like on the surface,
and in many places the learning curve is _very_ steep.

### New protocol implementations

We generally welcome broadening of BIRD capabilities. Upfront consultation is
very much appreciated to align all parties on the development principles,
internal APIs, coding style and more.

### Refactoring and reformatting

Please don't send us _any_ refactoring proposals without previous explicit approval.

### Programmer's documentation, user documentation or tutorials

We welcome updates to enhance the documentation, including the algorithmic
principles, internal libraries and API. We keep our right to reject low quality
contributions altogether.

### Minor changes

Feel free to propose minor fixes in any part of BIRD.

## Commit messages

Our commit messages have a specific structure which one should obey.
Not using our structure is usually not a sole reason for refusal, but it
may be a reason for ignoring your patch for longer than it would deserve,
because fixing your commit message is additional work.

Example:

```
Author: Maria Matejka <mq@ucw.cz>
Date:   Thu Jul 3 11:58:01 2025 +0200

    BGP: Listening socket refactoring
    
    We sometimes need to have multiple listening sockets for one passive
    BGP. This refactoring commit updates the appropriate data structures.
```

### Title

The message should have a title, shortly describing what is happening.
The title is expected to have a section prefix (`BGP` the example above), one colon, one space,
and a short description of the commit, with first letter capitalized
and not ended by punctuation. Articles may be omitted.

The title should generally get along well when displayed by `git log --oneline`.

**Do not**, unless really appropriate:

- exceed 80 characters including the prefix (and definitely not 120)
- put function / variable / file names into the title
- use vague words (minor fix, just a typo, …)
- imply security impact or other process category (feature, bug)
- mention issues, branches or other volatile stuff

#### Known sections

You may use more sections if necessary, delimited by `/` (forward slash).

Refer to the [list of sections](#list-of-known-sections-for-commit-messages)
down below for known sections, as of April 2026; please use one of these if possible.

#### Special titles

Any title beginning with `CI:` is expected to **only change CI** with no impact
on the actual code. Vice versa, all CI changes should ideally get their own commits,
so that we can easily cherry-pick them for stable branches.

All releases are titled "NEWS and version update".

Any title beginning with `WIP:` is a temporary commit containing work in progress.
Our CI runs no jobs for that commit to save resources. These commits must never
survive to stable branches.

Also, `fixup!` and `squash!` commits must never be accepted. There are two fixups
lost deep in BIRD 3 history; they have an exception.

### Commit message body

The commit message body should explain what is happening and why, in plain
technical English, using regular sentences and grammar. The purpose of the message
body is the **semantics of the update**, not technical details of the fix itself.

When the commit fixes a CVE, it should include the assigned CVE number in sentence.
If the commit reacts to some mailing-list discussions, please link the list archive.

You should also include appropriate additional info at the end of the commit message:

- categorization
  - `Issue: #<num>` if related to [BIRD internal issue](#issue-tracker) and you know that number
  - `Target: patch` if eligible for stable patch release and not CI
  - `Target: minor` otherwise, if not CI
- personal attribution (formatted as name and e-mail address)
  - Co-Authored-By: directly collaborated on the code
  - Reported-By: reported the issue and possibly provided crashdumps or other debug data
  - Identified-By: did significant work on finding out the algorithmic cause
  - Reproduced-By: did significant work on reliably reproducing the issue in testbed
  - Signed-Off-By: reviewed the code and approves
- relevant links
  - `Introduced-In: commithash` for fixing regressions
  - `Source: url` for external links

**Do not**, unless really appropriate:

- use bullet points
- use non-ascii characters outside person names (fancy punctuation is allowed though)
- list file paths, function names or variable names
- reference issues with closing remarks (`This closes #425.`)
- write in LinkedLingo or any other fancy style

## Using LLMs for contributions

We do not completely oppose (and do not refuse) LLM-assisted or LLM-generated
contributions. There is no way to prove whether you have or haven't used LLM.
We use the same scrutiny for all the contributions regardless, because in the
end, it's the maintainer team who is going to release and support that code if
accepted.

It's worth noting that while LLMs significantly shorten the time to get some
code which theoretically works, we still expect that the contributor
understands what they are sending. Special care needs to be taken with the
commit messages; the maintainers have plenty of experience with misleading
descriptions and reasoning by LLMs.

If you happen to send LLM slop too often, we'll deploy an LLM to reply to your
e-mails, without actually considering their content.

If you don't understand BIRD code but you wanna help, the best way is to
[create a reproducer](#testing) causing a crash on an assert.

It's much better to send a hand-written piece of code which is obviously wrong
but proves the point, than to let LLM generate something which looks right
but you would fail to explain what it is doing and why.

## Coding style

Your contributed code should more or less adhere to the current style of the codebase.

This section outlines just the most common issues and is **far** from exhaustive,
so if unsure how to write something specific, look around the codebase for
similar sections. Note that some older parts of the codebase are *not* consistent with
the current coding style themselves, so, please, pick more recent additions for inspiration.

Example from `nest/a-set.c`

```c
int
int_set_min(const struct adata *list, u32 *val)
{
  /* Some example comment */
  if (!list)
    return 0;

  u32 *l = (u32 *) list->data;
  int len = int_set_get_size(list);
  int i;

  if (len < 1)
    return 0;

  *val = *l++;
  for (i = 1; i < len; i++, l++)
    if (int_set_cmp(val, l) > 0)
      *val = *l;

  return 1;
}
```

Remarks

- two spaces should be used as indentation, but eight continous spaces should be substituted by a single tab
- statements preceding function names (return type, etc.) should be on a separate line
- opening and closing curly braces of a block should be on a separate line (for all types of blocks)
- in case only single statement follows after `if` or `else`, it should not have braces around it (even if the statement itself has multiple lines)
- null check of pointers should be simple `if (pointer)` instead of a `if (pointer == NULL)`
- even for single line comments use `/* */` istead of a `//`
- ...

For more information about code refer to the technical documentation.


## Testing

There is another repository, <https://gitlab.nic.cz/labs/bird-tools.git>, where
we store our automatic tests in the
[netlab/](https://gitlab.nic.cz/labs/bird-tools/-/tree/master/netlab)
directory. This repository is quite
messy and you may need some help with it. We're planning to rework that.

When contributing a feature, you should provide tests, even if it's a messy framework.
Otherwise, your contribution would be slowed by somebody in the maintainer team
doing that work.

These automatic tests are used by our [CI](gitlab/).

## Issue tracker

The team has an internal issue tracker. Due to limitations of Gitlab, we've
struggled with spammers littering issues of other projects. We are unable to
open the issue tracker even read-only for public, without allowing spammers in.

We expect to partially open the issue tracker one day, probably through our
website. It's not a high-priority issue. We expect non-CZ.NIC people to use
the mailing-list for discussion and contributions.

## Crediting policy

The credits are scattered over all the source code files; in the commentary
section, you may find typically the original authors of these files or some
major contributors who felt like adding their names there. Overall, if you feel
like your name should be there, include this change in your commits please.

If your name should be changed, please do that change in the source code files.
If your name should be changed in the displayed git commit author / commiter
logs, please submit a patch on the `.mailmap` file.

We are planning to centralize the credits one day; we'll then update this file
accordingly.

## Meta

If some of these rules are breached, you may complain either at the mailing
list, or directly to CZ.NIC who is currently BIRD's maintainer.

If we don't reply within 3 weeks, please ping us. We don't intend to ghost you,
we are just overloaded.

This contributing policy also applies to itself.

## Misc

### List of known sections for commit messages

- Lib
  - Alloc
  - Bitops
  - Callback, Defer, Event
  - Hash
  - IO (preferred over Poll)
  - IP
  - Linpool
  - List
  - Locking
  - Loop (preferred over Scheduler)
  - Macro
  - MD5
  - Net
  - Netindex
  - Printf
  - Resources
  - Slab
  - Socket
  - SSH
  - String
  - Threads
  - Timer
  - Tree
  - Trie
- Filters
  - ASPA
  - ROA
  - Types
    - Clist, EClist, LClist
- Nest (rather use subcategory)
  - Route
    - Attributes
      - Nexthop
  - Iface (preferred over Interfaces)
    - Neighbor
  - Table
    - Flowspec
    - Hostentry
    - MPLS
  - Channel
    - Export
    - Import
    - Preexport
  - Proto (preferred over Protocol)
    - Aggregator
    - Babel
    - BFD
    - BGP
    - BMP
    - Device
    - Direct
    - KRT (preferred over Kernel)
      - Netlink (for netlink-specific updates)
    - L3VPN
    - MRT
    - OSPF
    - Pipe
    - RAdv
    - RIP
    - RPKI
    - Static
  - VRF
- Sysdep
  - Unix
- CLI (preferred over `birdc`, `commands`, Client and similar)
  - Dump
- Conf (preferred over Config)
  - Bison
  - Lexer
  - Log (preferred over Logging)
    - Debug
  - Main (rather use specific)
    - Startup
    - Shutdown
- Doc (preferred over doc, docs, documentation and similar)
- build and portability
  - Android
  - Autoconf (preferred over Autotools)
  - Build (for general buildsystem updates, including compiler options)
  - CI (preferred over Gitlab, Testing, Tests)
  - Distro
    - BSD, FreeBSD, NetBSD, OpenBSD
    - Linux (preferred over packaging)
      - DEB
      - RPM
  - Docker (please use CI for CI docker updates)
  - GDB
  - Git
  - M4
  - Make (preferred over Makefile)
  - Portability (for updates specifically targetting portability only)
  - Tools
    - Releasing (for release tooling updates)
