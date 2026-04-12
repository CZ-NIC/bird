# Contributing to BIRD

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

## Security issues

Please contact us on bird-support@network.cz for private disclosure of any
security issues. This includes any crash in or related to filters, induced by
CLI or by receiving a malformed message by a protocol.

We take security issues seriously and we analyze them with high priority, often
even during weekends or nights, whenever something occurs. With that though,
we'd like you to first do your assessment whether the issue which you are about
to report, is indeed a security issue.

If you are using LLMs to find possible problems, we expect you to do the
following assessment before sending a report. In any case, write the report
yourself, proving that you actually understand what you are reporting.

### What is an issue for our security channel

**Do you get more power** compared to your regular
access level and available tools, **by exploiting that exact issue?** Yes?
Congratulations, you have found a security issue.

Parts of BIRD are expected to be exposed to the world. Thus, if you find a
misbehavior which may cause wrong routing/forwarding and is remote-triggerable
via BGP, RPKI or `birdc -r`, that is something worth sending through the
security channel.

BIRD runs with quite high privileges. If you need local `root` to exploit
the bug, it's not a security issue. If you need to build your binary yourself
with non-standard compiler flags, it's not a security issue.

BIRD has no quotas, query rate limiting or access control. If your root
left the control socket open, it's not our security issue. If you can saturate
the link so that BGP doesn't get through, it's not our security issue.

BIRD does not sanitize weird data from internal routing protocols.
If you are privileged enough to send garbage to OSPF, you are privileged
enough to spoof anything there. Not a security problem in BIRD.

BIRD expects operators to do reasonable things, and generally know what they
are doing. Crashes on configuration corner cases, weird combinations of debug
flags or crazy recursive filters are not a security issue, unless exploitable
unprivileged.

If unsure, use the security channel. If lazy, do the assessment.

## How to contribute

You can either send a patch (prepared by git format-patch) to our mailing-list
bird-users@network.cz, or you can send just a link to your repository and the
commit hash you're contributing. **We do not grant access to CZ.NIC gitlab.**

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

### Using LLMs for contributions

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

### Title

The message should have a title, shortly describing what is happening.
The title is expected to have a section prefix, one colon, one space,
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

These sections are already known, as of April 2026; please use
one of these if possible.

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
