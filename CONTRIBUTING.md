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

See section [Commit messages](doc/style.md#commit-messages) in the style guide for more information

### Code style guide

See section [Coding style](doc/style.md#coding-style) in the style guide for more information.

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

- your branch should have [understandable commit messages](doc/style.md#commit-messages)
- your branch must be rooted in:
  - the master branch
  - if specific for BIRD 3, thread-next
  - if specific for some stable version, stable-v... (e.g. stable-v2.17)
  - if specific for some experimental branch, that branch
- the master branch shall stay easily mergable into thread-next;
  if there is a major merge conflict, please suggest how to resolve it
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
problem (e.g. performance issues or it doesn't fit our future goals with the code),
we'll refuse your patch. Then we'll either
try to tell you how we prefer to reach the goal, or we may reimplement your
ideas ourselves. We'll mention your original contribution in the commit message.

We generally aim to avoid merge commits, apart from merging BIRD 2 to BIRD 3.
We are going to cherry-pick and rebase your work atop our main branches,
and if you do it yourself, it's more convenient for us.

## Specific kinds of contributions

### Substantial updates

If you feel like the BIRD internals need some major changes and you wish to
implement it, please contact the development team first. We're (as of October 2026)
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

### User documentation or tutorials

We welcome updates to enhance the user documentation.
We keep our right to reject low quality contributions altogether.

We generally don't accept patches for programmer's documentation
and we first plan to substantially rewrite it
to match BIRD 2 and 3. There are still some remnants from the principles
of BIRD 1 and we can't guarantee anything about that for now.

### Minor changes

Feel free to propose minor fixes in any part of BIRD. We expect, though,
that your fix won't change the default behavior of BIRD.

## Using LLMs for contributions

We have no strict opinion about accepting or rejecting LLM-assisted
or LLM-generated contributions.  We use the same scrutiny for all the
contributions regardless, because in the end, it's the maintainer team who is
going to release and support that code if accepted.

It's worth noting that while LLMs significantly shorten the time to get some
code which theoretically works, we still expect that the contributor
understands what they are sending. Special care needs to be taken with the
commit messages; the maintainers have plenty of experience with misleading
descriptions and reasoning by LLMs.

If you happen to send LLM or human slop too often, we'll deploy an LLM or a human
to reply to your e-mails, without actually considering their content.

If you don't understand BIRD code but you wanna help, the best way is to
[create a reproducer](#testing) causing a crash on an assert.

It's much better to send a hand-written piece of code which is obviously wrong
but proves the point, than to let LLM generate something which looks right
but you would fail to explain what it is doing and why.


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
