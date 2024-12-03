# Contributing to BIRD

We welcome a broad range of contributions to BIRD with some limitations and
caveats.

BIRD is highly optimized for performance in both memory and computation time.
We generally don't accept obviously inefficient code and even though the
quality of the existing codebase quite varies, there should be good reasons
why to commit something slow or greedy.

There are several basic rules for contributing:

- your branch must have understandable commit messages
- your branch must be either:
  - rooted in the current thread-next, aiming for inclusion in BIRD 3
  - or rooted in the master branch; in this case, we may refuse your patch
    if it's completely unmergeable with thread-next
- when incorporating proposed fixes, you may have to rebase your branch
- please add automatic tests (see below)
- upfront and continuous consultation with the development team gives you a
  fast track for merging
- don't forget to update documentation

## Security issues

Please contact us on bird-support@network.cz for private disclosure of any
security issues. This includes any crash in or related to filters, induced by
CLI or by receiving a malformed message by a protocol.

## How to contribute

You can either send a patch (prepared by git format-patch) to our mailing-list
bird-users@network.cz, or you can send just a link to your repository and the
commit hash you're contributing.

## What if your contribution isn't mergable

If your code needs minor updates to align with our standards / taste, we'll
just do these modifications ourselves and either add these as a separate commit
or just update your commit noting this fact in the commit message.

If your code has some major flaws, misses the point or introduces another
problem (e.g. performance issues), we'll refuse your patch. Then we'll either
try to tell you how we prefer to reach the goal, or we may reimplement your
ideas ourselves. We'll mention your original contribution in the commit message.

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

## Testing

There is another repository, https://gitlab.nic.cz/labs/bird-tools.git, where
we store our automatic tests in the netlab/ directory. This repository is quite
messy and you may need some help with it. We're planning to move the Netlab
suite into the main git repository; after we do that, we'll require every
contribution to add tests (if applicable, of course).

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
