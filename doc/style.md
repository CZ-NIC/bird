## Commit messages

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
- use function / variable / file names as the title
- use vague words (minor fix, just a typo, …)
- imply security impact
- mention issues, branches or other volatile stuff

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
  - `Issue: #<num>` if related to [BIRD internal issue](../CONTRIBUTING.md#issue-tracker) and you know that number
  - `Target: patch` if eligible for stable patch release and not CI
  - `Target: minor` otherwise, if not CI
- personal attribution (formatted as name and, if public, e-mail address)
  - Co-Authored-By: directly collaborated on the code
  - Reported-By: reported the issue and possibly provided crashdumps or other debug data
  - Identified-By: did significant work on finding out the algorithmic cause
  - Reproduced-By: did significant work on reliably reproducing the issue in testbed
  - Signed-Off-By: reviewed the code and approves
  - Original-By: created a previous version of the update
  - Edited-By: did significant updates on the original work
- relevant links
  - `Introduced-In: commithash` for fixing regressions
  - `Source: url` for external links

**Do not**, unless really appropriate:

- use non-ascii characters outside person names (fancy punctuation is allowed though)
- reference issues with closing remarks (`This closes #425.`)
- write in LinkedLingo or any other fancy style

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
- opening and closing curly braces of a block should be on a separate line (for all types of blocks except for struct/union definitions)
- in case only single statement follows after `if` or `else`, it need not have braces around it (even if the statement itself has multiple lines)
- null check of pointers should be simple `if (pointer)` instead of a `if (pointer == NULL)`
- even for single line comments use `/* */` instead of a `//`
- ...

For more information about code refer to the technical documentation.
