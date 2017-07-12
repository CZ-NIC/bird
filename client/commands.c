/*
 *	BIRD Client -- Command Handling
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "client/client.h"

struct cmd_info {
  /* use for build cmd tree and cli commands */
  char *command;
  char *args;
  char *help;

  /* only for build tree */
  int is_real_cmd;
  u32 flags;			/* Mask of (CLI_SF_*) */
};

static struct cmd_info command_table[] = {
#include "conf/commands.h"
};

struct cmd_node {
  struct cmd_node *sibling;
  struct cmd_node *son;
  struct cmd_node **plastson;	/* Helping pointer to son */
  struct cmd_info *cmd;		/* Short info */
  struct cmd_info *help;	/* Detailed info */
  signed char prio; 		/* Priority */
  u32 flags;			/* Mask of (CLI_SF_*) */
  uint len; 			/* Length of string in token */
  char token[1];		/* Name of command */
};

static struct cmd_node cmd_root;

#define isspace_(X) isspace((unsigned char) (X))

void
cmd_build_tree(void)
{
  uint i;

  cmd_root.plastson = &cmd_root.son;

  for(i=0; i<ARRAY_SIZE(command_table); i++)
    {
      struct cmd_info *cmd = &command_table[i];
      struct cmd_node *old, *new;
      char *c = cmd->command;

      old = &cmd_root;
      while (*c)
	{
	  char *d = c;
	  while (*c && !isspace_(*c))
	    c++;
	  for(new=old->son; new; new=new->sibling)
	    if (new->len == c-d && !memcmp(new->token, d, c-d))
	      break;
	  if (!new)
	    {
	      int size = sizeof(struct cmd_node) + c-d;
	      new = malloc(size);
	      bzero(new, size);
	      *old->plastson = new;
	      old->plastson = &new->sibling;
	      new->plastson = &new->son;
	      new->len = c-d;
	      memcpy(new->token, d, c-d);
	      new->prio = (new->len == 3 && (!memcmp(new->token, "roa", 3) || !memcmp(new->token, "rip", 3))) ? 0 : 1; /* Hack */
	    }
	  old = new;
	  while (isspace_(*c))
	    c++;
	}
      if (cmd->is_real_cmd)
	old->cmd = cmd;
      else
	old->help = cmd;
      old->flags |= cmd->flags;
    }
}

static void
cmd_do_display_help(struct cmd_info *c)
{
  char buf[strlen(c->command) + strlen(c->args) + 4];

  sprintf(buf, "%s %s", c->command, c->args);
  printf("%-45s  %s\n", buf, c->help);
}

static void
cmd_display_help(struct cmd_info *c1, struct cmd_info *c2)
{
  if (c1)
    cmd_do_display_help(c1);
  else if (c2)
    cmd_do_display_help(c2);
}

static struct cmd_node *
cmd_find_abbrev(struct cmd_node *root, const char *cmd, uint len, int *pambiguous)
{
  struct cmd_node *m, *best = NULL, *best2 = NULL;

  *pambiguous = 0;
  for(m=root->son; m; m=m->sibling)
    {
      if (m->len == len && !memcmp(m->token, cmd, len))
	return m;
      if (m->len > len && !memcmp(m->token, cmd, len))
	{
	  if (best && best->prio > m->prio)
	    continue;
	  if (best && best->prio == m->prio)
	    best2 = best;
	  best = m;
	}
    }
  if (best2)
    {
      *pambiguous = 1;
      return NULL;
    }
  return best;
}

static void
cmd_list_ambiguous(struct cmd_node *root, const char *cmd, uint len)
{
  struct cmd_node *m;

  for(m=root->son; m; m=m->sibling)
    if (m->len > len && !memcmp(m->token, cmd, len))
      if (complete)
	printf("%s\n", m->token);
      else
	cmd_display_help(m->help, m->cmd);

  list *syms = cli_get_symbol_list();
  if (!syms)
    return;

  struct cli_symbol *sym;
  WALK_LIST(sym, *syms)
  {
    if ((sym->flags & root->flags) && sym->len > len && memcmp(sym->name, cmd, len) == 0)
      printf("%s\n", sym->name);
  }
}

void
cmd_help(const char *cmd, int len)
{
  const char *end = cmd + len;
  struct cmd_node *n, *m;
  const char *z;
  int ambig;

  n = &cmd_root;
  while (cmd < end)
    {
      if (isspace_(*cmd))
	{
	  cmd++;
	  continue;
	}
      z = cmd;
      while (cmd < end && !isspace_(*cmd))
	cmd++;
      m = cmd_find_abbrev(n, z, cmd-z, &ambig);
      if (ambig)
	{
	  cmd_list_ambiguous(n, z, cmd-z);
	  return;
	}
      if (!m)
	break;
      n = m;
    }
  cmd_display_help(n->cmd, NULL);
  for (m=n->son; m; m=m->sibling)
    cmd_display_help(m->help, m->cmd);
}

/*
 * Return length of common prefix of all matches,
 * Write common prefix string into buf
 */
static int
cmd_merge_match_with_others(int max_common_len, const char *token_name, int token_len, char *buf, int from)
{
  if (max_common_len < 0)
  {
    /* For a case that we'll have exactly one match */
    strcpy(buf, token_name + from);
    max_common_len = token_len - from;
  }
  else
  {
    int i = 0;
    while (i < max_common_len && i < token_len - from && buf[i] == token_name[from+i])
      i++;
    max_common_len = i;
  }
  return max_common_len;
}

/*
 * Return length of common prefix of all matches,
 * Write count of all matches into pcount,
 * Write common prefix string into buf
 */
static int
cmd_find_common_match(struct cmd_node *root, const char *cmd, uint len, int *pcount, char *buf)
{
  struct cmd_node *m;
  int max_common_len;
  int best_prio;

  *pcount = 0;
  max_common_len = -1;
  best_prio = -1;
  for(m=root->son; m; m=m->sibling)
    {
      if (m->len < len || memcmp(m->token, cmd, len))
	continue;

      if (best_prio > m->prio)
	continue;

      if (best_prio < m->prio)
	{
	  *pcount = 0;
	  max_common_len = -1;
	}

      if (max_common_len < 0)
	best_prio = m->prio;

      (*pcount)++;
      max_common_len = cmd_merge_match_with_others(max_common_len, m->token, m->len, buf, len);
    }

  list *syms = cli_get_symbol_list();
  if (!syms)
    return max_common_len;

  struct cli_symbol *sym;
  WALK_LIST(sym, *syms)
  {
    if (!(sym->flags & root->flags))
      continue;

    if (sym->len < len || memcmp(sym->name, cmd, len))
      continue;

    (*pcount)++;
    max_common_len = cmd_merge_match_with_others(max_common_len, sym->name, sym->len, buf, len);
  }

  return max_common_len;
}

int
cmd_complete(const char *cmd, int len, char *buf, int again)
{
  const char *start = cmd;
  const char *end = cmd + len;
  const char *fin;
  struct cmd_node *n, *m = NULL;
  const char *z;
  int ambig, cnt = 0, common;

  /* Find the last word we want to complete */
  for(fin=end; fin > start && !isspace_(fin[-1]); fin--)
    ;

  /* Find the context */
  n = &cmd_root;
  while (cmd < fin)
    {
      if (isspace_(*cmd))
	{
	  cmd++;
	  continue;
	}
      z = cmd;
      while (cmd < fin && !isspace_(*cmd))
	cmd++;
      m = cmd_find_abbrev(n, z, cmd-z, &ambig);
      if (ambig)
	{
	  if (!again)
	    return -1;
	  if (!complete)
	    input_start_list();
	  cmd_list_ambiguous(n, z, cmd-z);
	  if (!complete)
	    input_stop_list();
	  return 0;
	}
      if (!m)
	return -1;

      /* Try skip a parameter/word */
      if (m->flags & CLI_SF_PARAMETER)
      {
	z = cmd;

	/* Skip spaces before parameter */
	while (cmd < fin && isspace(*cmd))
	  cmd++;

	/* Skip one parameter/word */
	while (cmd < fin && !isspace(*cmd))
	  cmd++;

	/* Check ending of parameter */
	if (isspace(*cmd))
	{
	  if (m->flags & CLI_SF_OPTIONAL)
	    m = n;
	  continue;
	}
	else
	  cmd = z;
      }

      /* Do not enter to optional command nodes */
      if (!(m->flags & CLI_SF_OPTIONAL))
	n = m;
    }

  /* Enter to the last command node */
  if (m && (m->flags & CLI_SF_PARAMETER))
    n = m;

  /* We know the context, let's try to complete */
  common = cmd_find_common_match(n, fin, end-fin, &cnt, buf);
  if (!cnt)
    return -1;
  if (cnt == 1)
    {
      buf[common++] = ' ';
      buf[common] = 0;
      return 1;
    }
  if (!complete && (common > 0))
    {
      buf[common] = 0;
      return 1;
    }
  if (!again)
    return -1;
  if (!complete)
    input_start_list();
  cmd_list_ambiguous(n, fin, end-fin);
  if (!complete)
    input_stop_list();
  return 0;
}

char *
cmd_expand(char *cmd)
{
  struct cmd_node *n, *m, *last_real_cmd = NULL;
  char *c, *b, *args, *lrc_args = NULL;
  int ambig;

  args = c = cmd;
  n = &cmd_root;
  while (*c)
    {
      if (isspace_(*c))
	{
	  c++;
	  continue;
	}
      b = c;
      while (*c && !isspace_(*c))
	c++;
      m = cmd_find_abbrev(n, b, c-b, &ambig);
      if (!m)
	{
	  if (!ambig)
	    break;
	  puts("Ambiguous command, possible expansions are:");
	  cmd_list_ambiguous(n, b, c-b);
	  return NULL;
	}

      args = c;
      n = m;

      if (m->cmd)
      {
	last_real_cmd = m;
	lrc_args = c;
      }
    }

  if (!n->cmd && !last_real_cmd)
    {
      puts("No such command. Press `?' for help.");
      return NULL;
    }

  if (last_real_cmd && last_real_cmd != n)
  {
    n = last_real_cmd;
    args = lrc_args;
  }
  b = malloc(strlen(n->cmd->command) + strlen(args) + 1);
  sprintf(b, "%s%s", n->cmd->command, args);
  return b;
}
