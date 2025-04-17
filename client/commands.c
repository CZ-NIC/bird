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
  char *command;
  char *args;
  char *help;
  int is_real_cmd;
  int is_option;
};

static struct cmd_info command_table[] = {
#include "conf/commands.h"
};

struct cmd_node {
  struct cmd_node *sibling, *son, **plastson;
  struct cmd_info *cmd, *help;
  int len;
  u8 final;
  s8 prio;
  char token[1];
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

      new = &cmd_root;
      while (*c)
	{
	  /* Walk through the keywords in the command from start of the command
	   * to its end */
	  char *d = c;
	  while (*c && !isspace_(*c))
	    c++;
	  old = new;
	  for(new=old->son; new; new=new->sibling)
	    if (new->len == c-d && !memcmp(new->token, d, c-d))
	      break;
	  if (!new)
	    {
	      /* If new keyword is not stored yet */
	      int size = sizeof(struct cmd_node) + c-d;
	      new = malloc(size);
	      bzero(new, size);
	      /* Making this keyword child of the previons
	       * keyword in the command */
	      *old->plastson = new;
	      old->plastson = &new->sibling;
	      new->plastson = &new->son;
	      new->len = c-d;
	      memcpy(new->token, d, c-d);
	      new->prio = (new->len == 3 && (!memcmp(new->token, "roa", 3) || !memcmp(new->token, "rip", 3))) ? 0 : 1; /* Hack */
	    }
	  while (isspace_(*c))
	    c++;
	}

      /* In new there is now stored the last keyword in command.
       * Only this command is going to contain cmd and help */
      if (cmd->is_real_cmd)
	new->cmd = cmd;
      else
	new->help = cmd;

      if (cmd->is_option)
	old->final = 1;
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
cmd_display_help(struct cmd_node *m)
{
  /* Go through children of the base keyword. Each keyword has its own node. */
  for (struct cmd_node *mm = m->son; mm; mm = mm->sibling)
  {
    /* Print hints for all of the children of given keyword. */
    if (mm->help)
      cmd_do_display_help(mm->help);
    else if (mm->cmd)
      cmd_do_display_help(mm->cmd);
    else
    {
      /* This child does not contain hint, let's try its children instead
       * (this child might be first part of multi keyword command) */
      cmd_display_help(mm);
    }
  }
}

static struct cmd_node *
cmd_find_abbrev(struct cmd_node *root, char *cmd, int len, int *pambiguous)
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
cmd_list_ambiguous(struct cmd_node *root, char *cmd, int len)
{
  struct cmd_node *m;

  for(m=root->son; m; m=m->sibling)
    if (m->len > len && !memcmp(m->token, cmd, len))
      cmd_display_help(m);
}

void
cmd_help(char *cmd, int len)
{
  char *end = cmd + len;
  struct cmd_node *n, *m;
  char *z;
  int ambig;

  n = &cmd_root;
  while (cmd < end && !n->final)
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

  if (n && n->cmd)
    cmd_do_display_help(n->cmd);

  /* Currently no help for options */
  if (n->final)
    return;

  cmd_display_help(n);
}

static int
cmd_find_common_match(struct cmd_node *root, char *cmd, int len, int *pcount, char *buf)
{
  struct cmd_node *m;
  int best, best_prio, i;

  *pcount = 0;
  best = -1;
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
	  best = -1;
	}

      (*pcount)++;
      if (best < 0)
	{
	  strcpy(buf, m->token + len);
	  best = m->len - len;
	  best_prio = m->prio;
	}
      else
	{
	  i = 0;
	  while (i < best && i < m->len - len && buf[i] == m->token[len+i])
	    i++;
	  best = i;
	}
    }
  return best;
}

int
cmd_complete(char *cmd, int len, char *buf, int again)
{
  char *start = cmd;
  char *end = cmd + len;
  char *fin;
  struct cmd_node *n, *m;
  char *z;
  int ambig, cnt = 0, common;

  /* Find the last word we want to complete */
  for(fin=end; fin > start && !isspace_(fin[-1]); fin--)
    ;

  /* Find the context */
  n = &cmd_root;
  while (cmd < fin && n->son && !n->final)
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
	  input_start_list();
	  cmd_list_ambiguous(n, z, cmd-z);
	  input_stop_list();
	  return 0;
	}
      if (!m)
	return -1;
      n = m;
    }

  /* Completion of parameters is not yet supported */
  if (!n->son)
    return -1;

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
  if (common > 0)
    {
      buf[common] = 0;
      return 1;
    }
  if (!again)
    return -1;
  input_start_list();
  cmd_list_ambiguous(n, fin, end-fin);
  input_stop_list();
  return 0;
}

char *
cmd_expand(char *cmd)
{
  struct cmd_node *n, *m;
  char *c, *b, *args;
  int ambig;

  args = c = cmd;
  n = &cmd_root;
  while (*c && !n->final)
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
    }
  if (!n->cmd)
    {
      puts("No such command. Press `?' for help.");
      return NULL;
    }
  b = malloc(strlen(n->cmd->command) + strlen(args) + 1);
  sprintf(b, "%s%s", n->cmd->command, args);
  return b;
}
