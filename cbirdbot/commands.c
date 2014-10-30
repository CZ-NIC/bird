/*
 *	BIRD Client -- Command Handling
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *	          2014 Pavel Spirek <pavel.spirek@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "client.h"

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))

struct cmd_info {
	char *command;
	char *args;
	char *help;
	int is_real_cmd;
};

static struct cmd_info command_table[] = {
#include "commands.h"
};

struct cmd_node {
	struct cmd_node *sibling, *son, **plastson;
	struct cmd_info *cmd, *help;
	int len;
	signed char prio;
	char token[1];
};

int
lastnb(char *str, int i)
{
	while (i--)
		if ((str[i] != ' ') && (str[i] != '\t'))
			return str[i];

	return 0;
}

static struct cmd_node cmd_root;

void
cmd_build_tree(void)
{
	unsigned int i;

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
			while (*c && !isspace(*c))
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
				new->prio = (new->len == 3 && !memcmp(new->token, "roa", 3)) ? 0 : 1; /* Hack */
			}
			old = new;
			while (isspace(*c))
				c++;
		}
		if (cmd->is_real_cmd)
			old->cmd = cmd;
		else
			old->help = cmd;
	}
}

/*static void
cmd_do_display_help(struct cmd_info *c)
{
	char buf[strlen(c->command) + strlen(c->args) + 4];

	sprintf(buf, "%s %s", c->command, c->args);
	printf("%-45s  %s\n", buf, c->help);
}*/

/*static void
cmd_display_help(struct cmd_info *c1, struct cmd_info *c2)
{
	if (c1)
		cmd_do_display_help(c1);
	else if (c2)
		cmd_do_display_help(c2);
}*/

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

static char*
cmd_list_ambiguous(struct cmd_node *root, char *cmd, int len)
{
	struct cmd_node *m;
	int cmd_count = 0;
	struct cmd_info* cmdinf;
	char* out;
	char buf[256];

	for(m=root->son; m; m=m->sibling)
		cmd_count++;

	out = malloc((cmd_count + 2) * 256); //radek max 256 znaku
	if(out == NULL)
		return NULL;

	strcpy(out, "Ambiguous command, possible expansions are:\n");

	for(m=root->son; m; m=m->sibling) {
		if(m->help)
			cmdinf = m->help;
		else
			cmdinf = m->cmd;

		if (m->len > len && !memcmp(m->token, cmd, len)) {
			//cmd_display_help(m->help, m->cmd);
			sprintf(buf, "%s\t%s\t - %s\n", cmdinf->command, cmdinf->args, cmdinf->help);
			strcat(out, buf);
		}
	}

	return out;
}

char* compose_help(struct cmd_node* m, struct cmd_node* n) {
	int cmd_count = 0;
	struct cmd_info* cmdinf;
	char* out;
	char buf[256];

	for (m=n->son; m; m=m->sibling)
		cmd_count++;

	out = malloc((cmd_count + 1) * 256); //radek max 256 znaku
	if(out == NULL)
		return NULL;

	out[0] = '\0';

	if(n->cmd != NULL) {
		sprintf(buf, "%s\t%s\t - %s\n", n->cmd->command, n->cmd->args, n->cmd->help);
		strcat(out, buf);
	}

	//cmd_display_help(n->cmd, NULL);
	for (m=n->son; m; m=m->sibling) {
		//cmd_display_help(m->help, m->cmd);

		if(m->help)
			cmdinf = m->help;
		else
			cmdinf = m->cmd;

		sprintf(buf, "%s\t%s\t - %s\n", cmdinf->command, cmdinf->args, cmdinf->help);
		strcat(out, buf);
	}

	return out;
}

char*
cmd_help(char *cmd, int len)
{
	char *end = cmd + len;
	struct cmd_node *n, *m;
	char *z;
	int ambig;
	char* out;

	n = &cmd_root;
	while (cmd < end)
	{
		if (isspace(*cmd))
		{
			cmd++;
			continue;
		}
		z = cmd;
		while (cmd < end && !isspace(*cmd))
			cmd++;
		m = cmd_find_abbrev(n, z, cmd-z, &ambig);
		if (ambig)
		{
			out = cmd_list_ambiguous(n, z, cmd-z);
			return out;
		}
		if (!m)
			break;
		n = m;
	}

	out = compose_help(m, n);
	return out;
}

char *
cmd_expand(char *cmd, int* is_ambig)
{
	struct cmd_node *n, *m;
	char *c, *b, *args;
	int ambig;

	args = c = cmd;
	n = &cmd_root;
	while (*c)
	{
		if (isspace(*c))
		{
			c++;
			continue;
		}
		b = c;
		while (*c && !isspace(*c))
			c++;
		m = cmd_find_abbrev(n, b, c-b, &ambig);
		if (!m)
		{
			if (!ambig)
				break;

			if(is_ambig != NULL) {
				*is_ambig = 1;
				return cmd_list_ambiguous(n, b, c-b);
			}
			else {
				return NULL;
			}
		}
		args = c;
		n = m;
	}
	if (!n->cmd)
	{
		return NULL;
	}

	b = malloc(strlen(n->cmd->command) + strlen(args) + 1);
	sprintf(b, "%s%s", n->cmd->command, args);
	return b;
}
