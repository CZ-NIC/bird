/* commands.c */

int lastnb(char *str, int i);

void cmd_build_tree(void);
char* cmd_help(char *cmd, int len);
int cmd_complete(char *cmd, int len, char *buf, int again);
char *cmd_expand(char *cmd, int* is_ambig);

/* cbirdbot.c */

void send_message(char* jid, char* mbody);
int check_user_auth(char* jid);
