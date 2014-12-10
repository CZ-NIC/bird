#define PRINTF_XMPP_RED(format, args...)	 printf("\x1B[31mXMPP:\x1B[0m "format"\n", ##args);
#define PRINTF_XMPP_GREEN(format, args...)	 printf("\x1B[32mXMPP:\x1B[0m "format"\n", ##args);
#define PRINTF_XMPP_YELLOW(format, args...)	 printf("\x1B[33mXMPP:\x1B[0m "format"\n", ##args);

/* commands.c */

int lastnb(char *str, int i);

void cmd_build_tree(void);
char* cmd_help(char *cmd, int len);
int cmd_complete(char *cmd, int len, char *buf, int again);
char *cmd_expand(char *cmd, int* is_ambig);

/* cbirdbot.c */

void send_message(char* jid, int is_muc, char* mbody);
int check_user_auth(char* jid, int is_muc);
