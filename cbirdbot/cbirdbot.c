#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <loudmouth/loudmouth.h>

#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>

#include "client.h"
#include "sysdep/paths.h"

#define PIP_RD	0
#define PIP_WR 1

/****************************** SETTINGS ************************************/

//#define PATH_CONTROL_SOCKET		"/usr/local/var/run/bird.ctl"

//#define PATH_CONFIG				"/etc/birdbot/birdbot.conf"
#define PATH_CONFIG				PATH_BOT_CONFIG_FILE

#define PATH_LOCKFILE			"/var/run/birdbot.lock"

/*****************************************************************************/

char*	superusers[100];
char*	restricted_users[100];

char*	birdbot_jid;
char*	birdbot_pw;

LmConnection	*xmpp_conn;
pthread_t		xmpp_keepalive_tid;
GMainLoop		*main_loop = NULL;

void send_message(char* jid, char* mbody);

typedef struct {
	char* jid;
	int bird_ready;
	int sock_fd;
	int termpipe_fd[2];
}conn_t;

typedef struct clitem {
	conn_t* connection;
	struct clitem* next;
}conn_listitem_t;

conn_listitem_t* conn_list = NULL;

pthread_mutex_t listmtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t xmppmtx = PTHREAD_MUTEX_INITIALIZER;

/**
 * Prida objekt sock. spojeni na konec seznamu
 * @param	conn Odkaz na objekt
 * @return	0 = OK, -1 = Chyba
 */
int list_add_end(conn_t* conn) {
	conn_listitem_t* c_tmp;

	pthread_mutex_lock(&listmtx);

	c_tmp = conn_list;

	if(conn_list == NULL) {
		conn_list = (conn_listitem_t*) malloc(sizeof(conn_listitem_t));
		if(conn_list == NULL) {
			pthread_mutex_unlock(&listmtx);
			return -1;
		}
		conn_list->connection = conn;
		conn_list->next = NULL;
	}
	else {
		while(c_tmp->next != NULL) {
			c_tmp = c_tmp->next;
		}
		c_tmp->next = (conn_listitem_t*) malloc(sizeof(conn_listitem_t));
		if(c_tmp->next == NULL) {
			pthread_mutex_unlock(&listmtx);
			return -1;
		}
		c_tmp->next->connection = conn;
		c_tmp->next->next = NULL;
	}

	pthread_mutex_unlock(&listmtx);
	return 0;
}

/**
 * Smaze spojeni ze seznamu
 * @param jid	JabberID uzivatele
 * @return		O = OK, -1 = Chyba
 */
int list_remove(char* jid) {
	conn_listitem_t* c_tmp;
	conn_listitem_t* c_tmp_prev = NULL;

	pthread_mutex_lock(&listmtx);

	if(conn_list == NULL) {
		pthread_mutex_unlock(&listmtx);
		return -1;
	}

	c_tmp = conn_list;

	while(c_tmp != NULL) {
		if(strcmp((c_tmp->connection)->jid, jid) == 0) {
			if(c_tmp_prev == NULL)	//prvni polozka seznamu
				conn_list = c_tmp->next;
			else
				c_tmp_prev->next = c_tmp->next;
			free(c_tmp);
			pthread_mutex_unlock(&listmtx);
			return 0;
		}
		c_tmp_prev = c_tmp;
		c_tmp = c_tmp->next;
	}

	pthread_mutex_unlock(&listmtx);
	return -1;
}

/**
 * Najde v seznamu spojeni s danym JabberID
 * @param jid	JabberID uzivatele
 * @return		Odkaz na spojeni, NULL = Chyba
 */
conn_t* find_connection(char* jid) {
	conn_listitem_t* c_tmp = conn_list;

	pthread_mutex_lock(&listmtx);

	while(c_tmp != NULL) {
		if(strcmp((c_tmp->connection)->jid, jid) == 0) {
			pthread_mutex_unlock(&listmtx);
			return c_tmp->connection;
		}
		c_tmp = c_tmp->next;
	}

	pthread_mutex_unlock(&listmtx);
	return NULL;
}

/**
 * Vypise seznam spojeni (DEBUG)
 */
void print_list(void) {
	conn_listitem_t* c_tmp = conn_list;
	while(c_tmp != NULL) {
		puts((c_tmp->connection)->jid);
		c_tmp = c_tmp->next;
	}
	puts("-----");
}

/**
 * Ukonci program s chybovou hlaskou
 * @param s		Text chyby
 */
void die(char* s) {
	puts(s);
	exit(-1);
}

/**
 * V zadanem retezci preskoci pocatecni bile znaky
 * @param str	Retezec
 * @return		Prvni viditelny znak
 */
char* skipblank(char* str) {
	while((*str == ' ') || (*str == '\t'))
		str++;
	return str;
}

/**
 * Vytvori nove spojeni se socketem BIRD a prida ho do seznamu
 * @param jid	JabberID uzivatele
 * @return		0 = OK, -1 = Chyba
 */
int create_connection(char* jid) {
	struct sockaddr_un sa;
	conn_t* conn;

	conn = (conn_t*) malloc(sizeof(conn_t));
	if(conn == NULL)
		return -1;

	conn->bird_ready = 0;

	if((conn->sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		free(conn);
		return -1;
	}

	memset(&sa, 0, sizeof(struct sockaddr_un));
	//inet_aton(BIRD_host, &(adr.sin_addr));
	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, PATH_CONTROL_SOCKET);
	//adr.sin_port = htons(BIRD_host_port);

	if(connect(conn->sock_fd, (struct sockaddr*) &sa, SUN_LEN(&sa)) < 0) {
		free(conn);
		return -1;
	}

	fcntl(conn->sock_fd, F_SETFL, O_NONBLOCK);

	conn->jid = (char*) malloc(strlen(jid) + 1);
	strcpy(conn->jid, jid);

	if(pipe(conn->termpipe_fd) != 0)
		puts("chyba vytvareni roury");

	list_add_end(conn);

	return 0;
}

int close_connection(conn_t* conn) {
	close(conn->sock_fd);
	close(conn->termpipe_fd[PIP_RD]);
	close(conn->termpipe_fd[PIP_WR]);
	return 0;
}

int delete_connection(conn_t* conn) {

	if(list_remove(conn->jid) != 0)
		return -1;

	close_connection(conn);

	free(conn->jid);
	free(conn);

	return 0;
}

/**
 * Ukonci vlakno spojeni a smaze ho ze seznamu
 * @param conn	Odkaz na objekt
 * @return		0 = OK, -1 = Chyba
 */
int connection_stop(conn_t* conn) {
	if(write(conn->termpipe_fd[PIP_WR], "stop", 5) == 5)
		return 0;
	else
		return -1;
}

/**
 * Korektni ukonceni programu - zavre vsechna spojeni
 */
void exit_clean(int exitno) {
	conn_listitem_t* c_tmp = conn_list;
	char** ptr;
	int timeout = 20;

	while(c_tmp != NULL) {
		connection_stop(c_tmp->connection);
		c_tmp = c_tmp->next;
	}

	free(birdbot_jid);
	free(birdbot_pw);

	ptr = superusers;
	while(*ptr != NULL) {
		free(*ptr);
		ptr++;
	}

	ptr = restricted_users;
	while(*ptr != NULL) {
		free(*ptr);
		ptr++;
	}

	pthread_kill(xmpp_keepalive_tid, SIGTERM);

	//pockame na ukonceni vsech vlaken spojeni
	while((conn_list != NULL) && timeout) {
		usleep(100000);
		timeout--;
	}

	exit(exitno);
}

/**
 * Zpracuje odpoved BIRD serveru
 * @param in	Retezec surovych dat ze socketu
 * @return		Cisty text (nove alokovany), NULL = Chyba
 */
char* process_bird_output(char* in) {
	char* out = malloc(4096);
	char* line_end;
	int code;

	if(out == NULL)
		return NULL;

	out[0] = '\0';

	if(in[0] == '+') {
		//asynchroni zprava serveru
		sprintf(out, "\n>>> %s", in + 1);
		return out;
	}

	while((line_end = strchr(in, '\n')) != NULL) {
		*line_end = '\0';
		if((strlen(in) > 4) && (sscanf(in, "%04d", &code) == 1) && ((in[4] == ' ') || (in[4] == '-'))) {
			//platny radek
			if(strlen(in) > 5) {
				strcat(out, "\n");
				strcat(out, in + 5);
			}
		}

		in = line_end + 1;
	}

	return out;
}

/**
 * Vlakno zajistujici cteni dat z BIRD socketu pro jednotlive uzivatele
 * @param args	Odkaz na objekt (conn_t*) spojeni
 */
void* connection_run_thread(void* args) {
	char tmp[4096];
	conn_t* conn = (conn_t*) args;
	fd_set fds;
	int maxfd;

	maxfd = conn->sock_fd;
	if(conn->termpipe_fd[PIP_RD] > maxfd)
		maxfd = conn->termpipe_fd[PIP_RD];

	printf("Vytvoreno vlakno spojeni %s\n", conn->jid);
	while(1) {
		FD_ZERO(&fds);
		FD_SET(conn->sock_fd, &fds);
		FD_SET(conn->termpipe_fd[PIP_RD], &fds);

		select(maxfd + 1, &fds, NULL, NULL, NULL);

		if(FD_ISSET(conn->termpipe_fd[PIP_RD], &fds)) {
			break;
		}
		else if(FD_ISSET(conn->sock_fd, &fds)) {
			int bytes;
			char* msg;

			bytes = recv(conn->sock_fd, tmp, 4095, MSG_DONTWAIT);
			if(bytes <= 0)
				break;

			tmp[bytes] = '\0';
			printf("Prijato ze socketu %d bytu: %s\n", bytes, tmp);

			msg = process_bird_output(tmp);


			if(!conn->bird_ready) {
				if(strstr(msg, "BIRD ") != NULL) {
					if(check_user_auth(conn->jid) < 2) {
						write(conn->sock_fd, "restrict\n", 9);
					}
					conn->bird_ready = 1;
				}
			}

			send_message(conn->jid, msg);
			free(msg);
		}
	}


	printf("Vlakno spojeni %s skonceno\n", conn->jid);

	if(delete_connection(conn) != 0)
		puts("chyba vymazu spojeni");

	return NULL;
}

/**
 * Spusti vlakno spojeni s BIRD socketem
 * @param conn	Odkaz na spojeni
 * @return		0 = OK, -1 = Chyba
 */
int connection_run(conn_t* conn) {
	pthread_t tid;
	pthread_create(&tid, NULL, connection_run_thread, conn);
	if(tid != 0)
		return -1;

	pthread_detach(tid);
	return 0;
}

/**
 * Posle zpravu pres XMPP
 * @param jid		JabberID uzivatele
 * @param mbody		Text tela zpravy
 */
void send_message(char* jid, char* mbody) {
    LmMessage*	msg;

    pthread_mutex_lock(&xmppmtx);

	msg = lm_message_new_with_sub_type(jid, LM_MESSAGE_TYPE_MESSAGE, LM_MESSAGE_SUB_TYPE_CHAT);
	lm_message_node_add_child (msg->node, "body", mbody);
	lm_connection_send(xmpp_conn, msg, NULL);
	lm_message_unref(msg);

	pthread_mutex_unlock(&xmppmtx);
}

/**
 * Posle HTML napovedu k prikazu
 * @param jid		JabberID uzivatele
 * @param mbody		Text tela zpravy
 */
void send_help_html(char* jid, char* mbody) {
	LmMessage*	msg;
	LmMessageNode *html, *htbody, *p;
	char* msg_arr[50][3];
	char* line_end;
	char *tab1, *tab2;
	char *in, *arr;
	int lines;
	int i = 0;

	arr = malloc(strlen(mbody) + 1);
	if(arr == NULL)
		return;

	in = arr;

	strcpy(in, mbody);

	while((line_end = strchr(in, '\n')) != NULL) {
		*line_end = '\0';

		tab1 = strchr(in, '\t');
		if(tab1 == NULL)
			break;

		tab2 = strstr(in, "\t - ");
		if(tab2 == NULL)
			break;

		msg_arr[i][2] = alloca(100);
		strncpy(msg_arr[i][2], tab2 + 4, 99);
		*tab2 = '\0';

		msg_arr[i][1] = alloca(100);
		strncpy(msg_arr[i][1], tab1 + 1, 95);
		strcat(msg_arr[i][1], "    ");
		*tab1 = '\0';

		msg_arr[i][0] = alloca(25);
		strncpy(msg_arr[i][0], in, 20);
		strcat(msg_arr[i][0], "    ");

		i++;
		if(i >= 50)
			break;

		in = line_end + 1;
	}

	lines = i;

	pthread_mutex_lock(&xmppmtx);
	msg = lm_message_new_with_sub_type(jid, LM_MESSAGE_TYPE_MESSAGE, LM_MESSAGE_SUB_TYPE_CHAT);
	lm_message_node_add_child(msg->node, "body", mbody);

	html = lm_message_node_add_child(msg->node, "html", NULL);
	lm_message_node_set_attribute(html, "xmlns", "http://jabber.org/protocol/xhtml-im");
	htbody = lm_message_node_add_child(html, "body", NULL);
	lm_message_node_set_attribute(htbody, "xmlns", "http://www.w3.org/1999/xhtml");
	lm_message_node_set_attribute(htbody, "lang", "en");
	p = lm_message_node_add_child(htbody, "p", NULL);

	for(i = 0; i < lines; i++) {
		lm_message_node_add_child(p, "br", NULL);
		lm_message_node_add_child(p, "strong", msg_arr[i][0]);
		lm_message_node_add_child(p, "em", msg_arr[i][1]);
		lm_message_node_add_child(p, "span", msg_arr[i][2]);
	}

	lm_connection_send(xmpp_conn, msg, NULL);
	lm_message_unref(msg);
	pthread_mutex_unlock(&xmppmtx);

	free(arr);
}

/**
 * Zpracuje prichozi zpravu z XMPP a pripadne odesle data na BIRD socket
 * @param jid		JabberID uzivatele
 * @param cmdtext	Text zpravy z XMPP
 * @param auth_lvl	Uroven opravneni uzivatele s danym JID (1 = Restricted, 2 = Superuser)
 * @return			0 = OK, -1 = Chyba
 */
int process_cmd(char* jid, char* cmdtext, int auth_lvl) {
	conn_t* conn;
	char* s;
	int ambig_expansion = 0;

	conn = find_connection(jid);

	if (lastnb(cmdtext, strlen(cmdtext)) == '?')
	{
		char* c = cmd_help(cmdtext, strlen(cmdtext));
		send_help_html(jid, c);
		free(c);

		return 0;
	}

	s = cmd_expand(cmdtext, &ambig_expansion);

	if(s == NULL) {
		send_message(jid, "No such command. Press `?' for help.");
		return 0;
	}

	if(ambig_expansion) {
		send_message(jid, s);
		free(s);
		return 0;
	}

	if(strcmp(s, "haltbot") == 0) {
		if(auth_lvl == 2) {
			free(s);
			exit_clean(0); //konec programu
		}
		else {
			send_message(jid, "You are not authorized to kill bots.");
			free(s);
			return 0;
		}
	}

	if(conn == NULL) {
		if(strcmp(s, "connect") == 0) {
			if(create_connection(jid) == 0) {
				conn = find_connection(jid);
				connection_run(conn);
				send_message(jid, "Connected.");
			}
			else {
				send_message(jid, "Error connecting to BIRD socket.");
				free(s);
				return -1;
			}
		}
		else {
			send_message(jid, "Not connected. Write 'connect' to connect.");
		}
	}
	else { //jsme pripojeni k BIRD socketu
		if(strcmp(s, "connect") == 0) {
			send_message(jid, "Already connected.");
		}
		else if((strcmp(s, "exit") == 0) || (strcmp(s, "quit") == 0)) {
			connection_stop(conn);
			send_message(jid, "Bye.");
		}
		else {
			if(conn->bird_ready) {
				printf("posilam %s\n", s);
				write(conn->sock_fd, s, strlen(s));
				write(conn->sock_fd, "\n", 1);
			}
			else {
				puts("BIRD not ready");
			}
		}
	}

	free(s);
	return 0;
}


/**
 * Zjisti, zda je zadane JID clenem superusers nebo restricted users
 * @param jid	JabberID uzivatele
 * @return		0 = Neopravnen, 1 = Restricted user, 2 = Superuser
 */
int check_user_auth(char* jid) {
	int user_auth_lvl = 0;
	char* ptr;
	int basejid_len;
	int i;

	ptr = strchr(jid, '/'); //trim extended jid
	if(ptr != NULL)
		basejid_len = ptr - jid;
	else
		basejid_len = strlen(jid);

	for(i = 0; /*i < sizeof(superusers)/sizeof(char*)*/superusers[i] != NULL; i++) {
		if(strncmp(jid, superusers[i], basejid_len) == 0) {
			user_auth_lvl = 2;
			break;
		}
	}

	if(user_auth_lvl == 0) {
		for(i = 0; /*i < sizeof(restricted_users)/sizeof(char*)*/restricted_users[i] != NULL; i++) {
			if(strncmp(jid, restricted_users[i], basejid_len) == 0) {
				user_auth_lvl = 1;
				break;
			}
		}
	}

	return user_auth_lvl;
}

/**
 * Reakce na SIGTERM (ciste ukonceni demona)
 */
void sigterm_handler(int n) {
	exit_clean(0);
}

/**
 * Nacte nastaveni z konfiguracniho souboru
 * @param path	Cesta k souboru
 * @return		0 = OK, -1 = Chyba
 */
int load_config(char* path) {
	///parse config file
	FILE* fconf;
	char line[101];
	char* lptr;
	char* ptr;
	int i = 0;

	memset(superusers, 0, sizeof(superusers));
	memset(restricted_users, 0, sizeof(restricted_users));

	fconf = fopen(path, "rt");
	if(fconf == NULL) {
		puts("Cannot open config file!");
		return -1;
	}

	while(fgets(line, 100, fconf) != NULL) {
		if(strstr(line, "XMPP:") != NULL)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		if((lastnb(line, strlen(line) - 1) == ':') || (line[0] == '\n') || (line[0] == '\r'))
			break;

		lptr = skipblank(line);
		ptr = malloc(strlen(lptr) + 1);
		strncpy(ptr, lptr, strlen(lptr) - 1);
		if(i == 0)
			birdbot_jid = ptr;
		else if(i == 1)
			birdbot_pw = ptr;

		i++;
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strstr(line, "SUPERUSERS:") != NULL)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		if((lastnb(line, strlen(line) - 1) == ':') || (line[0] == '\n') || (line[0] == '\r'))
			break;

		lptr = skipblank(line);
		ptr = malloc(strlen(lptr) + 1);
		strncpy(ptr, lptr, strlen(lptr) - 1);
		if(i < 99) {
			superusers[i] = ptr;
			i++;
		}
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strstr(line, "RESTRICTED:") != NULL)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		if((lastnb(line, strlen(line) - 1) == ':') || (line[0] == '\n') || (line[0] == '\r'))
			break;

		lptr = skipblank(line);
		ptr = malloc(strlen(lptr) + 1);
		strncpy(ptr, lptr, strlen(lptr) - 1);
		if(i < 99) {
			restricted_users[i] = ptr;
			i++;
		}
	}

	return 0;
}

void print_config(void) {
	char** ptr2;

	printf("Birdbot JID: %s\n", birdbot_jid);
	printf("Birdbot pass: %s\n", birdbot_pw);

	ptr2 = superusers;
	puts("Superusers:");
	while(*ptr2 != NULL) {
		puts(*ptr2);
		ptr2++;
	}

	ptr2 = restricted_users;
	puts("Restricted users:");
	while(*ptr2 != NULL) {
		puts(*ptr2);
		ptr2++;
	}
}

/**
 * Ziska uzivatelske jmeno z JID
 * @param jid	Jabber ID
 * @return		Jmeno uzivatele (nove alokovane), NULL = Chyba
 */
gchar* jid_get_name(const gchar *jid) {
    const gchar *ch;

    g_return_val_if_fail (jid != NULL, NULL);

    ch = strchr (jid, '@');
    if (!ch)
    	return NULL;

    return g_strndup (jid, ch - jid);
}

/**
 * Ziska jmeno serveru z JID
 * @param jid	Jabber ID
 * @return		Prvni znak nazvu serveru v JID, NULL = Chyba
 */
char* jid_get_server(const char* jid) {
	char* ptr;
	ptr = strchr(jid, '@');
	if(ptr != NULL)
		return ptr + 1;
	else
		return NULL;
}

/**
 * Callback funkce, zajistuje prihlasovani uzivatelu k serveru
 */
void xmpp_conn_auth_handler(LmConnection *connection, gboolean success, gpointer user_data) {
	if (success) {
		LmMessage *m;

		printf("XMPP: Authenticated successfully\n");

		m = lm_message_new_with_sub_type(NULL, LM_MESSAGE_TYPE_PRESENCE, LM_MESSAGE_SUB_TYPE_AVAILABLE);
		lm_connection_send(connection, m, NULL);
		printf("XMPP: Sent presence message: %s", lm_message_node_to_string(m->node));
		lm_message_unref(m);
	}
	else {
		printf("XMPP: Failed to authenticate\n");
		g_main_loop_quit(main_loop);
	}
}

/**
 * Callback funkce, obsluha udalosti spojeni s XMPP serverem
 */
void xmpp_conn_open_handler(LmConnection *connection, gboolean success, gpointer user_data) {
	if(success) {
		gchar *user;

		user = jid_get_name(birdbot_jid);
		lm_connection_authenticate(connection, user, birdbot_pw, "test-lm", xmpp_conn_auth_handler, NULL, FALSE,  NULL);
		g_free(user);

		printf("XMPP: Sent authentication message\n");
	} else {
		printf("XMPP: Failed to connect\n");
		g_main_loop_quit(main_loop);
	}
}

/**
 * Callback funkce, obsluha udalosti spojeni s XMPP serverem
 */
void xmpp_conn_close_handler(LmConnection *connection, LmDisconnectReason  reason, gpointer user_data) {
    const char *str;

    switch (reason) {
    case LM_DISCONNECT_REASON_OK:
        str = "LM_DISCONNECT_REASON_OK";
        break;
    case LM_DISCONNECT_REASON_PING_TIME_OUT:
        str = "LM_DISCONNECT_REASON_PING_TIME_OUT";
        break;
    case LM_DISCONNECT_REASON_HUP:
        str = "LM_DISCONNECT_REASON_HUP";
        break;
    case LM_DISCONNECT_REASON_ERROR:
        str = "LM_DISCONNECT_REASON_ERROR";
        break;
    case LM_DISCONNECT_REASON_UNKNOWN:
    default:
        str = "LM_DISCONNECT_REASON_UNKNOWN";
        break;
    }

    printf("XMPP: Disconnected, reason: %d->'%s'\n", reason, str);
}

/**
 * Callback funkce, spustena pri prijeti zpravy z XMPP
 */
LmHandlerResult xmpp_message_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	char* from;
	char *intext = NULL;
	int user_auth_lvl = 0; // 0 = not authorized, 1 = restricted, 2 = superuser

	if(lm_message_node_get_child(m->node, "body") == NULL)
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;

	if((lm_message_node_get_attribute(m->node, "type") != NULL) && !strcmp(lm_message_node_get_attribute(m->node, "type"), "error"))
		return LM_HANDLER_RESULT_REMOVE_MESSAGE;

	from = (char*)lm_message_node_get_attribute(m->node, "from");

    if(lm_message_node_get_child(m->node, "body")->value != NULL)
    	intext = (char*)lm_message_node_get_value(lm_message_node_get_child(m->node, "body"));

	printf("XMPP: Incoming message from %s: %s\n", from, intext);

	user_auth_lvl = check_user_auth(from);
	if(user_auth_lvl == 0) {
		send_message(from, "Not authorized.");
		return 1;
	}

	//jsme opravneny uzivatel
	process_cmd(from, intext, user_auth_lvl);

    return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

LmHandlerResult xmpp_presence_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* msub;
	char* from;
	LmMessageSubType subtype;

	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_SUBSCRIBE) {
		from = (char*)lm_message_node_get_attribute(m->node, "from");

		if(check_user_auth(from) > 0) {
			subtype = LM_MESSAGE_SUB_TYPE_SUBSCRIBED;
			printf("XMPP: User %s requested authorization, allowed\n", from);
		}
		else {
			subtype = LM_MESSAGE_SUB_TYPE_UNSUBSCRIBED;
			printf("XMPP: User %s requested authorization, declined\n", from);
		}

		msub = lm_message_new_with_sub_type(from, LM_MESSAGE_TYPE_PRESENCE, subtype);
		lm_connection_send(xmpp_conn, msub, NULL);
		lm_message_unref(msub);
	}
	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

/**
 * XMPP whitespace keepalive, posle serveru mezeru kazdych 5 minut
 */
void* xmpp_keep_alive_thread(void* args) {
	while(1) {
		sleep(300);
		pthread_mutex_lock(&xmppmtx);
		lm_connection_send_raw(xmpp_conn, " ", NULL);
		puts("XMPP: Sending keepalive");
		pthread_mutex_unlock(&xmppmtx);
	}
	return NULL;
}

int main(int argc, char **argv)
{
    LmMessageHandler *handler;
    gboolean          result;
    GError           *error = NULL;
    static char* xmpp_server;

    char opt;
    pid_t pid, sid;
    int lockfile;
    int release_terminal = 0;

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &action, NULL);

    //parse command line parameters
    while((opt = getopt(argc, argv, "d")) != -1) {
    	if(opt == 'd') {
    		//daemonize
    		//puts("Going to daemon mode");

    		pid = fork();
    		if(pid < 0)
    			return -1;

    		if(pid > 0)
    			return 0;

    		umask(0);

    		sid = setsid();
    		if(sid < 0)
    			return -1;

    		if ((chdir("/")) < 0)
    			return -1;

    		pid = fork();
    		if(pid < 0)
    			return -1;

    		if(pid > 0)
    			return 0;

    		release_terminal = 1;
    		break;
    	}
    }

    //ensure single instance
    lockfile = open(PATH_LOCKFILE, O_WRONLY | O_CREAT, "0666");
    if(lockfile < 0) {
    	puts("Error opening lockfile, exiting. (Is running as root?)");
    	return -1;
    }

    if(lockf(lockfile, F_TLOCK, 0) != 0) {
    	puts("Birdbot already running (lockfile exists), exiting.");
    	return 1;
    }

    //close standard file descriptors
    if(release_terminal) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
    }

    //load configuration
    if(load_config(PATH_CONFIG) != 0)
    	return -1;

    print_config();

    cmd_build_tree();

    //initialize XMPP
    xmpp_server = jid_get_server(birdbot_jid);
    if(xmpp_server == NULL) {
    	printf("Invalid XMPP bot jid: %s\n", birdbot_jid);
    	exit_clean(-1);
    }

    xmpp_conn = lm_connection_new(xmpp_server);
    lm_connection_set_port(xmpp_conn, LM_CONNECTION_DEFAULT_PORT);
    lm_connection_set_jid(xmpp_conn, birdbot_jid);

    handler = lm_message_handler_new(xmpp_message_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_MESSAGE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    handler = lm_message_handler_new(xmpp_presence_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_PRESENCE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    lm_connection_set_disconnect_function(xmpp_conn, xmpp_conn_close_handler, NULL, NULL);
    result = lm_connection_open(xmpp_conn, (LmResultFunction)xmpp_conn_open_handler, NULL, NULL, &error);

    if(!result) {
        printf("Opening xmpp_conn failed, error: %d->'%s'\n", error->code, error->message);
        g_free(error);
        exit_clean(-1);
    }

    pthread_create(&xmpp_keepalive_tid, NULL, xmpp_keep_alive_thread, NULL);
    pthread_detach(xmpp_keepalive_tid);

    main_loop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(main_loop);

    exit_clean(0);
    return 0;
}
