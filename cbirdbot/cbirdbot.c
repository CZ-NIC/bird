#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <loudmouth/loudmouth.h>

#include <pthread.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netdb.h>
#include <resolv.h>

#include "client.h"
#include "sysdep/paths.h"

#define PIP_RD	0
#define PIP_WR 1

/****************************** SETTINGS ************************************/

#define PATH_CONFIG					PATH_BOT_CONFIG_FILE
#define PATH_LOCKFILE				"/var/run/birdbot.lock"
#define XMPP_KEEPALIVE_INTERVAL		120

/*****************************************************************************/

char*	superusers[100];
char*	restricted_users[100];

char*	birdbot_jid;
char*	birdbot_pw;
char bird_socket[108];

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
 * Adds socket connection object to list
 * @param conn	Reference to object
 * @return		0 = OK, -1 = ERROR
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
 * Removes connection from list
 * @param jid	JabberID of user
 * @return		O = OK, -1 = ERROR
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
 * Finds connection with specific JabberID in the list
 * @param jid	JabberID of user
 * @return		Odkaz na spojeni, NULL = ERROR
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
 * Prints entire list of connections, for debugging purposes
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
 * Exits program with error message
 * @param s		Error message text
 */
void die(char* s) {
	puts(s);
	exit(-1);
}

/**
 * Skips leading whitespace characters in given string
 * @param str	String
 * @return		Pointer to first non-white character
 */
char* skipblank(char* str) {
	while((*str == ' ') || (*str == '\t'))
		str++;
	return str;
}

/**
 * Creates new connection with BIRD socket and adds it to the list
 * @param jid	JabberID of user
 * @return		0 = OK, -1 = ERROR
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
	strncpy(sa.sun_path, bird_socket, sizeof(sa.sun_path) - 1);
	sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';
	//adr.sin_port = htons(BIRD_host_port);

	if(connect(conn->sock_fd, (struct sockaddr*) &sa, SUN_LEN(&sa)) < 0) {
		free(conn);
		return -1;
	}

	fcntl(conn->sock_fd, F_SETFL, O_NONBLOCK);

	conn->jid = (char*) malloc(strlen(jid) + 1);
	strcpy(conn->jid, jid);

	if(pipe(conn->termpipe_fd) != 0)
		puts("Error creating pipe.");

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
 * Exits connection thread and removes it from the list
 * @param conn	Reference to connection object
 * @return		0 = OK, -1 = ERROR
 */
int connection_stop(conn_t* conn) {
	if(write(conn->termpipe_fd[PIP_WR], "stop", 5) == 5)
		return 0;
	else
		return -1;
}

/**
 * Clean exit of program, exits the all threads and does some housekeeping
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
 * Processes BIRD server response
 * @param in	Raw data string from BIRD socket
 * @return		Plain text (newly allocated), NULL = ERROR
 */
char* process_bird_output(char* in) {
	char* out = malloc(4096);
	char* line_end;
	int code;

	if(out == NULL)
		return NULL;

	out[0] = '\0';

	if(in[0] == '+') {
		//asynchronous server response
		sprintf(out, "\n>>> %s", in + 1);
		return out;
	}

	while((line_end = strchr(in, '\n')) != NULL) {
		*line_end = '\0';
		if((strlen(in) > 4) && (sscanf(in, "%04d", &code) == 1) && ((in[4] == ' ') || (in[4] == '-'))) {
			//valid line
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

	printf("Socket connection thread created: %s\n", conn->jid);
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
			printf("Received from socket: %d bytes: %s\n", bytes, tmp);

			msg = process_bird_output(tmp);


			if(!conn->bird_ready) {
				if(strstr(msg, "BIRD ") != NULL) {
					if(check_user_auth(conn->jid) < 2) {
						if(write(conn->sock_fd, "restrict\n", 9) <= 0) {
							puts("Cannot write to socket, exiting thread.");
							break;
						}
					}
					conn->bird_ready = 1;
				}
			}

			send_message(conn->jid, msg);
			free(msg);
		}
	}


	printf("Connection thread %s ended.\n", conn->jid);

	if(delete_connection(conn) != 0)
		puts("Error deleting connection");

	return NULL;
}

/**
 * Executes specific BIRD socket connetion thread
 * @param conn	Connection object reference
 * @return		0 = OK, -1 = ERROR
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
 * Sends message over XMPP
 * @param jid		JabberID of recipient
 * @param mbody		Message body text
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
 * Sends HTML help to specific command
 * @param jid		JabberID of recipient
 * @param mbody		Message body text
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
		strncpy(msg_arr[i][2], tab2 + 4, 100);
		msg_arr[i][2][99] = '\0';
		*tab2 = '\0';

		msg_arr[i][1] = alloca(100);
		strncpy(msg_arr[i][1], tab1 + 1, 95);
		msg_arr[i][1][95] = '\0';
		strcat(msg_arr[i][1], "    ");
		*tab1 = '\0';

		msg_arr[i][0] = alloca(25);
		strncpy(msg_arr[i][0], in, 20);
		msg_arr[i][0][20] = '\0';
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
 * Processes incoming message from XMPP and sends data to BIRD socket
 * @param jid		JabberID of sender
 * @param cmdtext	Message body text
 * @param auth_lvl	Authentication level of user with given JID (1 = Restricted, 2 = Superuser)
 * @return			0 = OK, -1 = ERROR
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

	//lowercase first command letter
	if((cmdtext[0] >= 'A') && (cmdtext[0] <= 'Z'))
		cmdtext[0] += 'a' - 'A';

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
			exit_clean(0); //program end
		}
		else {
			send_message(jid, "Access denied.");
			free(s);
			return 0;
		}
	}

	if(strcmp(s, "help") == 0) {
		send_message(jid, "Use `?' for context-sensitive help.");
		free(s);
		return 0;
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
	else { //we are connected to BIRD socket
		if(strcmp(s, "connect") == 0) {
			send_message(jid, "Already connected.");
		}
		else if((strcmp(s, "exit") == 0) || (strcmp(s, "quit") == 0)) {
			connection_stop(conn);
			send_message(jid, "Bye.");
		}
		else {
			if(conn->bird_ready) {
				int len;
				len = strlen(s);
				s[len] = '\n';	//append newline char
				s[++len] = '\0'; //s allocated with enough free space
				printf("Sending: %s\n", s);
				if(write(conn->sock_fd, s, len) <= 0) {
					puts("Socket write error.");
				}
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
 * Gets user authentication level
 * @param jid	JabberID of user
 * @return		0 = Not allowed, 1 = Restricted user, 2 = Superuser
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

	for(i = 0; superusers[i] != NULL; i++) {
		if(strncmp(jid, superusers[i], basejid_len) == 0) {
			user_auth_lvl = 2;
			break;
		}
	}

	if(user_auth_lvl == 0) {
		for(i = 0; restricted_users[i] != NULL; i++) {
			if(strncmp(jid, restricted_users[i], basejid_len) == 0) {
				user_auth_lvl = 1;
				break;
			}
		}
	}

	return user_auth_lvl;
}

/**
 * SIGTERM handler
 */
void sigterm_handler(int n) {
	exit_clean(0);
}

/**
 * Reads BIRDbot setting from config file
 * @param path	File path
 * @return		0 = OK, -1 = ERROR
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
		if(strcmp(skipblank(line), "XMPP:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		if((birdbot_jid == NULL) && (strncmp(lptr, "JID=", 4) == 0)) {
			birdbot_jid = malloc(strlen(lptr));
			strncpy(birdbot_jid, lptr + 4, strlen(lptr) - 4 - 1);
			birdbot_jid[strlen(lptr) - 4 - 1] = '\0';
		}
		else if((birdbot_pw == NULL) && (strncmp(lptr, "PASS=", 5) == 0)) {
			birdbot_pw = malloc(strlen(lptr));
			strncpy(birdbot_pw, lptr + 5, strlen(lptr) - 5 - 1);
			birdbot_pw[strlen(lptr) - 5 - 1] = '\0';
		}
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strcmp(skipblank(line), "SUPERUSERS:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		ptr = malloc(strlen(lptr) + 1);
		strncpy(ptr, lptr, strlen(lptr) - 1);
		ptr[strlen(lptr)] = '\0';
		if(i < 99) {
			superusers[i] = ptr;
			i++;
		}
	}

	rewind(fconf);

	i = 0;
	while(fgets(line, 100, fconf) != NULL) {
		if(strcmp(skipblank(line), "RESTRICTED:\n") == 0)
			break;
	}

	while(fgets(line, 100, fconf) != NULL) {
		lptr = skipblank(line);

		if(lptr[0] == '#')
			continue;
		if((lastnb(lptr, strlen(lptr) - 1) == ':') || (lptr[0] == '\n') || (lptr[0] == '\r'))
			break;

		ptr = malloc(strlen(lptr) + 1);
		strncpy(ptr, lptr, strlen(lptr) - 1);
		ptr[strlen(lptr)] = '\0';
		if(i < 99) {
			restricted_users[i] = ptr;
			i++;
		}
	}

	return 0;
}

/**
 * Prints BIRDbot configuration, for debugging purposes
 */
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
 * Gets username from JID
 * @param jid	JabberID of user
 * @return		Username (newly allocated), NULL = ERROR
 */
gchar* jid_get_name(const gchar *jid) {
    const gchar *ch;

    g_return_val_if_fail(jid != NULL, NULL);

    ch = strchr(jid, '@');
    if(!ch)
    	return NULL;

    return g_strndup(jid, ch - jid);
}

/**
 * Gets server domain from JID
 * @param jid	JabberID of user
 * @return		Pointer to first character of server domain in the JID, NULL = ERROR
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
 * Callback, for logging users to XMPP server
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
 * Callback, manages XMPP server connection events
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
 * Callback, manages XMPP server connection events
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
    g_main_loop_quit(main_loop);
}

/**
 * Callback for processing incoming XMPP messages
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

	//we are an authorized user
	process_cmd(from, intext, user_auth_lvl);

    return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

/**
 * Callback, authorizes allowed users to view presence status of BIRDbot
 */
LmHandlerResult xmpp_presence_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* msub;
	char* from;
	LmMessageSubType subtype;

	pthread_mutex_lock(&xmppmtx);
	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_SUBSCRIBE) {
		from = (char*)lm_message_node_get_attribute(m->node, "from");

		if(check_user_auth(from) > 0) {
			subtype = LM_MESSAGE_SUB_TYPE_SUBSCRIBED;
			printf("XMPP: User %s requested authorization, allowed.\n", from);
		}
		else {
			subtype = LM_MESSAGE_SUB_TYPE_UNSUBSCRIBED;
			printf("XMPP: User %s requested authorization, rejected.\n", from);
		}

		msub = lm_message_new_with_sub_type(from, LM_MESSAGE_TYPE_PRESENCE, subtype);
		lm_connection_send(xmpp_conn, msub, NULL);
		lm_message_unref(msub);
	}
	pthread_mutex_unlock(&xmppmtx);

	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

LmHandlerResult xmpp_iq_handler(LmMessageHandler *handler, LmConnection *connection, LmMessage *m, gpointer user_data) {
	LmMessage* msub;
	char *from, *data, *id;

	pthread_mutex_lock(&xmppmtx);

	if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_GET) {
		from = (char*)lm_message_node_get_attribute(m->node, "from");
		id = (char*)lm_message_node_get_attribute(m->node, "id");

		if(lm_message_node_get_child(m->node, "ping") != NULL) {
			data = lm_message_node_to_string(m->node);
			printf("XMPP: Incoming XMPP ping: %s\n", data);
			g_free(data);

			msub = lm_message_new_with_sub_type(from, LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_RESULT);
			lm_message_node_set_attribute(msub->node, "id", id);
			lm_connection_send(xmpp_conn, msub, NULL);
			lm_message_unref(msub);
		}
	}
	else if(lm_message_get_sub_type(m) == LM_MESSAGE_SUB_TYPE_RESULT) {
		data = lm_message_node_to_string(m->node);
		printf("XMPP: Incoming XMPP result: %s\n", data);
		g_free(data);
	}
	pthread_mutex_unlock(&xmppmtx);

	return LM_HANDLER_RESULT_REMOVE_MESSAGE;
}

/**
 * XMPP whitespace keepalive, sends space character to server every 5 minutes
 */
void* xmpp_keep_alive_thread(void* args) {
	LmMessage* msg;
	LmMessageNode* ping;
	int sresult;
	GError* err;
	time_t t;
	struct tm tm;

	while(1) {
		sleep(XMPP_KEEPALIVE_INTERVAL);
		pthread_mutex_lock(&xmppmtx);
		msg = lm_message_new_with_sub_type(jid_get_server(birdbot_jid), LM_MESSAGE_TYPE_IQ, LM_MESSAGE_SUB_TYPE_GET);
		lm_message_node_set_attribute(msg->node, "id", "client-ping");
		ping = lm_message_node_add_child(msg->node, "ping", NULL);
		lm_message_node_set_attribute(ping, "xmlns", "urn:xmpp:ping");
		sresult = lm_connection_send(xmpp_conn, msg, &err);
		lm_message_unref(msg);
		t = time(NULL);
		tm = *localtime(&t);
		printf("[%02d:%02d] XMPP: Sending keepalive\n", tm.tm_hour, tm.tm_min);
		if(!sresult) {
			printf("XMPP: Keepalive send failed, status: [%d] %s\n", err->code, err->message);
			g_free(err);
		}
		pthread_mutex_unlock(&xmppmtx);
	}
	return NULL;
}

/**
 * Callback, handles XMPP SSL events
 */
LmSSLResponse xmpp_ssl_handler(LmSSL *ssl, LmSSLStatus status, gpointer ud) {
	printf("XMPP: SSL status %d\n", status);

    switch(status) {
    case LM_SSL_STATUS_NO_CERT_FOUND:
    	printf("XMPP: No certificate found!\n");
        break;
    case LM_SSL_STATUS_UNTRUSTED_CERT:
    	printf("XMPP: Certificate is not trusted!\n");
        break;
    case LM_SSL_STATUS_CERT_EXPIRED:
    	printf("XMPP: Certificate has expired!\n");
        break;
    case LM_SSL_STATUS_CERT_NOT_ACTIVATED:
    	printf("XMPP: Certificate has not been activated!\n");
        break;
    case LM_SSL_STATUS_CERT_HOSTNAME_MISMATCH:
    	printf("XMPP: Certificate hostname does not match expected hostname!\n");
        break;
    case LM_SSL_STATUS_CERT_FINGERPRINT_MISMATCH: {
        //const char *fpr = lm_ssl_get_fingerprint (ssl);
    	printf("XMPP: Certificate fingerprint does not match expected fingerprint!\n");
        //print both fingerprints
        break;
    }
    case LM_SSL_STATUS_GENERIC_ERROR:
    	printf("XMPP: Generic SSL error!\n");
        break;
    }

    return LM_SSL_RESPONSE_CONTINUE;
}

void display_opt_help(const struct option* opts, const char* helptext[]) {
	int i = 0;
	puts("Send commands to BIRD via XMPP.\n");
	while(opts->name != NULL) {
		printf("-%c | --%s\n", opts->val, opts->name);
		if(helptext[i] != NULL) {
			printf("%s\n\n", helptext[i]);
			i++;
		}
		opts++;
	}
}

int main(int argc, char **argv)
{
    LmMessageHandler *handler;
    gboolean          result;
    GError           *error = NULL;
    static char* xmpp_domain;

    char opt;
    int longopts_idx;
    const struct option longopts[] = {
    		{"debug", no_argument, NULL, 'd'},
			{"force-ipv4", no_argument, NULL, '4'},
			{"nossl", no_argument, NULL, 's'},
			{"jid", required_argument, NULL, 'j'},
			{"pass", required_argument, NULL, 'w'},
			{"socket", required_argument, NULL, 'c'},
			{"help", required_argument, NULL, 'h'},
			{NULL, 0, NULL, 0}
    };

    const char* opthelp[] = {
    		"Debug mode. Program will display debugging information instead of going to background.",
			"Force IPv4 resolution of XMPP server hostname.",
			"Disable use of SSL connection with XMPP server.",
			"Specify BIRDbot's bare JID. This option overrides JID set in the configuration file.",
			"Specify BIRDbot's XMPP password. This option overrides password set in the configuration file.",
			"Set BIRD control socket.",
			"Display this help and exit.",
			NULL
    };

    pid_t pid, sid;
    int lockfile;
    int is_daemon = 1;
    int xmpp_force_ipv4 = 0;
    int xmpp_use_ssl = 1;

    struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &action, NULL);

    birdbot_jid = NULL;
    birdbot_pw = NULL;
    strncpy(bird_socket, PATH_CONTROL_SOCKET, sizeof(bird_socket) - 1);
    bird_socket[sizeof(bird_socket) - 1] = '\0';

    //parse command line parameters
    while((opt = getopt_long(argc, argv, "d4sj:w:s:h", longopts, &longopts_idx)) != -1) {
    	switch(opt) {
    		case 'd': {
    			is_daemon = 0;
    			break;
    		}
    		case '4': {
    			xmpp_force_ipv4 = 1;
    			break;
    		}
    		case 's': {
    			xmpp_use_ssl = 0;
    			break;
    		}
    		case 'j': {
    		    birdbot_jid = malloc(strlen(optarg) + 1);
    		    strcpy(birdbot_jid, optarg);
    		    break;
    		}
    		case 'w': {
    			birdbot_pw = malloc(strlen(optarg) + 1);
    			strcpy(birdbot_pw, optarg);
    			break;
    		}
    		case 'c': {
    			strncpy(bird_socket, optarg, sizeof(bird_socket) - 1);
    			bird_socket[sizeof(bird_socket) - 1] = '\0';
    			break;
    		}
    		case 'h': {
    			display_opt_help(longopts, opthelp);
    			puts("Exiting.");
    			return 1;
    			break;
    		}
    		default: {
    			//unknown option, do not continue
    			return -1;
    			break;
    		}
    	}
    }

    //load configuration
    if(load_config(PATH_CONFIG) != 0)
    	return -1;

    //print configuration
    if(!is_daemon)
    	print_config();

    //validate configuration
    if(birdbot_jid == NULL) {
    	puts("You must specify BIRDbot's JID in config file or as command line argument.");
    	exit_clean(-1);
    }
    else {
    	if(birdbot_pw == NULL) {
    		//if(!is_daemon) {
    			int attempts = 3;
    			birdbot_pw = malloc(31);
    			do {
    				printf("Enter XMPP account password: ");
    			}while((scanf("%30s", birdbot_pw) != 1) && --attempts);
    			if(attempts == 0)
    				exit_clean(-1);
    		//}
    		//else
    		//	exit_clean(-1);
    	}
    }

	//daemonize
    if(is_daemon) {
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
    if(is_daemon) {
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);

        open("/dev/null", O_RDWR);
        if(dup(0) == -1)
        	return -1;
        if(dup(0) == -1)
        	return -1;
    }

    cmd_build_tree();

    //initialize XMPP
    xmpp_domain = jid_get_server(birdbot_jid);
    if(xmpp_domain == NULL) {
    	printf("Invalid XMPP bot jid: %s\n", birdbot_jid);
    	exit_clean(-1);
    }


    //resolve XMPP server's SRV record from DNS
    char ns_buf[512];
    char xmpp_srv_nsrecord[256];
    char xmpp_srv_hostname[128];
	char xmpp_ip[64];
    int len;
    ns_msg msg;
    ns_rr rr;
    struct addrinfo aihints;
    struct addrinfo *aires, *aii;

    res_init();

    strcpy(xmpp_srv_nsrecord, "_xmpp-client._tcp.");
    strncat(xmpp_srv_nsrecord, xmpp_domain, sizeof(xmpp_srv_nsrecord) - sizeof("_xmpp-client._tcp."));

    len = res_query(xmpp_srv_nsrecord, ns_c_any, ns_t_srv, (u_char*)ns_buf, sizeof(ns_buf));
    if(len < 0) {
    	puts("NS: SRV record resolution failed.");
    	exit_clean(-1);
    }

    ns_initparse((u_char*)ns_buf, len, &msg);

    //len = ns_msg_count(msg, ns_s_an); //len = number of records found

    char* c;
    ns_parserr(&msg, ns_s_an, 0, &rr);	//0 = we take the first record
    ns_sprintrr(&msg, &rr, NULL, NULL, xmpp_srv_nsrecord, sizeof(xmpp_srv_nsrecord));

    c = strrchr(xmpp_srv_nsrecord, '.');
    if((c != NULL) && (*(c + 1) == '\0')) {
    	*c = '\0';
    	c = strrchr(xmpp_srv_nsrecord, ' ');
    	if(c != NULL) {
    		strncpy(xmpp_srv_hostname, c + 1, sizeof(xmpp_srv_hostname) - 1);
    		xmpp_srv_hostname[sizeof(xmpp_srv_hostname) - 1] = '\0';
    	}
    }

    printf("NS: Resolved hostname (SRV) of XMPP server: %s\n", xmpp_srv_hostname);

    xmpp_ip[0] = '\0';

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_family = AF_INET6;
    aihints.ai_socktype = SOCK_STREAM;

    /*if((getaddrinfo(xmpp_srv_hostname, "xmpp-client", &aihints, &aires) == 0) && (aires != NULL) && (!xmpp_force_ipv4)) {
    	for(aii = aires; aii != NULL; aii = aii->ai_next) {
    		if(getnameinfo(aii->ai_addr, aii->ai_addrlen, xmpp_ip, sizeof(xmpp_ip) - 1, NULL, 0, NI_NUMERICHOST) == 0) {
    			printf("NI: Using xmpp IPv6: %s\n", xmpp_ip);
    			break;
    		}
    	}
    	freeaddrinfo(aires);
    }
    else {*/
    	//Current version of libloudmouth does not support IPv6
    if(xmpp_force_ipv4) {
    	aihints.ai_family = AF_INET;
    	if((getaddrinfo(xmpp_srv_hostname, "xmpp-client", &aihints, &aires) == 0) && (aires != NULL)) {
    		for(aii = aires; aii != NULL; aii = aii->ai_next) {
    			if(getnameinfo(aii->ai_addr, aii->ai_addrlen, xmpp_ip, sizeof(xmpp_ip) - 1, NULL, 0, NI_NUMERICHOST) == 0) {
    				printf("NI: Using xmpp IPv4: %s\n", xmpp_ip);
    				break;
    			}
    		}
    		freeaddrinfo(aires);
    	}
    	else {
    		puts("NI: Cannot resolve xmpp server IP, exiting.");
    		exit_clean(-1);
    	}
    }
    //}

    if(xmpp_force_ipv4)
    	xmpp_conn = lm_connection_new(xmpp_ip);
    else
    	xmpp_conn = lm_connection_new(xmpp_srv_hostname);

    lm_connection_set_port(xmpp_conn, LM_CONNECTION_DEFAULT_PORT);
    lm_connection_set_jid(xmpp_conn, birdbot_jid);

    if(xmpp_use_ssl) {
        if(lm_ssl_is_supported()) {
        	LmSSL *ssl;
        	ssl = lm_ssl_new(NULL, (LmSSLFunction)xmpp_ssl_handler, NULL, NULL);
        	lm_ssl_use_starttls(ssl, TRUE, FALSE);
        	lm_connection_set_ssl(xmpp_conn, ssl);
        	lm_ssl_unref(ssl);
        }
        else {
        	puts("XMPP: Warning. SSL is not available in current instalation of libloudmouth.");
        }
    }

    handler = lm_message_handler_new(xmpp_message_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_MESSAGE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    handler = lm_message_handler_new(xmpp_presence_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_PRESENCE, LM_HANDLER_PRIORITY_NORMAL);
    lm_message_handler_unref(handler);

    handler = lm_message_handler_new(xmpp_iq_handler, NULL, NULL);
    lm_connection_register_message_handler(xmpp_conn, handler, LM_MESSAGE_TYPE_IQ, LM_HANDLER_PRIORITY_NORMAL);
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

    lm_connection_unref(xmpp_conn);
    exit_clean(0);
    return 0;
}
