#ifndef _REQUESTS_
#define _REQUESTS_

#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdio.h>
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include <errno.h>

/* DIE macro */
#define DIE(assertion, call_description)						\
	do {													    \
		if (assertion) {										\
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);	\
			perror(call_description);							\
			exit(errno);										\
		}												        \
	} while (0)

#define BUFLEN 4096
#define LINELEN 1000
#define HEADER_TERMINATOR "\r\n\r\n"
#define HEADER_TERMINATOR_SIZE (sizeof(HEADER_TERMINATOR) - 1)
#define CONTENT_LENGTH "Content-Length: "
#define CONTENT_LENGTH_SIZE (sizeof(CONTENT_LENGTH) - 1)

#define HOST_IP (char*)"34.246.184.49"
#define CONTENT_TYPE (char*)"application/json"
#define REGISTER_URL (char*)"/api/v1/tema/auth/register"
#define LOGIN_URL (char*)"/api/v1/tema/auth/login"
#define ENTER_LIB_URL (char*)"/api/v1/tema/library/access"
#define BOOKS_URL  (char*)"/api/v1/tema/library/books"
#define LOGOUT_URL (char*)"/api/v1/tema/auth/logout"


/* ------------------ Connection Functions ------------------ */
// opens a connection with server host_ip on port portno, returns a socket
int open_connection(char *host_ip, int portno, int ip_type, int socket_type, int flag);
// closes a server connection on socket sockfd
void close_connection(int sockfd);
// send a message to a server
void send_to_server(int sockfd, char *message);
// receives and returns the message from a server
char *receive_from_server(int sockfd);


/* ------------------ Request Functions ------------------  */
// computes and returns a GET request string (query_params
// and cookies can be set to NULL if not needed)
char *compute_del_request(char *host, char *url, char *query_params,
                            char *cookies, int cookies_num,
                            char *authorization);
char *compute_get_request(char *host, char *url, char *query_params,
                            char *cookies, int cookies_num,
                            char *authorization);
// computes and returns a POST request string (cookies can be NULL if not needed)
char *compute_post_request(char *host, char *url, char* content_type, char *body_data,
							int body_len, char* cookies, int cookies_len,
                            char *authorization);

/* ----------------- Command Functions ------------------  */
void register_user();
char *login();
char * enter_library(char *cookie);
void get_books(char *cookie, char *token);
void get_book(char *cookie, char *token);
void add_book(char *cookie, char *token);
void delete_book(char *cookie, char *token);
void logout(char *cookie);

#endif