#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
#include <sys/timerfd.h>

using namespace std;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

/* Server  info */
int server_socketfd;
struct sockaddr_in server_address;

/* Buffer for receiving data */
char *recv_buffer;
int recv_buffer_len;
int SEQ;
map<int, char*> received_packets;


int recv_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);

    /* We will write code here as to not have sync problems with recv_handler */
    if (!received_packets.empty()) {
        map<int, char*>::iterator iter = received_packets.begin();
        pair p = *iter;
        if (p.first == SEQ) {
            char *packet = p.second;
            poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)packet;
            char *payload = packet + sizeof(poli_tcp_data_hdr);
            size = ntohs(hdr->len);

            memcpy(buffer, payload, size);
            received_packets.erase(SEQ);
            free(packet);
            SEQ ++;
        }
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return size;
}

// Saves data received from a client in buffer to be
// used by the main thread
void add_to_buffer(char *segment) {
    poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)segment;
    int len = ntohs(hdr->len) + sizeof(poli_tcp_data_hdr);

    char *packet = (char*)malloc(len);
    memcpy(packet, segment, len);

    received_packets.insert({ntohs(hdr->seq_num), packet});
}

// Sends an Acknowledgement that the packet with seq has
// been received succesfully
void send_ack(int seq, int conn_id) {
    /* Build Packet */
    struct connection *con = cons[conn_id];
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

    //cerr << "Send ack for packet " << seq << "\n";

    char *packet = (char*)malloc(sizeof(poli_tcp_ctrl_hdr));
    poli_tcp_ctrl_hdr *chdr = (poli_tcp_ctrl_hdr *)packet;
    chdr->conn_id = con->conn_id;
    chdr->protocol_id = POLI_PROTOCOL_ID;
    chdr->ack_num = htons(seq);
    chdr->type = CONTROL;
    //chdr->recv_window = sizeof(recv_buffer - occupied);

    /* Send Ack */
    int res = sendto(con->sockfd, packet, sizeof(poli_tcp_ctrl_hdr), 0,
        (struct sockaddr *)&con->servaddr, sockaddr_len);
    DIE(res < 0, "sendto");

    free(packet);
}

void print_received_packets() {
    cerr << "Received packets: ";
    for (pair p : received_packets) {
        poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)p.second;
        cerr << htons(hdr->seq_num) << " ";
    }
    cerr << "\n";
}

void *receiver_handler(void *arg)
{

    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("Starting recviver handler\n");
    int seq = 0;

    while (1) {

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);

        /* Handle segment received from the sender. We use this between locks
        as to not have synchronization issues with the recv_data calls which are
        on the main thread */
        poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)segment;

        if (hdr->type == DATA) {
            //cerr << "hdr_seq " << ntohs(hdr->seq_num) << " - seq " << seq << "\n";
            if (ntohs(hdr->seq_num) == seq) {
                /* Correct packet received */
                add_to_buffer(segment);
                send_ack(seq, conn_id);
                seq++;

                /* Check for waiting packets and add them in the buffer */
                //print_received_packets();
                while (!received_packets.empty()) {
                    auto iter = received_packets.find(seq);
                    if (iter == received_packets.end())
                        break;

                    seq++;
                }


            } else if (ntohs(hdr->seq_num) > seq) {
                /* Packets lost */
                /* Store current packet */
                add_to_buffer(segment);
                send_ack(ntohs(hdr->seq_num), conn_id);

            } else {
                /* ACK not received by client */
                //cerr << "Resend ACK for" << ntohs(hdr->seq_num) << "\n";
                send_ack(ntohs(hdr->seq_num), conn_id);
            }
        }

        //cerr << "\n";
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}

int wait4connect(uint32_t ip, uint16_t port)
{
    int rc;
    ssize_t rec;
    /* TODO: Implement the Three Way Handshake on the receiver part. This blocks
       until a connection is established. */
    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

    struct sockaddr_in client_addr, bind_addr;
    memset(&client_addr, 0, sockaddr_len);
    memset(&bind_addr, 0, sockaddr_len);

    /* Receive SYN on the connection socket. Create a new socket and bind it to
       the chosen port. Send the data port number via SYN-ACK to the client */
    size_t packet_len = sizeof(poli_tcp_ctrl_hdr) + sizeof(int);
    char *buff = (char*)malloc(packet_len);
    int *p = (int*)(sizeof(poli_tcp_ctrl_hdr) + buff);  // payload
    poli_tcp_ctrl_hdr *Syn = (poli_tcp_ctrl_hdr*)buff;
    
    /* Receive SYN message */
    do {
    rec = recvfrom(server_socketfd, buff, packet_len, 0,
        (struct sockaddr *)&client_addr, &sockaddr_len);
    } while (rec < 0);
    con->conn_id = Syn->conn_id = cons.size() + 1;

    cerr << "\nReceived SYN\n";
    printf("-- conn_id %d\n\n", Syn->conn_id);

    /* Create a new socket */
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(con->sockfd < 0, "socket");

    /* ------------ Bind new socket ------------ */
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = client_addr.sin_port;
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    rc = bind(con->sockfd, (struct sockaddr*)&bind_addr, sockaddr_len);
    DIE(rc < 0, "server socket");

    cerr << "New socket: " << con->sockfd << "\nPort: " << ntohs(bind_addr.sin_port) << "\n";

    /* Send Syn-Ack */
    Syn->ack_num = 1;
    Syn->recv_window = recv_buffer_len / MAX_DATA_SIZE;
    *p = bind_addr.sin_port; // Send port as payload 

    do {
    rec = sendto(con->sockfd, buff, packet_len, 0,
        (struct sockaddr *)&client_addr, sockaddr_len);
    } while (rec < 0);

    cerr << "SYN - Ack sent\n\n";

    /* Receive Ack */
    do {
    rec = recvfrom(con->sockfd, buff, packet_len, 0,
        (struct sockaddr *)&client_addr, &sockaddr_len);
    } while (rec < 0);
    cerr << "Ack received -> Ack_num = " << Syn->ack_num << "\n";
    con->servaddr = client_addr;

    /* Since we can have multiple connection, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    data_fds[fdmax].fd = con->sockfd;    
    data_fds[fdmax].events = POLLIN;    
    
    /* This creates a timer and sets it to trigger every 1 sec. We use this
       to know if a timeout has happend on a connection */
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME,  0);    
    timer_fds[fdmax].events = POLLIN;    
    struct itimerspec spec;     
    spec.it_value.tv_sec = 0;    
    spec.it_value.tv_nsec = 1000000;
    spec.it_interval.tv_sec = 0;    
    spec.it_interval.tv_nsec = 1000000;    
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);    
    fdmax++;    

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({con->conn_id, con});

    free(buff);
    DEBUG_PRINT("Connection established!");

    return con->conn_id;
}


void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int rc;

    /* Allocate receive buffer */;
    recv_buffer = (char*)malloc(recv_buffer_bytes);
    recv_buffer_len = recv_buffer_bytes;

    /* --------------- Create the connection socket ---------------- */
    server_socketfd = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(server_socketfd < 0, "Server socket");

    /* Make ports reusable, in case we run this really fast two times in a row */
    int enable = 1;
    rc = setsockopt(server_socketfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    DIE(rc < 0, "setsockopt(SO_REUSEADDR) failed");

    /* Bind it to 8031 */
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(8032);
    server_address.sin_addr.s_addr = INADDR_ANY;

    rc = bind(server_socketfd, (struct sockaddr*)&server_address, sizeof(server_address));
    DIE(rc < 0, "server socket");

    /* Create Thread  */
    rc = pthread_create( &thread1, NULL, receiver_handler, NULL);
    assert(rc == 0);
}