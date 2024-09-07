#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>

using namespace std;

std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

/* Packet Queue - Packets to Send */
int seq;
vector<char *> segment_queue;
int window_size;

int send_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);

    /* Check buffer size */
    if (len > MAX_DATA_SIZE)
        size = MAX_DATA_SIZE;
    else
        size = len;

    /* We will write code here as to not have sync problems with sender_handler */
    struct connection * con = cons[conn_id];

    /* Build the packet */
    //cerr << "\nSeq " << seq << " - with Size  " << size << "\n";
    char *packet = (char*)malloc(sizeof(poli_tcp_data_hdr) + size);
    poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)packet;
    char *payload = packet + sizeof(poli_tcp_data_hdr);
    memset(packet, 0, sizeof(poli_tcp_data_hdr) + size);
    memcpy(payload, buffer, size);

    /* Set Header */
    hdr->protocol_id = POLI_PROTOCOL_ID;
    hdr->conn_id = con->conn_id;
    hdr->seq_num = htons(seq); seq++;
    hdr->len = htons(size); // payload size
    hdr->type = DATA;

    /* Add in queue */
    segment_queue.push_back(packet);
    
    pthread_mutex_unlock(&cons[conn_id]->con_lock);

    return size;
}

// Sends a packet to server
void send_packet(char *packet, int conn_id) {
    struct connection *con = cons[conn_id];
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);
    poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)packet;

    /* Send new Packet */
    //cerr << "Sending Packet " << ntohs(hdr->seq_num) << "\n";
    int res = sendto(con->sockfd, packet, sizeof(poli_tcp_data_hdr) + ntohs(hdr->len), 0,
        (struct sockaddr *)&con->servaddr, sockaddr_len);
    assert(res >= 0);
}

/* Sends the initial window */
void send_init_window(vector<char*>& window, int conn_id) {
    //cerr << "Send Window\n";
    int win_size = min(window_size, (int)segment_queue.size());
    for (int i = 0; i < win_size; i++) {
        char *packet = segment_queue[i];
        send_packet(packet, conn_id);
        window.push_back(packet);
    }
    /* Remove sent packets from segment_queue */
    segment_queue.erase(segment_queue.begin(), segment_queue.begin() + win_size);
}

//  Sends next packet and updates the window 
void send_slide_window(vector<char*>& window, int conn_id) {
    //cerr << "------- Send Slide window -------\n";
    char *packet;

    if (!segment_queue.empty()) {
        /* Extract new packet */
        packet = segment_queue[0];
        /* Send new Packet */
        send_packet(packet, conn_id);
        /* Slide window */
        segment_queue.erase(segment_queue.begin());
        window.push_back(packet);
    }
}

// Removes an ACK-ed packet from window
int remove_ack_packet (vector<char*>& window, int ack_num) {
    //cerr << "Remove ACK-ed packet " << ntohs(ack_num) << " from window\n";
    for (auto iter = window.begin(); iter < window.end(); ++iter) {
        char *p = *iter;
        poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)p;
        if (hdr->seq_num == ack_num) {
            /* Remove ACK-ed packet from window */
            window.erase(iter);
            free(p);
            return 1;
        }
    }
    return -1;
}

void print_window(vector<char*>& window) {
    cerr << "Window: ";
    for (char *p : window) {
        poli_tcp_data_hdr *hdr = (poli_tcp_data_hdr *)p;
        cerr << ntohs(hdr->seq_num) << " ";
    }
    cerr << "\n";
}

void *sender_handler(void *arg)
{
    int res = 0, packet_sent = 0;
    char buf[MAX_SEGMENT_SIZE];
    vector<char*> window;

    while (1) {

        if (cons.size() == 0) {
            continue;
        }
        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while(res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        /* Handle segment received from the receiver. We use this between locks
        as to not have synchronization issues with the send_data calls which are
        on the main thread */
        if (packet_sent == 0 && (int)segment_queue.size() < window_size) {
            //cerr << "Segm_Size (" << segment_queue.size() << ")  <  window_size(" << window_size << ")\n";
            pthread_mutex_unlock(&cons[conn_id]->con_lock);
            continue;
        }

        packet_sent = 1;
        poli_tcp_ctrl_hdr *chdr = (poli_tcp_ctrl_hdr *)buf;

        if (res != -1 && chdr->type == CONTROL) {
            /* Ack received */
            //cerr << "Received Ack for packet " << htons(chdr->ack_num) << "\n";
            if (remove_ack_packet(window, chdr->ack_num) == 1 )
                send_slide_window(window, conn_id);

        } else if (res == -1 && !window.empty()) {
            send_packet(window[0], conn_id);

        } else if (res == -1 && !segment_queue.empty()) {
            send_init_window(window, conn_id);
        }

        //print_window(window);
        //cerr << "\n";
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}



int setup_connection(uint32_t ip, uint16_t port)
{
    /* Implement the sender part of the Three Way Handshake. Blocks
    until the connection is established */
    int rc;
    ssize_t rec;
    struct connection *con = (struct connection *)malloc(sizeof(struct connection));
    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

    seq = 0;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    cerr << "\n" << con->sockfd << "\n";
    DIE(con->sockfd < 0, "setup_connection -> bad socket");

    /* Set a timer on socket */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;
    rc = setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv));
    assert(rc >= 0);

    /* Fill the information that will be put into the IP and UDP header to
    identify the target process (via PORT) on a given host (via SEVER_IP) */
    memset(&con->servaddr, 0, sockaddr_len);
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_port = port;
    con->servaddr.sin_addr.s_addr = ip;

    /* We will send the SYN on 8032. Then we will receive a SYN-ACK with the connection
       port. We can use con->sockfd for both cases, but we will need to update server_addr
       with the port received via SYN-ACK */

    /* Build a SYN message */
    size_t packet_len = sizeof(poli_tcp_ctrl_hdr) + sizeof(int);
    char *buff = (char*)malloc(packet_len);
    int *p = (int*)(sizeof(poli_tcp_ctrl_hdr) + buff);
    poli_tcp_ctrl_hdr *Syn = (poli_tcp_ctrl_hdr*)buff;

    Syn->protocol_id = POLI_PROTOCOL_ID;
    Syn->ack_num = 0;
    Syn->conn_id = con->conn_id;
    Syn->type = CONTROL;

    /* Send SYN message */
    do {
    rec = sendto(con->sockfd, buff, packet_len, 0,
        (struct sockaddr *)&con->servaddr, sockaddr_len);
    } while (rec < 0);
    cerr << "SYN message sent\n\n";

    /* Receive SYN-ACK message */
    do {
    rec = recvfrom(con->sockfd, buff, packet_len, 0,
        (struct sockaddr *)&con->servaddr, &sockaddr_len);
    } while (rec < 0);
    con->conn_id = Syn->conn_id;
    con->servaddr.sin_port = *p;
    con->max_window_seq = Syn->recv_window;

    cerr << "Received SYN - Ack\n\n";
    cout << "Port = " << ntohs(*p) << "\n";

    /* Send final Ack */
    Syn->ack_num ++;
    do {
    rec = sendto(con->sockfd, buff, packet_len, 0,
        (struct sockaddr *)&con->servaddr, sockaddr_len);
    } while (rec < 0);

    cerr << "Ack sent\n\n";
    
    /* Since we can have multiple connection, we want to know if data is available
       on the socket used by a given connection. We use POLL for this */
    data_fds[fdmax].fd = con->sockfd;    
    data_fds[fdmax].events = POLLIN;    
    
    /* This creates a timer and sets it to trigger every 1 sec. We use this
       to know if a timeout has happend on our connection */
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

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;

    /* Compute bandwidth-delay product  */
    double BDP = (double) speed * delay;
    /* Compute window size */
    window_size = fmax(1, BDP)+1;
    cerr << "\n Window Size = " << window_size << "\n";

    /* Create a thread that will */
    ret = pthread_create( &thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
