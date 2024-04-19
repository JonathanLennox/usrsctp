#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include <usrsctp.h>

#define NUM_HOGS 8 /* Set to at least twice your number of cores */
#define NUM_REPEATS 1000
#define SCTP_DEBUG_FLAGS 0x00000002 /* SCTP_DEBUG_TIMER2 */

static int
onSctpOutboundPacket
    (void *addr, void *buffer, size_t length, uint8_t tos, uint8_t set_df);

static void
debugSctpPrintf(const char *format, ...);

static void plog(const char* label, const char* format, ...);

static int
onSctpData
    (struct socket *so, union sctp_sockstore addr, void *data, size_t datalen,
     struct sctp_rcvinfo rcv, int flags, void *ulp_info);

typedef struct {
    struct socket* so;
    void* id;
    const char* name;
    bool connected;
} sockobj;

static uintptr_t addr_ctr = 1;

static int SCTP_EVENT_TYPES[]
    = {
        SCTP_ASSOC_CHANGE,
        SCTP_PEER_ADDR_CHANGE,
        SCTP_SEND_FAILED_EVENT,
        SCTP_SENDER_DRY_EVENT,
        SCTP_STREAM_RESET_EVENT
    };

sockobj* create_socket(const char* name)
{
    sockobj* o = malloc(sizeof(sockobj));

    o->id = (void*)addr_ctr;
    addr_ctr++;

    usrsctp_register_address(o->id);

    o->name = name;
    o->connected = false;
    
    o->so = usrsctp_socket(
	AF_CONN,
	SOCK_STREAM,
	IPPROTO_SCTP,
	onSctpData,
	/* send_cb */ NULL,
	/* sb_threadhold */ 0,
	o->id);
    if (o->so == NULL) {
	perror("usrsctp_socket");
	exit(1);
    }

    if (usrsctp_set_non_blocking(o->so, 1) < 0)
    {
        perror("Failed to set SCTP to non blocking.");
        return 0;
    }

    struct linger linger_opt;
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    if (usrsctp_setsockopt(o->so, SOL_SOCKET, SO_LINGER, &linger_opt,
                           sizeof(linger_opt)))
    {
        perror("Failed to set SO_LINGER.");
	exit(1);
    }

    uint32_t nodelay = 1;

    if (usrsctp_setsockopt(o->so, IPPROTO_SCTP, SCTP_NODELAY, &nodelay,
                           sizeof(nodelay)))
    {
        perror("Failed to set SCTP_NODELAY.");
	exit(1);
    }

    struct sctp_event ev;

    int eventTypeCount = sizeof(SCTP_EVENT_TYPES) / sizeof(int);
    memset(&ev, 0, sizeof(ev));
    ev.se_assoc_id = SCTP_ALL_ASSOC;
    ev.se_on = 1;
    for (int i = 0; i < eventTypeCount; i++)
    {
        ev.se_type = SCTP_EVENT_TYPES[i];
        if (usrsctp_setsockopt(o->so, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev))
                < 0)
        {
            printf("Failed to set SCTP_EVENT type: %i: %s\n", ev.se_type, strerror(errno));
	    exit(1);
        }
    }
    return o;
}

static void
getSctpSockAddr(struct sockaddr_conn *sconn, void *addr, int port)
{
    memset(sconn, 0, sizeof(struct sockaddr_conn));
    sconn->sconn_addr = addr;
    sconn->sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
    sconn->sconn_len = sizeof(struct sockaddr_conn);
#endif
    sconn->sconn_port = htons(port);
}

static void socket_send(sockobj* o, const void* data, size_t len)
{
    if (!o->connected) {
	return;
    }
    
    struct sctp_sndinfo sndinfo;

    sndinfo.snd_assoc_id = 0;
    sndinfo.snd_context = 0;
    sndinfo.snd_flags = 0;
    sndinfo.snd_ppid = htonl(0);
    sndinfo.snd_sid = 0;

    if (usrsctp_sendv(
	    o->so,
	    data,
	    len,
	    /* to */ NULL,
	    /* addrcnt */ 0,
	    &sndinfo,
	    (socklen_t) sizeof(sndinfo),
	    SCTP_SENDV_SNDINFO,
	    /* flags */ 0) < 0) {
        perror("usrsctp_sendv");
	exit(1);
    }
}

static void close_socket(sockobj* o)
{
    o->connected = false;
    usrsctp_close(o->so);
    usrsctp_deregister_address(o->id);
    free(o);
}

static sockobj* active[2] = { NULL, NULL };

void run_test(int close_ns)
{
    const struct timespec t10ms = {0, 10000000};
    const struct timespec close_delay = {0, close_ns};
    
    sockobj* client = create_socket("Client");
    active[0] = client;
    
    sockobj* server = create_socket("Server");
    active[1] = server;
    
    struct sockaddr_conn sconn;
    
    getSctpSockAddr(&sconn, server->id, 5000);
    if (usrsctp_bind(server->so, (struct sockaddr*)&sconn, sizeof(sconn)) < 0) {
	perror("usrsctp_bind");
	exit(1);
    }
    if (usrsctp_listen(server->so, 1) < 0) {
	perror("usrsctp_listen");
	exit(1);
    }

    getSctpSockAddr(&sconn, client->id, 5000);
    if (usrsctp_bind(client->so, (struct sockaddr*)&sconn, sizeof(sconn)) < 0) {
	perror("usrsctp_listen");
	exit(1);
    }

    getSctpSockAddr(&sconn, client->id, 5000);
    if (usrsctp_connect(client->so, (struct sockaddr*)&sconn, sizeof(sconn)) < 0
	&& errno != EINPROGRESS) {
	perror("usrsctp_connect");
	exit(1);
    }

    struct socket* so = NULL;
    for (int i = 0; i < 100; i++) {
	if ((so = usrsctp_accept(server->so, NULL, NULL)) == NULL) {
	    if (errno != EINPROGRESS && errno != EAGAIN) {
		perror("usrsctp_accept");
		exit(1);
	    }
	    nanosleep(&t10ms, NULL);
	}
	else {
	    break;
	}
    }
    if (so == NULL) {
	perror("usrsctp_accept");
	exit(1);
    }
    plog("App", "Accepted connection at server\n");
    usrsctp_close(server->so);
    server->so = so;

    nanosleep(&t10ms, NULL);

    plog("App", "Sending data from client\n");
    const char data1[] = "Client Hello";

    socket_send(client, data1, sizeof(data1));

    nanosleep(&t10ms, NULL);

    plog("App", "Sending data from client again\n");
    const char data2[] = "Client Hello Again";

    socket_send(client, data2, sizeof(data2));
    
    nanosleep(&close_delay, NULL);
    
    plog("App", "Closing server\n");
    close_socket(server);
    active[1] = NULL;
    
    nanosleep(&t10ms, NULL);

    close_socket(client);
    active[0] = NULL;
}

static atomic_bool done = false;

static void* hog(void* arg)
{
    unsigned int seed = (unsigned int)time(NULL);
    while (!done) {
	sqrt(rand_r(&seed));
    }
    return NULL;
}

int main(void)
{
    usrsctp_init(0, onSctpOutboundPacket, debugSctpPrintf);
    usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_FLAGS);
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    pthread_t* hogs = calloc(NUM_HOGS, sizeof(pthread_t));
    for (int i = 0; i < NUM_HOGS; i++) {
	pthread_create(&hogs[i], NULL, hog, NULL);
    }
    
    int base_delay_ns = 200000000;
    int delay_variance_ns = 10000000;

    srand48(time(NULL));

    for (int repeat = 0; repeat < NUM_REPEATS; repeat++) {
	int delay = base_delay_ns + (drand48() * 2 - 1) * delay_variance_ns;
	printf("\nRunning with delay %d ns\n", delay);
	run_test(delay);
    }

    done = true;

    for (int i = 0; i < NUM_HOGS; i++) {
	pthread_join(hogs[i], NULL);
    }

    usrsctp_finish();
    
    return 0;
}


static char* isotime(char buf[24])
{
    struct timeval tv;
    struct tm tm;

    if (gettimeofday(&tv, NULL) != 0) {
	strcpy(buf, "-");
	return buf;
    }
    if (gmtime_r(&tv.tv_sec, &tm) == NULL) {
	strcpy(buf, "-");
	return buf;
    }
    size_t len = strftime(buf, 24, "%Y-%m-%d %H:%M:%S", &tm);
    if (len < 24) {
	snprintf(buf + len, 24 - len, ".%03ld", (long)(tv.tv_usec / 1000));
    }
    return buf;
}

static void vlog(const char* label, const char* format, va_list args)
{
    char buf[24];
    printf("%s %s: ", isotime(buf), label);
    vprintf(format, args);
}

static void
debugSctpPrintf(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vlog("SCTP", format, args);
    va_end(args);
}

static void plog(const char* label, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vlog(label, format, args);
    va_end(args);
}

static sockobj* get_socket(void* addr)
{
    for (int i = 0; i < 2; i++) {
	if (active[i] != NULL && active[i]->id == addr) {
	    return active[i];
	}
    }
    return NULL;
}

static sockobj* get_other_socket(sockobj* socket)
{
    for (int i = 0; i < 2; i++) {
	if (active[i] != NULL && active[i] != socket) {
	    return active[i];
	}
    }
    return NULL;
}

struct loopback_packet_data
{
    sockobj* dest;
    void* buffer;
    size_t length;
};

static void* input_packet_data(void* arg)
{
    struct loopback_packet_data* data = (struct loopback_packet_data*)arg;
    usrsctp_conninput(data->dest->id, data->buffer, data->length, 0);
    free(data->buffer);
    free(data);
    return NULL;
}

static int
onSctpOutboundPacket
    (void *addr, void *buffer, size_t length, uint8_t tos, uint8_t set_df)
{
    sockobj* o = get_socket(addr);

    if (o == NULL) {
	return -1;
    }

    sockobj* dest = get_other_socket(o);
    if (dest == NULL) {
	return -1;
    }
    
    struct loopback_packet_data* data = malloc(sizeof(struct loopback_packet_data));
    data->dest = dest;
    data->buffer = malloc(length);
    data->length = length;
    memcpy(data->buffer, buffer, length);

    pthread_t thr;
    pthread_create(&thr, NULL, input_packet_data, (void*)data);
    pthread_detach(thr);

    return 0;
}

static int
onSctpData
    (struct socket *so, union sctp_sockstore addr, void *data, size_t datalen,
     struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
    sockobj* o = get_socket(ulp_info);
    if (o == NULL) {
	plog("App", "No socket found for data %p", ulp_info);
	return 0;
    }
    
    if ((flags & MSG_NOTIFICATION) != 0) {
	const union sctp_notification* notif = (const union sctp_notification*)data;
	if (notif->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
	    plog(o->name, "Got sctp association state update: %d\n", notif->sn_assoc_change.sac_state);
	    switch (notif->sn_assoc_change.sac_state) {
	    case SCTP_COMM_UP:
	    {
		plog(o->name, "sctp is now up.  was connected = %d\n", o->connected);
		o->connected = true;
		break;
	    }
	    case SCTP_COMM_LOST:
	    case SCTP_SHUTDOWN_COMP:
	    case SCTP_CANT_STR_ASSOC:
	    {
		plog(o->name, "sctp is now down.  was connected = %d\n", o->connected);
		o->connected = false;
	    }
	    }
	}
    }
    else {
	plog(o->name, "Received: %d bytes: %.*s\n",
	     (int)datalen, (int)datalen, (char*)data);
    }
    return 1;
}
