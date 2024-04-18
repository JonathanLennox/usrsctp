/*
 * Copyright (C) 2024 8x8, Inc
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* Simplified code replicating the behavior of Jitsi's JNI code as used in jitsi-videobridge. */

#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include "jitsi_jni.h"

typedef struct _SctpSocket
{
    struct socket *so;
    void *id;
    int localPort;
} SctpSocket;


IncomingSctpDataHandler* incomingSctpDataHandler = NULL;
OutgoingSctpDataHandler* outgoingSctpDataHandler = NULL;


int
callOnSctpOutboundPacket
    (void *socketAddr, void *data, size_t length, uint8_t tos, uint8_t set_df);

int
connectSctp(SctpSocket *sctpSocket, int remotePort);

static void
debugSctpPrintf(const char *format, ...);

static void
sctpPError(const char* message);

void
getSctpSockAddr(struct sockaddr_conn *sconn, void *addr, int port);

static int
onSctpInboundPacket
    (struct socket *so, union sctp_sockstore addr, void *data, size_t datalen,
        struct sctp_rcvinfo rcv, int flags, void *ulp_info);

static int
onSctpOutboundPacket
    (void *addr, void *buffer, size_t length, uint8_t tos, uint8_t set_df);

static int SCTP_EVENT_TYPES[]
    = {
        SCTP_ASSOC_CHANGE,
        SCTP_PEER_ADDR_CHANGE,
        SCTP_SEND_FAILED_EVENT,
        SCTP_SENDER_DRY_EVENT,
        SCTP_STREAM_RESET_EVENT
    };


void JNI_on_network_in(uintptr_t ptr, const char* pkt, int len)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    usrsctp_conninput(sctpSocket->id, pkt, len, 0);
}

bool JNI_usrsctp_accept(uintptr_t ptr)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    struct socket* so;

    if((so = usrsctp_accept(sctpSocket->so, NULL, NULL)) != NULL)
    {
        usrsctp_close(sctpSocket->so);
        sctpSocket->so = so;
        return true;
    }
    else
    {
	sctpPError("usrsctp_accept");
        return false;
    }
}

void JNI_usrsctp_close(uintptr_t ptr)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    usrsctp_close(sctpSocket->so);
    usrsctp_deregister_address(sctpSocket->id);
    free(sctpSocket);
}

bool JNI_usrsctp_connect(uintptr_t ptr, int remotePort)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    return
        connectSctp(sctpSocket, remotePort)
            ? true
            : false;
}

bool JNI_usrsctp_init(int port, uint32_t sctp_debug_mask)
{
    /*
     * First argument is udp_encapsulation_port which is not relevant to our
     * AF_CONN use of SCTP.
     */
    printf("org_jitsi_modified_sctp4j_SctpJni.c calling init\n");
    usrsctp_init((uint16_t) port, onSctpOutboundPacket, debugSctpPrintf);

    printf("=====>: org_jitsi_modified_sctp4j_SctpJni.c setting debug mask %#x\n", sctp_debug_mask);
    usrsctp_sysctl_set_sctp_debug_on(sctp_debug_mask);

    /* TODO(ldixon) Consider turning this on/off. */
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    return true;
}

void JNI_usrsctp_listen(uintptr_t ptr)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    struct sockaddr_conn sconn;
    struct sockaddr_conn *psconn = &sconn;

    /* Bind server socket. */
    getSctpSockAddr(psconn, sctpSocket->id, sctpSocket->localPort);
    if (usrsctp_bind(sctpSocket->so, (struct sockaddr *) psconn, sizeof(sconn))
            < 0)
    {
        sctpPError("usrsctp_bind");
    }
    /* Make server side passive. */
    if (usrsctp_listen(sctpSocket->so, 1) < 0)
        sctpPError("usrsctp_listen");
}


int JNI_usrsctp_send(uintptr_t ptr, const char* data, int len,
		     bool ordered, bool abort, int sid, int ppid)
{
    SctpSocket* sctpSocket = (SctpSocket*)ptr;
    ssize_t r;  /* returned by usrsctp_sendv */

    struct sctp_sndinfo sndinfo;

    sndinfo.snd_assoc_id = 0;
    sndinfo.snd_context = 0;
    sndinfo.snd_flags = 0;
    if (false == ordered)
	sndinfo.snd_flags |= SCTP_UNORDERED;
    if (abort) {
	sndinfo.snd_flags |= SCTP_ABORT;
    }
    sndinfo.snd_ppid = htonl(ppid);
    sndinfo.snd_sid = sid;

    r
	= usrsctp_sendv(
	    sctpSocket->so,
	    data,
	    len,
	    /* to */ NULL,
	    /* addrcnt */ 0,
	    &sndinfo,
	    (socklen_t) sizeof(sndinfo),
	    SCTP_SENDV_SNDINFO,
	    /* flags */ 0);
    if (r < 0)
        sctpPError("Sctp send error: ");
    return (int)r;
}


uintptr_t JNI_usrsctp_socket(int localPort, long idL)
{
    SctpSocket *sctpSocket;
    struct socket *so;
    struct linger linger_opt;
    struct sctp_assoc_value stream_rst;
    uint32_t nodelay = 1;
    size_t i, eventTypeCount;
    void *id = (void *) (intptr_t) idL;

    struct sctp_event ev;

    sctpSocket = malloc(sizeof(SctpSocket));
    if (sctpSocket == NULL)
    {
        sctpPError("Out of memory!");
        return 0;
    }

    // Register this object's index for usrsctp. This is used by SCTP to
    // direct the packets received (by the created socket) to this class.
    usrsctp_register_address(id);

    so
        = usrsctp_socket(
                AF_CONN,
                SOCK_STREAM,
                IPPROTO_SCTP,
                onSctpInboundPacket,
                /* send_cb */ NULL,
                /* sb_threshold */ 0,
                id);
    if (so == NULL)
    {
        sctpPError("usrsctp_socket");
        free(sctpSocket);
        return 0;
    }

    // Make the socket non-blocking. Connect, close, shutdown etc will not block
    // the thread waiting for the socket operation to complete.
    if (usrsctp_set_non_blocking(so, 1) < 0)
    {
        sctpPError("Failed to set SCTP to non blocking.");
        free(sctpSocket);
        return 0;
    }

    // This ensures that the usrsctp close call deletes the association. This
    // prevents usrsctp from calling onSctpOutboundPacket with references to
    // this class as the address.
    linger_opt.l_onoff = 1;
    linger_opt.l_linger = 0;
    if (usrsctp_setsockopt(so, SOL_SOCKET, SO_LINGER, &linger_opt,
                           sizeof(linger_opt)))
    {
        sctpPError("Failed to set SO_LINGER.");
        free(sctpSocket);
        return 0;
    }

    // Enable stream ID resets.
    stream_rst.assoc_id = SCTP_ALL_ASSOC;
    stream_rst.assoc_value = 1;
    if (usrsctp_setsockopt(so, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
                           &stream_rst, sizeof(stream_rst)))
    {
        sctpPError("Failed to set SCTP_ENABLE_STREAM_RESET.");
        free(sctpSocket);
        return 0;
    }

    // Nagle.
    if (usrsctp_setsockopt(so, IPPROTO_SCTP, SCTP_NODELAY, &nodelay,
                           sizeof(nodelay)))
    {
        sctpPError("Failed to set SCTP_NODELAY.");
        free(sctpSocket);
        return 0;
    }

    // Subscribe to SCTP events.
    eventTypeCount = sizeof(SCTP_EVENT_TYPES) / sizeof(int);
    memset(&ev, 0, sizeof(ev));
    ev.se_assoc_id = SCTP_ALL_ASSOC;
    ev.se_on = 1;
    for (i = 0; i < eventTypeCount; i++)
    {
        ev.se_type = SCTP_EVENT_TYPES[i];
        if (usrsctp_setsockopt(so, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev))
                < 0)
        {
            printf("Failed to set SCTP_EVENT type: %i: %s\n", ev.se_type, strerror(errno));
            free(sctpSocket);
            return 0;
        }
    }

    sctpSocket->so = so;
    sctpSocket->id = id;
    sctpSocket->localPort = localPort;

    return (uintptr_t)sctpSocket;
}

void
callOnSctpInboundPacket
    (void *socketAddr, void *data, size_t length, uint16_t sid, uint16_t ssn,
        uint16_t tsn, uint32_t ppid, uint16_t context, int flags)
{
    if (incomingSctpDataHandler) {
	incomingSctpDataHandler((uintptr_t)socketAddr, data, length, sid, ssn, tsn, ppid, context, flags);
    }
    else {
	printf("Failed to get onSctpInboundPacket method\n");
    }
}


int
callOnSctpOutboundPacket
    (void *socketAddr, void *data, size_t length, uint8_t tos, uint8_t set_df)
{
    if (outgoingSctpDataHandler) {
	outgoingSctpDataHandler((uintptr_t)socketAddr, data, length, tos, set_df);
	return 0;
    }
    printf("Failed to get onSctpOutboundPacket method\n");
    return -1;
}


int
connectSctp(SctpSocket *sctpSocket, int remotePort)
{
    struct socket *so;
    struct sockaddr_conn sconn;
    struct sockaddr_conn *psconn = &sconn;
    int connect_result;

    so = sctpSocket->so;

    getSctpSockAddr(psconn, sctpSocket->id, sctpSocket->localPort);
    if (usrsctp_bind(so, (struct sockaddr *) psconn, sizeof(sconn)) < 0)
    {
        sctpPError("usrsctp_bind");
        return 0;
    }

    getSctpSockAddr(psconn, sctpSocket->id, remotePort);
    connect_result
        = usrsctp_connect(so, (struct sockaddr *) psconn, sizeof(sconn));
    if (connect_result < 0 && errno != EINPROGRESS)
    {
        sctpPError("usrsctp_connect");
        return 0;
    }

    return 1;
}

static void
debugSctpPrintf(const char *format, ...)
{
    char buf[24];
    printf("%s SCTP: ", isotime(buf));
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

static void
sctpPError(const char* message)
{
    debugSctpPrintf("ERROR: %s: %s\n", message, strerror(errno));
}

void
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

// This is the callback called from usrsctp when data has been received, after
// a packet has been interpreted and parsed by usrsctp and found to contain
// payload data. It is called by a usrsctp thread. It is assumed this function
// will free the memory used by 'data'.
static int
onSctpInboundPacket
    (struct socket *so, union sctp_sockstore addr, void *data, size_t datalen,
        struct sctp_rcvinfo rcv, int flags, void *ulp_info)
{
    if (data)
    {
        // Pass the (packet) data to Java.
        if (flags & MSG_NOTIFICATION)
        {
            callOnSctpInboundPacket(
                    ulp_info,
                    data,
                    datalen,
                    /* sid */ 0,
                    /* ssn */ 0,
                    /* tsn */ 0,
                    /* ppid */ 0,
                    /* context */ 0,
                    flags);
        }
        else
        {
            callOnSctpInboundPacket(
                    ulp_info,
                    data,
                    datalen,
                    rcv.rcv_sid,
                    rcv.rcv_ssn,
                    rcv.rcv_tsn,
                    rcv.rcv_ppid,
                    rcv.rcv_context,
                    flags);
        }
        free(data);
    }
    return 1;
}

static int
onSctpOutboundPacket
    (void *addr, void *buffer, size_t length, uint8_t tos, uint8_t set_df)
{
    if (buffer && length) {
        return callOnSctpOutboundPacket(addr, buffer, length, tos, set_df);
    }

    /* FIXME not sure about this value, but an error for now */
    return -1;
}

char* isotime(char buf[24])
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
