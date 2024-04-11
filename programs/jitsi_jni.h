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

#ifndef JITSI_JNI_H
#define JITSI_JNI_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <usrsctp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Functions simplified from JNI */

typedef void (IncomingSctpDataHandler)(uintptr_t socketAddr, const char *data, size_t length, uint16_t sid, uint16_t ssn,
        uint16_t tsn, uint32_t ppid, uint16_t context, int flags);


typedef int (OutgoingSctpDataHandler)(uintptr_t socketAddr, void *data, size_t length, uint8_t tos, uint8_t set_df);


extern IncomingSctpDataHandler* incomingSctpDataHandler;
extern OutgoingSctpDataHandler* outgoingSctpDataHandler;


void JNI_on_network_in(uintptr_t ptr, const char* pkt, int len);
bool JNI_usrsctp_accept(uintptr_t ptr);
void JNI_usrsctp_close(uintptr_t ptr);
bool JNI_usrsctp_connect(uintptr_t ptr, int remotePort);
bool JNI_usrsctp_init(int port);
void JNI_usrsctp_listen(uintptr_t ptr);
int JNI_usrsctp_send(uintptr_t ptr, const char* data, int len,
		     bool ordered, bool abort, int sid, int ppid);
uintptr_t JNI_usrsctp_socket(int localPort, long idL);

/* Not part of jitsi_jni, but a useful util. */
char* isotime(char buf[24]);
    
#ifdef __cplusplus
}
#endif

#endif
