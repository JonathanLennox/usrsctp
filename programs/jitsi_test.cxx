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

#include <unistd.h>
#include <time.h>
#include <future>

#include "jitsi_sctp4j.h"

using namespace std;

class MutualDataSender : public SctpDataSender
{
private:
    weak_ptr<SctpSocket> peer;

public:
    bool enabled = true;

    MutualDataSender(shared_ptr<SctpSocket> p): peer(p) { }

    virtual int send(string data, int length) {
	if (enabled) {
	    auto p = peer.lock();
	    if (p) {
		auto thr = thread([=]{p->onConnIn(data, length);});
		thr.detach();
	    }
	    return length;
	}
	return 0;
    }
};

class LoggingDataCallback : public SctpDataCallback
{
private:
    Logger logger;

public:
    LoggingDataCallback(shared_ptr<SctpSocket> s): logger(s->logger) { }

    virtual void onSctpPacket(std::string data, int sid, int ssn, int tsn, long ppid,
			      int context, int flags) {
	logger.log() << "data received: " << data << endl;
    }
};


int main(void)
{
    Sctp4j::init(0);
    const struct timespec t100ms = {0, 100'000'000};

    auto client = Sctp4j::createClientSocket(5000, Logger("Client"));
    auto server = Sctp4j::createServerSocket(5000, Logger("Server"));

    client->outgoingDataSender = unique_ptr<SctpDataSender>(new MutualDataSender(server));
    server->outgoingDataSender = unique_ptr<SctpDataSender>(new MutualDataSender(client));

    client->dataCallback = unique_ptr<SctpDataCallback>(new LoggingDataCallback(client));
    server->dataCallback = unique_ptr<SctpDataCallback>(new LoggingDataCallback(server));

    server->listen();
    client->connect(5000);

    for (int i = 0; i < 100; i++) {
	if (server->accept()) {
	    server->logger.log() << "Accepted" << endl;
	    break;
	}
	nanosleep(&t100ms, NULL);
    }

    nanosleep(&t100ms, NULL);

    client->send("Client Hello", 1, 0, 0);

    nanosleep(&t100ms, NULL);

    server->send("Server Hello", 1, 0, 0);

    sleep(5);

    cout << endl;
    cout << "Closing sockets" << endl;

    client->close();
    server->close();

    client.reset();
    server.reset();

    sleep(30);
    
    return 0;
}
