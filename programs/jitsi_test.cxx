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

const int NUM_HOGS = 8;
const int NUM_REPEATS = 1000;

#include <unistd.h>
#include <time.h>
#include <future>
#include <vector>
#include <cmath>
#include <functional>
#include <sstream>

#include "jitsi_sctp4j.h"

using namespace std;

class MutualDataSender : public SctpDataSender
{
private:
    weak_ptr<SctpSocket> peer;

    static constexpr struct timespec t30ms = {0, 30'000'000};


public:
    bool enabled = true;

    MutualDataSender(shared_ptr<SctpSocket> p): peer(p) { }

    virtual int send(string data, int length) {
	if (enabled) {
	    auto p = peer.lock();
	    if (p) {
		auto thr = thread([=]{
		    p->onConnIn(data, length);
		});
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

void run_test(Logger& logger, int close_ns)
{
    const struct timespec t10ms = {0, 10'000'000};
    const struct timespec close_delay = {0, close_ns};
    
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
	    logger.log() << "Server accepted" << endl;
	    break;
	}
	nanosleep(&t10ms, NULL);
    }

    nanosleep(&t10ms, NULL);

    logger.log() << "Sending data from client" << endl;
    client->send("Client Hello", true, false, 0, 0);

    nanosleep(&t10ms, NULL);

    client->send("Client Hello Again", true, false, 0, 0);

    nanosleep(&close_delay, NULL);

    logger.log() << "Closing server" << endl;
    
    server->close();
    
    nanosleep(&t10ms, NULL);

    client->close();

    client.reset();
    server.reset();
}

static atomic<bool> done = false;

static void hog(void)
{
    unsigned int seed = (unsigned int)time(NULL);
    while (!done) {
	sqrt(rand_r(&seed));
    }
}

int main(void)
{
    Sctp4j::init(0, 0x00000002 /* SCTP_DEBUG_TIMER2 */);
    Logger logger("App");

    int base_delay = 200'000'000;
    int delay_variance = 10'000'000;

    srand48(time(NULL));
    srand(time(NULL));

    auto hogs = vector<thread>();
    for (int i = 0; i < NUM_HOGS; i++) {
	hogs.push_back(thread(hog));
    }

    for (int repeat = 0; repeat < NUM_REPEATS; repeat++) {
	int delay = base_delay + (drand48() * 2 - 1) * delay_variance;
	logger.log() << "Running with delay " << delay << "ns" << endl;
	cout << endl;
	run_test(logger, delay);
    }

done = true;

    for_each(hogs.begin(), hogs.end(), mem_fn(&thread::join));
    
    usrsctp_finish();

    return 0;
}
