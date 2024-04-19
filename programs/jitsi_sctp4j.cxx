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

/* Simplified code replicating the behavior of Jitsi's Sctp code as used in jitsi-videobridge. */
#include <iostream>

#include "jitsi_sctp4j.h"
#include "jitsi_jni.h"

using namespace std;

std::ostream& Logger::log()
{
    char buf[24];
    return std::cout << isotime(buf) << " " << prefix << ": ";
}

class Exception {
public:
    string message;
    Exception(string msg): message(msg) { }
};

class IOException: public Exception {
public: IOException(string msg): Exception(msg) { }
};

class RuntimeException: public Exception {
public: RuntimeException(string msg): Exception(msg) { }
};

class IllegalArgumentException: public Exception {
public: IllegalArgumentException(string msg): Exception(msg) { }
};


SctpSocket::SctpSocket(uintptr_t ptr, long id, Logger lgr): ptr(ptr), id(id), ptrLockCount(0), logger(lgr)
{
}

uintptr_t SctpSocket::lockPtr()
{
    uintptr_t ptr;

    lock_guard<std::mutex> lock(mutex);

    if (closed)
    {
	throw IOException("SctpSocket is closed!");
    }
    else
    {
	ptr = this->ptr;
	if (ptr == 0)
	    throw IOException("SctpSocket is closed!");
	else
	    ++ptrLockCount;
    }

    return ptr;
}

    /**
     * Unlocks {@link #ptr} for reading. If this <code>SctpSocket</code> has been
     * closed while <code>ptr</code> was locked for reading and there are no other
     * readers at the time of the method invocation, closes <code>ptr</code>. Each
     * <code>unlockPtr</code> method invocation must be balanced with a previous
     * <code>lockPtr</code> method invocation.
     */
void SctpSocket::unlockPtr()
{
    uintptr_t ptr;

    {
	lock_guard<std::mutex> synchronized(mutex);

	int ptrLockCount = this->ptrLockCount - 1;

	if (ptrLockCount < 0)
	{
	    throw RuntimeException(
		"Unbalanced SctpSocket:unlockPtr() method invocation!");
	}
        else
        {
	    this->ptrLockCount = ptrLockCount;
	    if (closed && (ptrLockCount == 0))
            {
		// The actual closing of ptr was deferred until now.
		ptr = this->ptr;
		this->ptr = 0;
	    }
	    else
            {
		// The actual closing of ptr may not have been requested or
		// will be deferred.
		ptr = 0;
	    }
	}
    }
    if (ptr != 0)
    {
	Sctp4j::closeSocket(ptr, id);
    }
}

bool SctpSocket::socketConnected()
{
    return ptr != 0 && connected;
}

void SctpSocket::onNotification(const sctp_notification* notif)
{
    if (notif->sn_header.sn_type == SCTP_ASSOC_CHANGE) {
	logger.log() << "Got sctp association state update: " << notif->sn_assoc_change.sac_state << endl;
	switch (notif->sn_assoc_change.sac_state) {
	case SCTP_COMM_UP:
	{
	    bool wasReady = isReady();
	    logger.log() << "sctp is now up. was ready=" << wasReady << endl;
	    connected = true;
	    if (isReady() && !wasReady) {
		if (eventHandler) {
		    logger.log() << "sctp invoking onready" << endl;
		    eventHandler->onReady();
		}
	    }
	    break;
	}
	case SCTP_COMM_LOST:
	case SCTP_SHUTDOWN_COMP:
	case SCTP_CANT_STR_ASSOC:
	{
	    connected = false;
	    if (eventHandler)
	    {
		eventHandler->onDisconnected();
	    }
	    break;
	}
	}
    }
}

void SctpSocket::close()
{
    // The value of the field closed only ever changes from false to true.
    // Additionally, its reading is always synchronized and combined with
    // access to the field ptrLockCount governed by logic which binds the
    // meanings of the two values together. Consequently, the
    // synchronization with respect to closed is considered consistent.
    // Allowing the writing outside the synchronized block expedites the
    // actual closing of ptr.
    closed = true;
    connected = false;
    
    uintptr_t ptr;

    {
	lock_guard<std::mutex> synchronized(mutex);
	
	if (ptrLockCount == 0)
        {
	    // The actual closing of ptr will not be deferred.
	    ptr = this->ptr;
	    this->ptr = 0;
	}
	else
        {
	    // The actual closing of ptr will be deferred.
	    ptr = 0;
	}
    }
    if (ptr != 0)
    {
	Sctp4j::closeSocket(ptr, id);
    }
}

/**
 * Call this method to pass network packets received on the link to the
 * SCTP stack.
 *
 * @param packet network packet received.
 * @param offset the position in the packet buffer where actual data starts
 * @param len length of packet data in the buffer.
 */
void SctpSocket::onConnIn(string packet, int len)
{
    if (len <= 0 || len > packet.size())
    {
	throw IllegalArgumentException("l: " + to_string(len) + " packet l: " + to_string(packet.size()));
    }

    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	logger.log() << "Socket isn't open, ignoring incoming data" << endl;
	return;
    }

    try
    {
	JNI_on_network_in(ptr, packet.data(), len);
    }
    catch (...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();
}

/**
 * Method fired by SCTP stack to notify about incoming data.
 *
 * @param data buffer holding received data
 * @param sid stream id
 * @param ssn
 * @param tsn
 * @param ppid payload protocol identifier
 * @param context
 * @param flags
 */
void SctpSocket::onSctpIn(
    string data, int sid, int ssn, int tsn, long ppid, int context,
    int flags)
{
    if ((flags & MSG_NOTIFICATION) != 0)
    {
	const sctp_notification* notif = (const sctp_notification*)data.data();
	onNotification(notif);
    }
    else
    {
        if (dataCallback)
	{
	    dataCallback->onSctpPacket(
		data, sid, ssn, tsn, ppid, context, flags);
	}
    }
}

/**
 * Callback triggered by SCTP stack whenever it wants to send some network
 * packet.
 *
 * @param packet network packet buffer.
 * @param tos type of service???
 * @param set_df use IP don't fragment option
 * @return 0 if the packet was successfully sent or -1 otherwise.
 */
int SctpSocket::onSctpOut(string packet, int tos, int set_df)
{
    int ret = -1;
    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	return ret;
    }

    try
    {
	if (outgoingDataSender)
       	{
	    ret = outgoingDataSender->send(packet, packet.size());
	}
    }
    catch(...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();

    return ret;
}

/**
 * Send SCTP app data through the stack and out
 * @return the number of bytes sent or -1 on error
 */
int SctpSocket::send(string data, bool ordered, bool abort, int sid, int ppid)
{
    int ret = -1;

    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	return ret;
    }

    try
    {
	if (socketConnected())
       	{
	    ret = JNI_usrsctp_send(
		ptr,
		data.data(),
		data.length(),
		ordered, abort, sid, ppid);
	}
    }
    catch(...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();

    return ret;
}

SctpClientSocket::SctpClientSocket(uintptr_t ptr, long id, Logger logger) :
    SctpSocket(ptr, id, logger)
{
}

bool SctpClientSocket::isReady()
{
    return socketConnected();
}

/**
 * Starts a connection on this socket (if it's open).
 *
 * @return true if the connection has started, false otherwise
 */
bool SctpClientSocket::connect(int remoteSctpPort)
{
    bool ret = false;
    
    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	return ret;
    }

    try
    {
	ret = JNI_usrsctp_connect(ptr, remoteSctpPort);
    }
    catch(...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();

    return ret;
}

SctpServerSocket::SctpServerSocket(uintptr_t ptr, long id, Logger logger) :
    SctpSocket(ptr, id, logger)
{
}

void SctpServerSocket::listen()
{
    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	logger.log() << "Server socket can't listen: " << ioe.message << endl;
	return;
    }

    try
    {
	JNI_usrsctp_listen(ptr);
    }
    catch(...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();

    return;
}

bool SctpServerSocket::isReady()
{
    return socketConnected() && accepted;
}

/**
 * Accepts incoming SCTP connection.
 *
 * Usrsctp is currently configured to work in non blocking mode thus this
 * method should be polled in intervals.
 *
 * NOTE: Normally the socket used to accept would be re-used to accept
 * multiple incoming connections, and each successful accept would return a
 * new socket for the new connection.  Instead, the JNI C file, upon
 * successfully accepting a connection, will overwrite an underlying socket
 * pointer it stores to now 'redirect' this java {@link SctpSocket} instance
 * to the newly accepted connection.  So after a successful call to accept,
 * this instance should be used for sending/receiving data on that new
 * connection.
 *
 * @return <code>true</code> if we have accepted incoming connection
 *         successfully.
 */
bool SctpServerSocket::accept()
{
    bool ret = false;
    try
    {
	lockPtr();
    }
    catch (IOException& ioe)
    {
	logger.log() << "Server can't accept: " << ioe.message << endl;
	return ret;
    }

    try
    {
	if (JNI_usrsctp_accept(ptr))
	{
	    accepted = true;
	    // It's possible we can get the SCTP notification SCTP_COMM_UP
	    // before we've accepted, since accept is called repeatedly at
	    // some interval, so we need to check if we're ready here
	    //TODO: doesn't feel great to invoke this handler in the context
	    // of the accept call, should we post it elsewhere?
	    if (isReady() && eventHandler)
	    {
		eventHandler->onReady();
	    }
	    ret = true;
	}
    }
    catch(...)
    {
	unlockPtr();
	throw;
    }
    unlockPtr();

    return ret;
}


bool Sctp4j::initialized = false;

void Sctp4j::init(int port, uint32_t sctp_debug_mask)
{
    if (!initialized)
    {
	JNI_usrsctp_init(port, sctp_debug_mask);
	initialized = true;

	incomingSctpDataHandler = onSctpIncomingData;
	outgoingSctpDataHandler = onOutgoingSctpData;
    }
}

void Sctp4j::init(int port)
{
    init(port, 0);
}

std::unordered_map<long, shared_ptr<SctpSocket>> Sctp4j::sockets = unordered_map<long, shared_ptr<SctpSocket>>();


/**
 * Closes the SCTP socket addressed by the given native pointer.
 *
 * @param ptr the native socket pointer.
 */
void Sctp4j::closeSocket(uintptr_t ptr, long id)
{
    JNI_usrsctp_close(ptr);
    sockets.erase(id);
}


void Sctp4j::onSctpIncomingData(
    uintptr_t socketAddr,
    const char* data, size_t length,
    uint16_t sid, uint16_t ssn, uint16_t tsn, uint32_t ppid, uint16_t context, int flags)
{
    try
    {
	auto socket = Sctp4j::sockets.at(socketAddr);
	socket->onSctpIn(string(data, length), sid, ssn, tsn, ppid, context, flags);
    }
    catch(out_of_range& e)
    {
	cout << "No socket found in onSctpIncomingData" << endl;
    }
}

int Sctp4j::onOutgoingSctpData(
    uintptr_t socketAddr,
    void *data, size_t length,
    uint8_t tos, uint8_t set_df)
{
    try
    {
	auto socket = Sctp4j::sockets.at(socketAddr);
	return socket->onSctpOut(string((const char*)data, length), tos, set_df);
    }
    catch(out_of_range& e)
    {
	cout << "No socket found in onOutgoingSctpData" << endl;
    }
    return -1;
}


/**
 * Create an {@link SctpServerSocket} which can be used to listen for an
 * incoming connection
 * @param localSctpPort
 * @return
 */
shared_ptr<SctpServerSocket> Sctp4j::createServerSocket(int localSctpPort, Logger logger)
{
    long id = nextId++;
    uintptr_t ptr = JNI_usrsctp_socket(localSctpPort, id);
    if (ptr == 0)
    {
	logger.log() << "Failed to create server socket" << endl;
	return NULL;
    }
    auto socket = shared_ptr<SctpServerSocket>(new SctpServerSocket(ptr, id, logger));
    sockets[id] = socket;

    return socket;
}
/**
 * Create an {@link SctpClientSocket} which can be used to connect to an
 * {@link SctpServerSocket}.
 *
 * @param localSctpPort
 * @return
 */
shared_ptr<SctpClientSocket> Sctp4j::createClientSocket(int localSctpPort, Logger logger)
{
    long id = nextId++;
    uintptr_t ptr = JNI_usrsctp_socket(localSctpPort, id);
    if (ptr == 0)
    {
	logger.log() << "Failed to create client socket" << endl;
	return NULL;
    }
    auto socket = shared_ptr<SctpClientSocket>(new SctpClientSocket(ptr, id, logger));
    sockets[id] = socket;

    return socket;
}


atomic_long Sctp4j::nextId(1);
