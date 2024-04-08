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

/* Simplified code replicating the behavior of Jitsi's Sctp code as used in sctp4j. */

#include <unordered_map>
#include <string>
#include <memory>
#include <mutex>
#include <cstdint>
#include <atomic>
#include <usrsctp.h>

#include "jitsi_jni.h"

class SctpDataSender
{
  public: virtual int send(std::string data, int length);

  public: virtual ~SctpDataSender() = 0;
};

class SctpDataCallback
{
  public: virtual void onSctpPacket(std::string data, int sid, int ssn, int tsn, long ppid,
				    int context, int flags);
  public: virtual ~SctpDataCallback() = 0;
};

class Logger
{
private:
    std::string prefix;
public:
    Logger(std::string prfx): prefix(prfx) { }
    std::ostream& log() { return (std::cout << prefix << ": "); }
};

class SctpSocket {
  public: class SctpSocketEventHandler
    {
      public: virtual void onReady() = 0;
      public: virtual void onDisconnected() = 0;

      public: virtual ~SctpSocketEventHandler() = 0;
    };

    /**
     * ID for the socket address map
     */
  private: long id;

    /**
     * Pointer to the native socket counterpart
     */
  protected: std::uintptr_t ptr;

    /**
     * Used to send network packets.
     */
  public: std::unique_ptr<SctpDataSender> outgoingDataSender;

    /**
     * Handler to be notified of socket events (connected, disconnected)
     */
  public: std::unique_ptr<SctpSocketEventHandler> eventHandler;

  private:
    bool connected = false;

    /**
     * Callback used to notify about received data that has been processed by the
     * SCTP stack
     */
  public: std::unique_ptr<SctpDataCallback> dataCallback;

    /**
     * The number of current readers of {@link #ptr} which are preventing the
     * writer (i.e. {@link #close()}) from invoking
     * {@link Sctp4j#closeSocket(long, long)}.
     */
  private: int ptrLockCount = 0;

    /**
     * The indicator which determines whether {@link #close()} has been invoked
     * on this <code>SctpSocket</code>. It does NOT indicate whether
     * {@link Sctp4j#closeSocket(long, long)} has been invoked with {@link #ptr}.
     */
  private: bool closed = false;

  protected: Logger logger;
    
  public: SctpSocket(std::uintptr_t ptr, long id, Logger lgr);

    /**
     * Locks {@link #ptr} for reading and returns its value if this
     * <code>SctpSocket</code> has not been closed (yet). Each <code>lockPtr</code>
     * method invocation must be balanced with a subsequent <code>unlockPtr</code>
     * method invocation.
     *
     * @return <code>ptr</code>
     * @throws IOException if this <code>SctpSocket</code> has (already) been closed
     */
  protected: std::uintptr_t lockPtr();

    /**
     * Unlocks {@link #ptr} for reading. If this <code>SctpSocket</code> has been
     * closed while <code>ptr</code> was locked for reading and there are no other
     * readers at the time of the method invocation, closes <code>ptr</code>. Each
     * <code>unlockPtr</code> method invocation must be balanced with a previous
     * <code>lockPtr</code> method invocation.
     */
  protected: void unlockPtr();

    /**
     * Whether or not this connection is ready for use.  The logic to determine
     * this is different for client vs server sockets.
     * @return
     */
  protected: virtual bool isReady() = 0;

  protected: bool socketConnected();

    /**
     * Fired when usrsctp stack sends notification.
     *
     * @param notification the <code>SctpNotification</code> triggered.
     */
  private: void onNotification(const sctp_notification* notification);

    /**
     * Closes this socket. After call to this method this instance MUST NOT be
     * used.
     */
  private: void close();

    /**
     * Call this method to pass network packets received on the link to the
     * SCTP stack.
     *
     * @param packet network packet received.
     * @param offset the position in the packet buffer where actual data starts
     * @param len length of packet data in the buffer.
     */
  public: void onConnIn(std::string packet, int len);

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
  private: void onSctpIn(std::string data, int sid, int ssn, int tsn, long ppid, int context,
		    int flags);

    /**
     * Callback triggered by SCTP stack whenever it wants to send some network
     * packet.
     *
     * @param packet network packet buffer.
     * @param tos type of service???
     * @param set_df use IP don't fragment option
     * @return 0 if the packet was successfully sent or -1 otherwise.
     */
  public: int onSctpOut(std::string packet, int tos, int set_df);

    /**
     * Send SCTP app data through the stack and out
     * @return the number of bytes sent or -1 on error
     */
  public: int send(std::string data, bool ordered, int sid, int ppid);

  public: virtual ~SctpSocket() = default;

  private: std::mutex mutex;
    
    friend class Sctp4j;
};

/**
 * An SctpServerSocket can be used to listen for an incoming connection and then
 * to send and receive data to/from the other peer.
 */
class SctpServerSocket: public SctpSocket
{
  private: bool accepted = false;

  public: SctpServerSocket(std::uintptr_t ptr, long id, Logger logger);

    /**
     * Makes SCTP socket passive.
     * "Marks the socket as a passive socket, that is, as a socket that will be
     * used to accept incoming connection requests using accept"
     */
  public: void listen();

  protected: bool isReady();


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
  public: bool accept();

  public: virtual ~SctpServerSocket() = default;
};

class SctpClientSocket: public SctpSocket
{
  public: SctpClientSocket(std::uintptr_t ptr, long id, Logger logger);

  protected: bool isReady();

    /**
     * Starts a connection on this socket (if it's open).
     *
     * @return true if the connection has started, false otherwise
     */
  public: bool connect(int remoteSctpPort);
    
  public: virtual ~SctpClientSocket() = default;
};

class Sctp4j {
 private: static bool initialized;

 public: static void init(int port);

    /**
     * Closes the SCTP socket addressed by the given native pointer.
     *
     * @param ptr the native socket pointer.
     */
  private: static void closeSocket(std::uintptr_t ptr, long id);

    /**
     * List of instantiated SctpSockets mapped by native pointer.
     */
  private: static std::unordered_map<long, SctpSocket*> sockets;

    /**
     * This callback is called by the SCTP stack when it has an incoming packet
     * it has finished processing and wants to pass on.  This is only called for
     * SCTP 'app' packets (not control packets, which are handled entirely by
     * the stack itself)
     *
     * @param socketAddr
     * @param data
     * @param sid
     * @param ssn
     * @param tsn
     * @param ppid
     * @param context
     * @param flags
     */
  private: static IncomingSctpDataHandler onSctpIncomingData;


    /**
     * This callback is called by the SCTP stack when it has a packet it wants
     * to send out to the network.
     * @param socketAddr
     * @param data
     * @param tos
     * @param set_df
     * @return 0 if the packet was successfully sent, -1 otherwise
     */
  private: static OutgoingSctpDataHandler onOutgoingSctpData;

    /**
     * Create an {@link SctpServerSocket} which can be used to listen for an
     * incoming connection
     * @param localSctpPort
     * @return
     */
  public: static SctpServerSocket* createServerSocket(int localSctpPort, Logger logger);


    /**
     * Create an {@link SctpClientSocket} which can be used to connect to an
     * {@link SctpServerSocket}.
     *
     * @param localSctpPort
     * @return
     */
  public: static SctpClientSocket* createClientSocket(int localSctpPort, Logger logger);

  private: static std::atomic_long nextId;

    friend class SctpSocket;
};
