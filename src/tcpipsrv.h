// tcpipclientthread.h
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright (C) 2000-2026 Ake Hedman, Grodans Paradis AB
// <info@vscp.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

/*!
    @brief Functionality for the VSCP TCP/IP server
    This includes managing client connections, handling commands, and
   facilitating communication over TCP/IP. It provides an interface for sending
   and receiving VSCP events, managing user sessions, and enforcing access
   control based on user privileges.

    The object is owned by the application ControlObject which holds users and
   clients
*/

#if !defined(VSCP_TCPIPSRV_H__INCLUDED_)
#define VSCP_TCPIPSRV_H__INCLUDED_

#include "mongoose.h"

#include "clientlist.h"
#include "controlobject.h"
#include "userlist.h"

#define VSCP_TCPIP_SRV_RUN  0
#define VSCP_TCPIP_SRV_STOP 1

#define VSCP_TCPIP_COMMAND_LIST_MAX 200 // Max number of saved old commands

#define VSCP_TCP_MAX_CLIENTS 1024

#define MSG_WELCOME       "Welcome to the VSCP daemon.\r\n"
#define MSG_OK            "+OK - Success.\r\n"
#define MSG_GOODBY        "+OK - Connection closed by client.\r\n"
#define MSG_GOODBY2       "+OK - Connection closed.\r\n"
#define MSG_USERNAME_OK   "+OK - User name accepted, password please\r\n"
#define MSG_PASSWORD_OK   "+OK - Ready to work.\r\n"
#define MSG_QUEUE_CLEARED "+OK - All events cleared.\r\n"
#define MSG_RECEIVE_LOOP                                                       \
    "+OK - Receive loop entered. QUITLOOP to terminate.\r\n"
#define MSG_QUIT_LOOP "+OK - Quit receive loop.\r\n"

#define MSG_ERROR           "-OK - Error\r\n"
#define MSG_UNKNOWN_COMMAND "-OK - Unknown command\r\n"
#define MSG_PARAMETER_ERROR "-OK - Invalid parameter or format\r\n"
#define MSG_BUFFER_FULL     "-OK - Buffer Full\r\n"
#define MSG_NO_MSG          "-OK - No event(s) available\r\n"

#define MSG_PASSWORD_ERROR "-OK - Invalid username or password.\r\n"
#define MSG_NOT_ACCREDITED "-OK - Need to log in to perform this command.\r\n"
#define MSG_INVALID_USER   "-OK - Invalid user.\r\n"
#define MSG_NEED_USERNAME                                                      \
    "-OK - Need a Username before a password can be entered.\r\n"

#define MSG_MAX_NUMBER_OF_CLIENTS "-OK - Max number of clients connected.\r\n"
#define MSG_INTERNAL_ERROR        "-OK - Server Internal error.\r\n"
#define MSG_INTERNAL_MEMORY_ERROR "-OK - Internal Memory error.\r\n"
#define MSG_INVALID_REMOTE_ERROR  "-OK - Invalid or unknown peer.\r\n"

#define MSG_LOW_PRIVILEGE_ERROR                                                \
    "-OK - User need higher privilege level to perform this operation.\r\n"
#define MSG_INTERFACE_NOT_FOUND  "-OK - Interface not found.\r\n"
#define MSG_UNABLE_TO_SEND_EVENT "-OK - Unable to send event.\r\n"

#define MSG_VARIABLE_NOT_DEFINED "-OK - Variable is not defined.\r\n"
#define MSG_VARIABLE_MUST_BE_EVENT_TYPE                                        \
    "-OK - Variable must be of event type.\r\n"
#define MSG_VARIABLE_NOT_STOCK                                                 \
    "-OK - Operation does not work with stock variables.\r\n"
#define MSG_VARIABLE_NO_SAVE     "-OK - Variable could not be saved.\r\n"
#define MSG_VARIABLE_NOT_NUMERIC "-OK - Variable is not numeric.\r\n"
#define MSG_VARIABLE_UNABLE_ADD  "-OK - Unable to add variable.\r\n"

#define MSG_NO_TCPIP_ERROR                                                     \
    "-OK - User does not have rights to use tcp/ip interface.\r\n"

#define MSG_NO_RIGHTS_ERROR                                                    \
    "-OK - User does not have rights to perform this operation.\r\n"

#define MSG_INTERFACE_NOT_FOUND "-OK - Interface not found.\r\n"

#define MSG_VARIABLE_NOT_DEFINED "-OK - Variable is not defined.\r\n"
#define MSG_MOT_ALLOWED_TO_SEND_EVENT                                          \
    "-OK - Not allowed to sen this event (contact admin).\r\n"
#define MSG_INVALID_PATH           "-OK - Invalid path.\r\n"
#define MSG_FAILED_TO_GENERATE_SID "-OK - Failed to generate sid.\r\n"

#define MSG_FAILED_TO_CREATE_TABLE                                             \
    "-OK - Failed to create (one or more) table(s).\r\n"
#define MSG_FAILED_TO_ADD_TABLE_TO_DB                                          \
    "-OK - Failed to add table to database.\r\n"
#define MSG_FAILED_TO_INIT_TABLE   "-OK - Failed to initialize table.\r\n"
#define MSG_FAILED_GET_TABLE_NAMES "-OK - Failed to get table names.\r\n"
#define MSG_FAILED_UNKNOWN_TABLE                                               \
    "-OK - No table with that name can be found.\r\n"
#define MSG_FAILED_TABLE_NAME_IN_USE                                           \
    "-OK - This table name is already in use.\r\n"
#define MSG_FAILED_TO_PREPARE_TABLE "-OK - Failed to prepare table search.\r\n"
#define MSG_FAILED_TO_FINALIZE_TABLE                                           \
    "-OK - Failed to finalize table search.\r\n"
#define MSG_FAILED_TO_CLEAR_TABLE  "-OK - Failed to clear table.\r\n"
#define MSG_FAILED_TO_WRITE_TABLE  "-OK - Failed to write data to table.\r\n"
#define MSG_FAILED_TO_REMOVE_TABLE "-OK - Failed to remove table.\r\n"

typedef const char* (*COMMAND_METHOD)(void);

// Forward declarations
class tcpipClientObj;

/*!
    Class that defines one command
*/
typedef struct {
    std::string m_strCmd;    // Command name
    uint8_t m_securityLevel; // Security level for command (0-15)
} structCommand;

// ----------------------------------------------------------------------------

/*!
    @brief This class implements the server code for handling individual TCP/IP
   client connections.
*/

class CTcpipSrv {

  public:
    /// Constructor
    CTcpipSrv(CControlObject* obj = nullptr);

    /// Destructor
    ~CTcpipSrv();

    /*!
     * Write string to client
     * If encryption is activated this routine will encrypt
     * the string before sending it,
     * @param conn Pointer to the client connection.
     * @param str String to write.
     * @param bAddCRLF If true crlf will be added to string
     * @return True on success, false on failure
     */
    bool write(struct mg_connection* conn,
               std::string& str,
               bool bAddCRLF = false);

    /*!
     * Write string to client
     * @param conn Pointer to the client connection.
     * @param buf Pointer to string to write
     * @param len Number of characters to write.
     * @return True on success, false on failure
     */
    bool write(struct mg_connection* conn, const char* buf, size_t len);

    /*!
     * read string (crlf terminated) from input queue
     * If encryption is activated the string will be decrypted
     * before it is returned.
     * @param conn Pointer to the client connection.
     * @param str String that will get read data
     * @return True on success (there is data to read), false on failure
     */
    bool read(struct mg_connection* conn, std::string& str);

    /*!
        When a command is received on the TCP/IP interface the command handler
       is called.

        @param conn Pointer to the client connection.
        @param strCommand The command string to handle.
        @return Result of command handling.
    */
    int commandHandler(struct mg_connection* conn,
                       const std::string& strCommand);

    /*!
        Check if a user has been verified
        @param conn Pointer to the client connection.
        @return true if verified, else false.
    */
    bool isVerified(struct mg_connection* conn);

    /*!
        Check if a user has enough privilege
        @param conn Pointer to the client connection.
        @param reqiredPrivilege Privileges required to do operation.
        @return true if yes, else false.
    */
    bool checkPrivilege(struct mg_connection* conn,
                        unsigned long reqiredPrivilege);

    /*!
        Client send event

        @param conn Pointer to the client connection.
        @return void.

        @note This function handles sending an event from the client to the
       server.
    */
    void handleClientSend(struct mg_connection* conn);

    /*!
        Client receive

        @param conn Pointer to the client connection.
        @return void.

        @note This function handles receiving an event from the server to the
       client.
    */
    void handleClientReceive(struct mg_connection* conn);

    /*!
        sendOneEventFromQueue
        @param 	bStatusMsg True if response messages (+OK/-OK) should be sent.
       Default.
        @return True on success/false on failure.
    */
    bool sendOneEventFromQueue(struct mg_connection* conn,
                               bool bStatusMsg = true);

    /*!
        Client DataAvailable
    */
    void handleClientDataAvailable(struct mg_connection* conn);

    /*!
        Client Clear Input queue
    */
    void handleClientClearInputQueue(struct mg_connection* conn);

    /*!
        Client Get statistics
    */
    void handleClientGetStatistics(struct mg_connection* conn);

    /*!
        Client get status
    */
    void handleClientGetStatus(struct mg_connection* conn);

    /*!
        Client get channel GUID
    */
    void handleClientGetChannelGUID(struct mg_connection* conn);

    /*!
        Client set channel ID
    */
    void handleClientSetChannelGUID(struct mg_connection* conn);

    /*!
        Client get version
    */
    void handleClientGetVersion(struct mg_connection* conn);

    /*!
        Client set filter
    */
    void handleClientSetFilter(struct mg_connection* conn);

    /*!
        Client set mask
    */
    void handleClientSetMask(struct mg_connection* conn);

    /*!
        Client issue user
    */
    void handleClientUser(struct mg_connection* conn);

    /*!
    Client issue password
    */
    bool handleClientPassword(struct mg_connection* conn);

    /*!
     Handle challenge
     */
    void handleChallenge(struct mg_connection* conn);

    /*!
        Client Get channel ID
    */
    void handleClientGetChannelID(struct mg_connection* conn);

    /*!
        Handle RcvLoop
    */
    void handleClientRcvLoop(struct mg_connection* conn);

    /*!
          Client Help
      */
    void handleClientHelp(struct mg_connection* conn);

    /*!
          Client Test
      */
    void handleClientTest(struct mg_connection* conn);

    /*!
          Client Restart
      */
    void handleClientRestart(struct mg_connection* conn);

    /*!
        Client Shutdown
    */
    void handleClientShutdown(struct mg_connection* conn);

    /*!
        Client REMOTE command
    */
    void handleClientRemote(struct mg_connection* conn);

    /*!
        Client CLIENT/INTERFACE command
    */
    void handleClientInterface(struct mg_connection* conn);

    /*!
        Client INTERFACE LIST command
    */
    void handleClientInterface_List(struct mg_connection* conn);

    /*!
        Client INTERFACE UNIQUE command
    */
    void handleClientInterface_Unique(struct mg_connection* conn);

    /*!
        Client INTERFACE NORMAL command
    */
    void handleClientInterface_Normal(struct mg_connection* conn);

    /*!
        Client INTERFACE CLOSE command
    */
    void handleClientInterface_Close(struct mg_connection* conn);

    /*!
        Client WhatCanYouDo command
    */
    void handleClientCapabilityRequest(struct mg_connection* conn);

    /*!
     * Handle client measurement

       @param conn Pointer to the client connection.
     */
    void handleClientMeasurement(struct mg_connection* conn);

    /*!
        Stop the TCP/IP server.

        This function sets the run flag to false, signaling the server to stop
        its operations. It should be called when the server needs to be
        gracefully terminated.

        All worker threads will be terminated to ensure a clean shutdown.
    */
    void stopServer(void) { m_bRun = false; };

    /*!
        Check if the server is no longer running.

        @return true if the server has been stopped, false otherwise.
    */
    bool isWorking(void) { return m_bRun; };

    /*!
        Get the current command for the client connection.

        @return The current command string.
    */
    std::string& getCurrentCommand() { return m_currentCommand; };

    /*!
        Set the current command for the client connection.

        @param cmd The command string to set as the current command.
    */
    void setCurrentCommand(const std::string& cmd)
    {
        m_currentCommand = cmd;
        vscp_trim(m_currentCommand);
    };

    /*!
        Get the last command processed for the client connection.

        @return The last command string.
    */
    std::string& getLastCommand() { return m_lastCommand; };

    /*!
        Set the last command processed for the client connection.

        @param cmd The command string to set as the last command.
    */
    void setLastCommand(const std::string& cmd) { m_lastCommand = cmd; };

    /*!
        Check if the current command starts with the specified prefix.

        @param cmd The command prefix to check.
        @param bFix If true, remove the prefix from the current command.
        @return true if the current command starts with the specified prefix,
       false otherwise.
    */
    bool commandStartsWith(const std::string& cmd, bool bFix = false);

    // ----------------------------------------------------------------------------

    /// Getters/setters

    /*!
        Get the interface address for the TCP/IP connection.
        @return The address of the interface.
    */
    std::string getInterfaceAddress() const { return m_interfaceAddress; }

    /*!
        Set interface address
        Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
        Examples for IPv6: [::]:80, [::1]:80
    */
    void setInterfaceAddress(const std::string& str)
    {
        m_interfaceAddress = str;
    };

    /*!
        Get the TLS options for the TCP/IP server instance.

        @return Reference to the TLS options structure.
    */
    mg_tls_opts& getTlsOpts() { return m_tcpip_tls_opts; }

    /*!
        Getter/setter for control object
    */
    void setControlObjectPointer(CControlObject* pobj) { m_pCtrlObj = pobj; };
    CControlObject* getControlObject(void) { return m_pCtrlObj; };

    /*!

  private:
    // --- Member variables ---

    /*!
        @brief Control object for the TCP/IP server instance.
        This object provides access to the core control functionalities required
       by the TCP/IP server instance. The control object holds configurations
       and state information necessary for the TCP/IP server to operate
       correctly. It should be properly initialized before the TCP/IP server
       starts handling client connections.
    */
    CControlObject* m_pCtrlObj;

    /// @brief Run baby run flag
    bool m_bRun;

    /*!
        Interface used for TCP/IP connection  (only one)
        Examples for IPv4: 80, 127.0.0.1:9598,
            192.0.2.3:9598,
            tcp://192.0.2.3:9599,
            ssl://192.0.2.3:9598.
            tls://192.0.2.3:9598
        Examples for IPv6: [::]:9598,
            [::1]:9598,
            tcp://[::1]:9598,
            tcp://[::1]:9598,
            ssl://[::1]:9598,
            tls://[::1]:9598
    */
    std::string m_interfaceAddress;

    /*!
        tcp/ip SSL settings

        ca - Certificate Authority, an mg_str. Used to verify the certificate
       that the other end sends to us. If NULL, then server authentication for
       clients and client authentication for servers are disabled.
       If ca is set but cert is NULL, then only server authentication is
       performed.

       cert - Our own
        certificate; an mg_str. If NULL, then we don't authenticate ourselves to
       the other peer.


       key - Our own private key; an mg_str. Sometimes, a
       certificate and its key are bundled in a single PEM file, in which case
       the values for cert and key could be the same

       name - Server name; an
       mg_str. If not empty, enable server name verification.

        NOTE: if both ca and cert are set, then two-way (mutual) TLS
       authentication is enabled, both sides authenticate each other. Usually,
       for one-way (server) TLS authentication, server connections set both key
       and cert, whilst clients only ca and/or possibly name.
    */
    mg_tls_opts m_tcpip_tls_opts;

    // All input is added to the receive buf. as it is
    // received. Commands are then fetched from this buffer
    // as we go
    // std::string m_strResponse;

    // Saved return value for last sockettcp operation
    size_t m_rv;

    // Flag for receive loop active
    bool m_bReceiveLoop;

    /*!
        The current command being processed for the client connection.
    */
    std::string m_currentCommand;

    /*!
        The last command processed for the client connection.
    */
    std::string m_lastCommand;

    // /*!
    //     @brief Map of client items indexed by their unique ID.
    //     This map allows quick lookup of client items based on their unique
    //     identifier.
    // */
    // std::map<unsigned long, CClientItem*> m_clientMapById;

    // *************************************************************************

    // TCP/IP client thread
    pthread_t m_tcpipClientThread;
};

#endif
