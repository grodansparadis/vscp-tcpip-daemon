// unittest.cpp
//
// Unit tests for vscpClientWs1
//
// These tests exercise the vscpClientWs1 class without requiring
// actual websocket communication. Constructor defaults, JSON config
// stubs, getters/setters, receive queue, getcount, clear, timeouts,
// callbacks, and encrypt_password are all tested locally.
//

#include <gtest/gtest.h>

#include <semaphore.h>
#include <vscp-client-ws1.h>
#include <vscphelper.h>

#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
//                       Constructor / Default State
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ConstructorDefaults)
{
  vscpClientWs1 client;
  EXPECT_EQ(CVscpClient::connType::WS1, client.getType());
  EXPECT_FALSE(client.isConnected());
  EXPECT_FALSE(client.m_bConnected);
  EXPECT_EQ(nullptr, client.m_conn);
}

TEST(VscpClientWs1, ConstructorNotConnected)
{
  vscpClientWs1 client;
  EXPECT_FALSE(client.isConnected());
}

TEST(VscpClientWs1, EventReceiveQueueInitiallyEmpty)
{
  vscpClientWs1 client;
  EXPECT_TRUE(client.m_eventReceiveQueue.empty());
}

TEST(VscpClientWs1, MsgReceiveQueueInitiallyEmpty)
{
  vscpClientWs1 client;
  EXPECT_TRUE(client.m_msgReceiveQueue.empty());
}

// ---------------------------------------------------------------------------
//                      Connection / Response timeout
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, DefaultConnectionTimeout)
{
  vscpClientWs1 client;
  EXPECT_EQ(WS1_CONNECTION_TIMEOUT, client.getConnectionTimeout());
}

TEST(VscpClientWs1, DefaultResponseTimeout)
{
  vscpClientWs1 client;
  EXPECT_EQ(WS1_RESPONSE_TIMEOUT, client.getResponseTimeout());
}

TEST(VscpClientWs1, SetConnectionTimeout)
{
  vscpClientWs1 client;
  client.setConnectionTimeout(5000);
  EXPECT_EQ(5000u, client.getConnectionTimeout());
}

TEST(VscpClientWs1, SetResponseTimeout)
{
  vscpClientWs1 client;
  client.setResponseTimeout(1000);
  EXPECT_EQ(1000u, client.getResponseTimeout());
}

TEST(VscpClientWs1, TimeoutConstants)
{
  EXPECT_EQ(30000u, WS1_CONNECTION_TIMEOUT);
  EXPECT_EQ(2000u, WS1_RESPONSE_TIMEOUT);
}

// ---------------------------------------------------------------------------
//                         ConnType / Name
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ConnTypeIsWs1)
{
  vscpClientWs1 client;
  EXPECT_EQ(CVscpClient::connType::WS1, client.getType());
}

TEST(VscpClientWs1, SetGetName)
{
  vscpClientWs1 client;
  client.setName("test-ws1");
  EXPECT_EQ("test-ws1", client.getName());
}

TEST(VscpClientWs1, FullLevel2Flag)
{
  vscpClientWs1 client;
  EXPECT_FALSE(client.isFullLevel2());
  client.setFullLevel2(true);
  EXPECT_TRUE(client.isFullLevel2());
}

// ---------------------------------------------------------------------------
//                       getcount / clear
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, GetcountEmpty)
{
  vscpClientWs1 client;
  uint16_t count = 0xFFFF;
  int rv         = client.getcount(&count);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(0u, count);
}

TEST(VscpClientWs1, GetcountNullPointer)
{
  vscpClientWs1 client;
  int rv = client.getcount(nullptr);
  EXPECT_EQ(VSCP_ERROR_INVALID_POINTER, rv);
}

TEST(VscpClientWs1, ClearEmptyQueue)
{
  vscpClientWs1 client;
  int rv = client.clear();
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
}

// ---------------------------------------------------------------------------
//                    Receive when not connected
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ReceiveEventNotConnected)
{
  vscpClientWs1 client;
  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  int rv = client.receive(ev);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, ReceiveEventExNotConnected)
{
  vscpClientWs1 client;
  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  int rv = client.receive(ex);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, ReceiveCanalMsgNotConnected)
{
  vscpClientWs1 client;
  canalMsg msg;
  memset(&msg, 0, sizeof(msg));
  int rv = client.receive(msg);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

// ---------------------------------------------------------------------------
//             Receive when connected but queue empty
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ReceiveEventEmptyQueue)
{
  vscpClientWs1 client;
  client.m_bConnected = true;
  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  int rv = client.receive(ev);
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, rv);
}

TEST(VscpClientWs1, ReceiveEventExEmptyQueue)
{
  vscpClientWs1 client;
  client.m_bConnected = true;
  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  int rv = client.receive(ex);
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, rv);
}

TEST(VscpClientWs1, ReceiveCanalMsgEmptyQueue)
{
  vscpClientWs1 client;
  client.m_bConnected = true;
  canalMsg msg;
  memset(&msg, 0, sizeof(msg));
  int rv = client.receive(msg);
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, rv);
}

// ---------------------------------------------------------------------------
//            Receive blocking (just calls receive, no sem wait)
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ReceiveBlockingNotConnected)
{
  vscpClientWs1 client;
  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  int rv = client.receiveBlocking(ev, 10);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, ReceiveBlockingExNotConnected)
{
  vscpClientWs1 client;
  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  int rv = client.receiveBlocking(ex, 10);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, ReceiveBlockingCanalNotConnected)
{
  vscpClientWs1 client;
  canalMsg msg;
  memset(&msg, 0, sizeof(msg));
  int rv = client.receiveBlocking(msg, 10);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

// ---------------------------------------------------------------------------
//                    Send when not connected
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, SendEventNotConnected)
{
  vscpClientWs1 client;
  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  ev.vscp_class = VSCP_CLASS1_MEASUREMENT;
  ev.vscp_type  = 6;
  ev.sizeData   = 0;
  ev.pdata      = nullptr;
  int rv        = client.send(ev);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, SendEventExNotConnected)
{
  vscpClientWs1 client;
  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  ex.vscp_class = VSCP_CLASS1_MEASUREMENT;
  ex.vscp_type  = 6;
  ex.sizeData   = 0;
  int rv        = client.send(ex);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

// ---------------------------------------------------------------------------
//          setfilter / getversion / getinterfaces / getwcyd
//          require connection - verify NOT_CONNECTED returns
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, SetFilterNotConnected)
{
  vscpClientWs1 client;
  vscpEventFilter filter;
  memset(&filter, 0, sizeof(filter));
  int rv = client.setfilter(filter);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, GetVersionNotConnected)
{
  vscpClientWs1 client;
  uint8_t major, minor, release, build;
  int rv = client.getversion(&major, &minor, &release, &build);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, GetInterfacesNotConnected)
{
  vscpClientWs1 client;
  std::deque<std::string> iflist;
  int rv = client.getinterfaces(iflist);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

TEST(VscpClientWs1, GetWcydNotConnected)
{
  vscpClientWs1 client;
  uint64_t wcyd = 0;
  int rv        = client.getwcyd(wcyd);
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, rv);
}

// ---------------------------------------------------------------------------
//                        disconnect
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, DisconnectSetsConnNull)
{
  vscpClientWs1 client;
  int rv = client.disconnect();
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(nullptr, client.m_conn);
}

// ---------------------------------------------------------------------------
//                        getConfigAsJson / initFromJson stubs
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, GetConfigAsJsonReturnsEmpty)
{
  vscpClientWs1 client;
  std::string config = client.getConfigAsJson();
  EXPECT_TRUE(config.empty());
}

TEST(VscpClientWs1, InitFromJsonAlwaysTrue)
{
  vscpClientWs1 client;
  EXPECT_TRUE(client.initFromJson("{}"));
  EXPECT_TRUE(client.initFromJson("{\"host\":\"example.com\"}"));
  EXPECT_TRUE(client.initFromJson("any string"));
}

// ---------------------------------------------------------------------------
//                           init
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, InitSetsHostAndPort)
{
  vscpClientWs1 client;
  uint8_t key[32] = { 0 };
  int rv           = client.init("192.168.1.1", 443, true, "admin", "secret", key, 10000, 3000);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(10000u, client.getConnectionTimeout());
  EXPECT_EQ(3000u, client.getResponseTimeout());
}

TEST(VscpClientWs1, InitWithDefaultTimeouts)
{
  vscpClientWs1 client;
  uint8_t key[32] = { 0 };
  int rv           = client.init("localhost", 8884, false, "user", "pass", key);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(WS1_CONNECTION_TIMEOUT, client.getConnectionTimeout());
  EXPECT_EQ(WS1_RESPONSE_TIMEOUT, client.getResponseTimeout());
}

// ---------------------------------------------------------------------------
//                          Callbacks
// ---------------------------------------------------------------------------

static bool g_evCallbackFired = false;
static bool g_exCallbackFired = false;

static void
testCallbackEv(vscpEvent & /*ev*/, void * /*pobj*/)
{
  g_evCallbackFired = true;
}

static void
testCallbackEx(vscpEventEx & /*ex*/, void * /*pobj*/)
{
  g_exCallbackFired = true;
}

TEST(VscpClientWs1, SetCallbackEv)
{
  vscpClientWs1 client;
  g_evCallbackFired = false;
  int rv            = client.setCallbackEv(testCallbackEv, nullptr);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
}

TEST(VscpClientWs1, SetCallbackEx)
{
  vscpClientWs1 client;
  g_exCallbackFired = false;
  int rv            = client.setCallbackEx(testCallbackEx, nullptr);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
}

// ---------------------------------------------------------------------------
//       Receive returns NOT_SUPPORTED when callback is active
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ReceiveNotSupportedWithEvCallback)
{
  vscpClientWs1 client;
  client.m_bConnected = true;
  client.setCallbackEv(testCallbackEv, nullptr);

  // Put an event in the queue so we get past the empty check
  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->pdata = nullptr;
  client.m_eventReceiveQueue.push_back(pev);

  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  int rv = client.receive(ev);
  EXPECT_EQ(VSCP_ERROR_NOT_SUPPORTED, rv);

  // Clean up the event we added
  client.clear();
}

TEST(VscpClientWs1, ReceiveNotSupportedWithExCallback)
{
  vscpClientWs1 client;
  client.m_bConnected = true;
  client.setCallbackEx(testCallbackEx, nullptr);

  // Put an event in the queue so we get past the empty check
  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->pdata = nullptr;
  client.m_eventReceiveQueue.push_back(pev);

  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  int rv = client.receive(ex);
  EXPECT_EQ(VSCP_ERROR_NOT_SUPPORTED, rv);

  // Clean up
  client.clear();
}

// ---------------------------------------------------------------------------
//              Receive with event in queue (connected, no callback)
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, ReceiveEventFromQueue)
{
  vscpClientWs1 client;
  client.m_bConnected = true;

  // Create and enqueue an event
  vscpEvent *pev    = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->vscp_class = VSCP_CLASS1_MEASUREMENT;
  pev->vscp_type  = 6;
  pev->sizeData   = 0;
  pev->pdata      = nullptr;
  client.m_eventReceiveQueue.push_back(pev);

  vscpEvent ev;
  memset(&ev, 0, sizeof(ev));
  int rv = client.receive(ev);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(VSCP_CLASS1_MEASUREMENT, ev.vscp_class);
  EXPECT_EQ(6, ev.vscp_type);
  EXPECT_TRUE(client.m_eventReceiveQueue.empty());
}

TEST(VscpClientWs1, ReceiveEventExFromQueue)
{
  vscpClientWs1 client;
  client.m_bConnected = true;

  vscpEvent *pev    = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->vscp_class = VSCP_CLASS1_MEASUREMENT;
  pev->vscp_type  = 6;
  pev->sizeData   = 0;
  pev->pdata      = nullptr;
  client.m_eventReceiveQueue.push_back(pev);

  vscpEventEx ex;
  memset(&ex, 0, sizeof(ex));
  int rv = client.receive(ex);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(VSCP_CLASS1_MEASUREMENT, ex.vscp_class);
  EXPECT_EQ(6, ex.vscp_type);
  EXPECT_TRUE(client.m_eventReceiveQueue.empty());
}

TEST(VscpClientWs1, GetcountWithEvents)
{
  vscpClientWs1 client;

  // Add two events
  for (int i = 0; i < 2; i++) {
    vscpEvent *pev = new vscpEvent;
    memset(pev, 0, sizeof(vscpEvent));
    pev->pdata = nullptr;
    client.m_eventReceiveQueue.push_back(pev);
  }

  uint16_t count = 0;
  int rv         = client.getcount(&count);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_EQ(2u, count);

  // Clean up
  client.clear();
}

TEST(VscpClientWs1, ClearWithEvents)
{
  vscpClientWs1 client;

  for (int i = 0; i < 3; i++) {
    vscpEvent *pev = new vscpEvent;
    memset(pev, 0, sizeof(vscpEvent));
    pev->pdata = nullptr;
    client.m_eventReceiveQueue.push_back(pev);
  }

  EXPECT_EQ(3u, client.m_eventReceiveQueue.size());
  int rv = client.clear();
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_TRUE(client.m_eventReceiveQueue.empty());
}

// ---------------------------------------------------------------------------
//                      encrypt_password
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, EncryptPasswordProducesOutput)
{
  vscpClientWs1 client;
  uint8_t key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                       0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                       0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
  uint8_t iv[16]  = { 0 };
  std::string result;

  int rv = client.encrypt_password(result, "admin", "secret", key, iv);
  EXPECT_EQ(VSCP_ERROR_SUCCESS, rv);
  EXPECT_FALSE(result.empty());
  // Output is hex string of 16 bytes = 32 hex chars
  EXPECT_EQ(32u, result.size());
}

TEST(VscpClientWs1, EncryptPasswordDeterministic)
{
  vscpClientWs1 client;
  uint8_t key[32] = { 0 };
  uint8_t iv1[16] = { 0 };
  uint8_t iv2[16] = { 0 };
  std::string result1, result2;

  // Use input that is exactly 16 bytes ("admin" + ":" + "0123456789") = 16
  // to avoid AES reading uninitialized memory beyond the string buffer
  client.encrypt_password(result1, "admin", "0123456789", key, iv1);
  client.encrypt_password(result2, "admin", "0123456789", key, iv2);
  EXPECT_EQ(result1, result2);
}

TEST(VscpClientWs1, EncryptPasswordDifferentInputDifferentOutput)
{
  vscpClientWs1 client;
  uint8_t key[32] = { 0 };
  uint8_t iv[16]  = { 0 };
  std::string result1, result2;

  client.encrypt_password(result1, "admin", "password1", key, iv);
  client.encrypt_password(result2, "admin", "password2", key, iv);
  EXPECT_NE(result1, result2);
}

// ---------------------------------------------------------------------------
//                      waitForResponse (timeout)
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, WaitForResponseTimeout)
{
  vscpClientWs1 client;
  // No semaphore posted, should timeout
  int rv = client.waitForResponse(100);
  EXPECT_EQ(VSCP_ERROR_TIMEOUT, rv);
}

// ---------------------------------------------------------------------------
//                      Message receive queue
// ---------------------------------------------------------------------------

TEST(VscpClientWs1, MsgReceiveQueueOps)
{
  vscpClientWs1 client;
  client.m_msgReceiveQueue.push_back("test message 1");
  client.m_msgReceiveQueue.push_back("test message 2");
  EXPECT_EQ(2u, client.m_msgReceiveQueue.size());

  std::string front = client.m_msgReceiveQueue.front();
  client.m_msgReceiveQueue.pop_front();
  EXPECT_EQ("test message 1", front);
  EXPECT_EQ(1u, client.m_msgReceiveQueue.size());
}
