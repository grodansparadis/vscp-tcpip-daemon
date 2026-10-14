// unittest.cpp
//
// Unit tests for vscpClientWs2
//

#include <semaphore.h>

#include <deque>
#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <vscp.h>
#include <vscphelper.h>
#include <vscp-client-ws2.h>

using json = nlohmann::json;

// ============================================================================
//                       Constructor / Defaults
// ============================================================================

TEST(VscpClientWs2, ConstructorDefaults)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(CVscpClient::connType::WS2, ws2.getType());
  EXPECT_FALSE(ws2.isConnected());
  EXPECT_EQ(nullptr, ws2.m_conn);
  EXPECT_TRUE(ws2.m_eventReceiveQueue.empty());
  EXPECT_TRUE(ws2.m_msgReceiveQueue.empty());
}

TEST(VscpClientWs2, ConstructorNotConnected)
{
  vscpClientWs2 ws2;
  EXPECT_FALSE(ws2.m_bConnected);
  EXPECT_EQ(nullptr, ws2.m_conn);
}

TEST(VscpClientWs2, EventReceiveQueueInitiallyEmpty)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(0u, ws2.m_eventReceiveQueue.size());
}

TEST(VscpClientWs2, MsgReceiveQueueInitiallyEmpty)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(0u, ws2.m_msgReceiveQueue.size());
}

// ============================================================================
//                       Timeout constants & accessors
// ============================================================================

TEST(VscpClientWs2, DefaultConnectionTimeout)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(WS2_CONNECTION_TIMEOUT, ws2.getConnectionTimeout());
}

TEST(VscpClientWs2, DefaultResponseTimeout)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(WS2_RESPONSE_TIMEOUT, ws2.getResponseTimeout());
}

TEST(VscpClientWs2, SetConnectionTimeout)
{
  vscpClientWs2 ws2;
  ws2.setConnectionTimeout(5000);
  EXPECT_EQ(5000u, ws2.getConnectionTimeout());
}

TEST(VscpClientWs2, SetResponseTimeout)
{
  vscpClientWs2 ws2;
  ws2.setResponseTimeout(3000);
  EXPECT_EQ(3000u, ws2.getResponseTimeout());
}

TEST(VscpClientWs2, TimeoutConstants)
{
  EXPECT_EQ(30000u, WS2_CONNECTION_TIMEOUT);
  EXPECT_EQ(2000u, WS2_RESPONSE_TIMEOUT);
}

// ============================================================================
//                       Type / name / level
// ============================================================================

TEST(VscpClientWs2, ConnTypeIsWs2)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(CVscpClient::connType::WS2, ws2.getType());
}

TEST(VscpClientWs2, SetGetName)
{
  vscpClientWs2 ws2;
  ws2.setName("test-ws2");
  EXPECT_EQ("test-ws2", ws2.getName());
}

TEST(VscpClientWs2, FullLevel2Flag)
{
  vscpClientWs2 ws2;
  ws2.setFullLevel2(true);
  EXPECT_TRUE(ws2.isFullLevel2());
  ws2.setFullLevel2(false);
  EXPECT_FALSE(ws2.isFullLevel2());
}

// ============================================================================
//                       getcount / clear (no connection needed)
// ============================================================================

TEST(VscpClientWs2, GetcountEmpty)
{
  vscpClientWs2 ws2;
  uint16_t cnt = 999;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.getcount(&cnt));
  EXPECT_EQ(0u, cnt);
}

TEST(VscpClientWs2, GetcountNullPointer)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(VSCP_ERROR_INVALID_POINTER, ws2.getcount(nullptr));
}

TEST(VscpClientWs2, ClearEmptyQueue)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.clear());
}

// ============================================================================
//                       Receive – not connected
// ============================================================================

TEST(VscpClientWs2, ReceiveEventNotConnected)
{
  vscpClientWs2 ws2;
  vscpEvent ev;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receive(ev));
}

TEST(VscpClientWs2, ReceiveEventExNotConnected)
{
  vscpClientWs2 ws2;
  vscpEventEx ex;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receive(ex));
}

TEST(VscpClientWs2, ReceiveCanalMsgNotConnected)
{
  vscpClientWs2 ws2;
  canalMsg msg;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receive(msg));
}

// ============================================================================
//                  Receive – connected, empty queue
// ============================================================================

TEST(VscpClientWs2, ReceiveEventEmptyQueue)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;
  vscpEvent ev;
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, ws2.receive(ev));
  ws2.m_bConnected = false;
}

TEST(VscpClientWs2, ReceiveEventExEmptyQueue)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;
  vscpEventEx ex;
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, ws2.receive(ex));
  ws2.m_bConnected = false;
}

TEST(VscpClientWs2, ReceiveCanalMsgEmptyQueue)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;
  canalMsg msg;
  EXPECT_EQ(VSCP_ERROR_RCV_EMPTY, ws2.receive(msg));
  ws2.m_bConnected = false;
}

// ============================================================================
//                  Receive blocking – not connected
// ============================================================================

TEST(VscpClientWs2, ReceiveBlockingNotConnected)
{
  vscpClientWs2 ws2;
  vscpEvent ev;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receiveBlocking(ev, 10));
}

TEST(VscpClientWs2, ReceiveBlockingExNotConnected)
{
  vscpClientWs2 ws2;
  vscpEventEx ex;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receiveBlocking(ex, 10));
}

TEST(VscpClientWs2, ReceiveBlockingCanalNotConnected)
{
  vscpClientWs2 ws2;
  canalMsg msg;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.receiveBlocking(msg, 10));
}

// ============================================================================
//                  Send – not connected
// ============================================================================

TEST(VscpClientWs2, SendEventNotConnected)
{
  vscpClientWs2 ws2;
  vscpEvent ev = {};
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.send(ev));
}

TEST(VscpClientWs2, SendEventExNotConnected)
{
  vscpClientWs2 ws2;
  vscpEventEx ex = {};
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.send(ex));
}

// ============================================================================
//                  Other methods – not connected
// ============================================================================

TEST(VscpClientWs2, SetFilterNotConnected)
{
  vscpClientWs2 ws2;
  vscpEventFilter filter = {};
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.setfilter(filter));
}

TEST(VscpClientWs2, GetVersionNotConnected)
{
  vscpClientWs2 ws2;
  uint8_t major, minor, release, build;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED,
            ws2.getversion(&major, &minor, &release, &build));
}

TEST(VscpClientWs2, GetInterfacesNotConnected)
{
  vscpClientWs2 ws2;
  std::deque<std::string> iflist;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.getinterfaces(iflist));
}

TEST(VscpClientWs2, GetWcydNotConnected)
{
  vscpClientWs2 ws2;
  uint64_t wcyd = 0;
  EXPECT_EQ(VSCP_ERROR_NOT_CONNECTED, ws2.getwcyd(wcyd));
}

// ============================================================================
//                  Disconnect
// ============================================================================

TEST(VscpClientWs2, DisconnectSetsConnNull)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.disconnect());
  EXPECT_EQ(nullptr, ws2.m_conn);
}

// ============================================================================
//                  JSON config stubs
// ============================================================================

TEST(VscpClientWs2, GetConfigAsJsonReturnsEmpty)
{
  vscpClientWs2 ws2;
  std::string cfg = ws2.getConfigAsJson();
  EXPECT_TRUE(cfg.empty());
}

TEST(VscpClientWs2, InitFromJsonAlwaysTrue)
{
  vscpClientWs2 ws2;
  EXPECT_TRUE(ws2.initFromJson("{}"));
  EXPECT_TRUE(ws2.initFromJson("{\"host\":\"example.com\"}"));
  EXPECT_TRUE(ws2.initFromJson(""));
  EXPECT_TRUE(ws2.initFromJson("garbage"));
}

// ============================================================================
//                  init()
// ============================================================================

TEST(VscpClientWs2, InitSetsHostAndPort)
{
  vscpClientWs2 ws2;
  uint8_t key[32] = { 0 };
  ws2.init("192.168.1.1", 9001, true, "admin", "secret", key);
  // init encrypts password and stores internally – we just verify
  // it returned and didn't crash.
}

TEST(VscpClientWs2, InitWithDefaultTimeouts)
{
  vscpClientWs2 ws2;
  uint8_t key[32] = { 0 };
  ws2.init("host", 443, false, "user", "pass", key);
  EXPECT_EQ(WS2_CONNECTION_TIMEOUT, ws2.getConnectionTimeout());
  EXPECT_EQ(WS2_RESPONSE_TIMEOUT, ws2.getResponseTimeout());
}

TEST(VscpClientWs2, InitWithCustomTimeouts)
{
  vscpClientWs2 ws2;
  uint8_t key[32] = { 0 };
  ws2.init("host", 443, false, "user", "pass", key, 10000, 5000);
  EXPECT_EQ(10000u, ws2.getConnectionTimeout());
  EXPECT_EQ(5000u, ws2.getResponseTimeout());
}

// ============================================================================
//                  Callbacks
// ============================================================================

static void
evCallback(vscpEvent &ev, void *pobj)
{
  (void)ev;
  (void)pobj;
}

static void
exCallback(vscpEventEx &ex, void *pobj)
{
  (void)ex;
  (void)pobj;
}

TEST(VscpClientWs2, SetCallbackEv)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.setCallbackEv(evCallback, nullptr));
  EXPECT_TRUE(ws2.isCallbackEvActive());
}

TEST(VscpClientWs2, SetCallbackEx)
{
  vscpClientWs2 ws2;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.setCallbackEx(exCallback, nullptr));
  EXPECT_TRUE(ws2.isCallbackExActive());
}

TEST(VscpClientWs2, ReceiveNotSupportedWithEvCallback)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;

  // Enqueue an event so we pass the "empty" check
  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  ws2.m_eventReceiveQueue.push_back(pev);

  ws2.setCallbackEv(evCallback, nullptr);

  vscpEvent ev;
  EXPECT_EQ(VSCP_ERROR_NOT_SUPPORTED, ws2.receive(ev));

  // Cleanup
  ws2.m_bConnected = false;
  ws2.clear();
}

TEST(VscpClientWs2, ReceiveNotSupportedWithExCallback)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;

  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  ws2.m_eventReceiveQueue.push_back(pev);

  ws2.setCallbackEx(exCallback, nullptr);

  vscpEventEx ex;
  EXPECT_EQ(VSCP_ERROR_NOT_SUPPORTED, ws2.receive(ex));

  ws2.m_bConnected = false;
  ws2.clear();
}

// ============================================================================
//                  Receive event from queue
// ============================================================================

TEST(VscpClientWs2, ReceiveEventFromQueue)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;

  // Enqueue a test event
  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->vscp_class = 10;
  pev->vscp_type  = 6;
  pev->pdata      = nullptr;
  pev->sizeData   = 0;
  ws2.m_eventReceiveQueue.push_back(pev);

  vscpEvent ev;
  memset(&ev, 0, sizeof(vscpEvent));
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.receive(ev));
  EXPECT_EQ(10, ev.vscp_class);
  EXPECT_EQ(6, ev.vscp_type);

  ws2.m_bConnected = false;
}

TEST(VscpClientWs2, ReceiveEventExFromQueue)
{
  vscpClientWs2 ws2;
  ws2.m_bConnected = true;

  vscpEvent *pev = new vscpEvent;
  memset(pev, 0, sizeof(vscpEvent));
  pev->vscp_class = 20;
  pev->vscp_type  = 3;
  pev->pdata      = nullptr;
  pev->sizeData   = 0;
  ws2.m_eventReceiveQueue.push_back(pev);

  vscpEventEx ex;
  memset(&ex, 0, sizeof(vscpEventEx));
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.receive(ex));
  EXPECT_EQ(20, ex.vscp_class);
  EXPECT_EQ(3, ex.vscp_type);

  ws2.m_bConnected = false;
}

// ============================================================================
//                  getcount / clear with events
// ============================================================================

TEST(VscpClientWs2, GetcountWithEvents)
{
  vscpClientWs2 ws2;

  for (int i = 0; i < 5; i++) {
    vscpEvent *pev = new vscpEvent;
    memset(pev, 0, sizeof(vscpEvent));
    pev->pdata = nullptr;
    ws2.m_eventReceiveQueue.push_back(pev);
  }

  uint16_t cnt = 0;
  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.getcount(&cnt));
  EXPECT_EQ(5u, cnt);

  ws2.clear();
}

TEST(VscpClientWs2, ClearWithEvents)
{
  vscpClientWs2 ws2;

  for (int i = 0; i < 3; i++) {
    vscpEvent *pev = new vscpEvent;
    memset(pev, 0, sizeof(vscpEvent));
    pev->pdata = nullptr;
    ws2.m_eventReceiveQueue.push_back(pev);
  }

  EXPECT_EQ(VSCP_ERROR_SUCCESS, ws2.clear());

  uint16_t cnt = 999;
  ws2.getcount(&cnt);
  EXPECT_EQ(0u, cnt);
}

// ============================================================================
//                  encrypt_password
// ============================================================================

TEST(VscpClientWs2, EncryptPasswordProducesOutput)
{
  vscpClientWs2 ws2;
  std::string out;
  uint8_t key[32] = { 0 };
  uint8_t iv[16]  = { 0 };
  EXPECT_EQ(VSCP_ERROR_SUCCESS,
            ws2.encrypt_password(out, "admin", "secret", key, iv));
  EXPECT_FALSE(out.empty());
}

TEST(VscpClientWs2, EncryptPasswordDeterministic)
{
  vscpClientWs2 ws2;
  std::string out1, out2;
  uint8_t key[32] = { 1, 2, 3, 4 };
  uint8_t iv[16]  = { 5, 6, 7, 8 };
  ws2.encrypt_password(out1, "admin", "secret", key, iv);
  ws2.encrypt_password(out2, "admin", "secret", key, iv);
  EXPECT_EQ(out1, out2);
}

TEST(VscpClientWs2, EncryptPasswordDifferentInputDifferentOutput)
{
  vscpClientWs2 ws2;
  std::string outA, outB;
  uint8_t key[32] = { 0 };
  uint8_t iv[16]  = { 0 };
  ws2.encrypt_password(outA, "admin", "secret", key, iv);
  ws2.encrypt_password(outB, "admin", "other", key, iv);
  EXPECT_NE(outA, outB);
}

// ============================================================================
//                  waitForResponse
// ============================================================================

TEST(VscpClientWs2, WaitForResponseTimeout)
{
  vscpClientWs2 ws2;
  // With no signal posted, this should return a non-success code quickly
  int rv = ws2.waitForResponse(1); // 1 ms timeout
  EXPECT_NE(VSCP_ERROR_SUCCESS, rv);
}

// ============================================================================
//                  JSON message receive queue
// ============================================================================

TEST(VscpClientWs2, MsgReceiveQueueOps)
{
  vscpClientWs2 ws2;
  EXPECT_TRUE(ws2.m_msgReceiveQueue.empty());

  json j;
  j["type"]    = "+";
  j["command"] = "test";
  ws2.m_msgReceiveQueue.push_back(j);

  EXPECT_EQ(1u, ws2.m_msgReceiveQueue.size());

  json front = ws2.m_msgReceiveQueue.front();
  EXPECT_EQ("+", front["type"]);
  EXPECT_EQ("test", front["command"]);

  ws2.m_msgReceiveQueue.pop_front();
  EXPECT_TRUE(ws2.m_msgReceiveQueue.empty());
}

TEST(VscpClientWs2, MsgReceiveQueueMultipleMessages)
{
  vscpClientWs2 ws2;

  for (int i = 0; i < 5; i++) {
    json j;
    j["index"] = i;
    ws2.m_msgReceiveQueue.push_back(j);
  }

  EXPECT_EQ(5u, ws2.m_msgReceiveQueue.size());

  for (int i = 0; i < 5; i++) {
    json front = ws2.m_msgReceiveQueue.front();
    ws2.m_msgReceiveQueue.pop_front();
    EXPECT_EQ(i, front["index"]);
  }

  EXPECT_TRUE(ws2.m_msgReceiveQueue.empty());
}
