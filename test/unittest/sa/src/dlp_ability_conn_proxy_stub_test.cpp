/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <functional>
#include <iremote_broker.h>

#include "gtest/gtest.h"

#define private public
#include "dlp_ability_conn.h"
#include "dlp_ability_proxy.h"
#include "dlp_ability_stub.h"
#undef private

#include "dlp_permission.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
bool g_disconnectCalled = false;

int32_t TestDisconnectCallback(int32_t errCode, uint64_t reqId, uint8_t *outData, uint32_t outDataLen)
{
    (void)errCode;
    (void)reqId;
    (void)outData;
    (void)outDataLen;
    g_disconnectCalled = true;
    return DLP_OK;
}

class DlpAbilityConnProxyStubTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        g_disconnectCalled = false;
        DlpAbilityStub::singleton_ = nullptr;
    }

    void TearDown() override
    {
        DlpAbilityStub::singleton_ = nullptr;
    }
};

class TestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.ability.conn.proxy.stub.test");

    TestRemoteObj() = default;
    ~TestRemoteObj() override = default;
};

enum class ReplyMode {
    SEND_FAIL = 0,
    REPLY_CODE_FAIL,
    TOKEN_MISMATCH,
    STATUS_FAIL,
    MASK_EMPTY,
    SUCCESS,
};

class FakeAbilityRemote : public IRemoteStub<IDlpAbility> {
public:
    explicit FakeAbilityRemote(ReplyMode mode) : mode_(mode) {}
    ~FakeAbilityRemote() override = default;

    int32_t HandleGetWaterMark(sptr<IRemoteObject> remoteObj, WaterMarkInfo &waterMarkInfo) override
    {
        (void)remoteObj;
        (void)waterMarkInfo;
        return DLP_OK;
    }

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        (void)code;
        (void)data;
        (void)option;
        switch (mode_) {
            case ReplyMode::SEND_FAIL:
                return DLP_ABILITY_CONNECT_ERROR;
            case ReplyMode::REPLY_CODE_FAIL:
                reply.WriteInt32(DLP_ABILITY_CONNECT_ERROR);
                return DLP_OK;
            case ReplyMode::TOKEN_MISMATCH:
                reply.WriteInt32(DLP_OK);
                reply.WriteInterfaceToken(u"wrong.descriptor");
                return DLP_OK;
            case ReplyMode::STATUS_FAIL:
                reply.WriteInt32(DLP_OK);
                reply.WriteInterfaceToken(IDlpAbilityCallback::GetDescriptor());
                reply.WriteInt32(DLP_ABILITY_CONNECT_ERROR);
                return DLP_OK;
            case ReplyMode::MASK_EMPTY:
                reply.WriteInt32(DLP_OK);
                reply.WriteInterfaceToken(IDlpAbilityCallback::GetDescriptor());
                reply.WriteInt32(DLP_OK);
                reply.WriteString16(u"");
                return DLP_OK;
            case ReplyMode::SUCCESS:
                reply.WriteInt32(DLP_OK);
                reply.WriteInterfaceToken(IDlpAbilityCallback::GetDescriptor());
                reply.WriteInt32(DLP_OK);
                reply.WriteString16(u"mask");
                reply.WriteFileDescriptor(0);
                return DLP_OK;
            default:
                return DLP_ABILITY_CONNECT_ERROR;
        }
    }

private:
    ReplyMode mode_;
};
} // namespace

/**
 * @tc.name: DlpAbilityConnection001
 * @tc.desc: DlpAbilityConnection OnAbilityConnectDone covers null and non-null remote branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityConnection001, TestSize.Level1)
{
    bool connectCalled = false;
    g_disconnectCalled = false;
    DlpAbilityConnection connection(
        [&connectCalled](sptr<IRemoteObject> remoteObj) {
            connectCalled = (remoteObj != nullptr);
        },
        TestDisconnectCallback);

    AppExecFwk::ElementName element;
    connection.OnAbilityConnectDone(element, nullptr, DLP_OK);
    EXPECT_FALSE(connection.IsConnected());
    EXPECT_FALSE(connectCalled);

    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    ASSERT_NE(remoteObj, nullptr);
    connection.OnAbilityConnectDone(element, remoteObj->AsObject(), DLP_OK);
    EXPECT_TRUE(connection.IsConnected());
    EXPECT_TRUE(connectCalled);
    EXPECT_NE(connection.GetProxy(), nullptr);

    connection.OnAbilityDisconnectDone(element, DLP_OK);
    EXPECT_TRUE(g_disconnectCalled);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: DlpAbilityConnection002
 * @tc.desc: DlpAbilityConnection OnAbilityDisconnectDone covers isDestroyFlag true branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityConnection002, TestSize.Level1)
{
    g_disconnectCalled = false;
    DlpAbilityConnection connection(
        nullptr,
        TestDisconnectCallback);

    AppExecFwk::ElementName element;
    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    ASSERT_NE(remoteObj, nullptr);
    connection.OnAbilityConnectDone(element, remoteObj->AsObject(), DLP_OK);
    EXPECT_TRUE(connection.IsConnected());

    connection.SetIsDestroyFlag(true);
    connection.OnAbilityDisconnectDone(element, DLP_OK);
    EXPECT_FALSE(g_disconnectCalled);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: DlpAbilityConnection003
 * @tc.desc: DlpAbilityConnection covers connectCallback_ == nullptr branch in OnAbilityConnectDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityConnection003, TestSize.Level1)
{
    DlpAbilityConnection connection(nullptr, nullptr);
    AppExecFwk::ElementName element;
    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    ASSERT_NE(remoteObj, nullptr);

    connection.OnAbilityConnectDone(element, remoteObj->AsObject(), DLP_OK);
    EXPECT_TRUE(connection.IsConnected());
    EXPECT_NE(connection.GetProxy(), nullptr);
}

/**
 * @tc.name: DlpAbilityConnection004
 * @tc.desc: DlpAbilityConnection covers disconnectCallback_ == nullptr branch in OnAbilityDisconnectDone.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityConnection004, TestSize.Level1)
{
    DlpAbilityConnection connection(nullptr, nullptr);
    AppExecFwk::ElementName element;
    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    ASSERT_NE(remoteObj, nullptr);

    connection.OnAbilityConnectDone(element, remoteObj->AsObject(), DLP_OK);
    EXPECT_TRUE(connection.IsConnected());

    connection.OnAbilityDisconnectDone(element, DLP_OK);
    EXPECT_FALSE(connection.IsConnected());
}

/**
 * @tc.name: DlpAbilityProxy001
 * @tc.desc: DlpAbilityProxy HandleGetWaterMark covers remote null and send fail branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityProxy001, TestSize.Level1)
{
    WaterMarkInfo info;
    sptr<DlpAbilityStub> stub = DlpAbilityStub::GetInstance(nullptr);
    ASSERT_NE(stub, nullptr);

    DlpAbilityProxy proxyNull(nullptr);
    int32_t ret = proxyNull.HandleGetWaterMark(stub, info);
    EXPECT_EQ(ret, DLP_IPC_SEND_REQUEST_ERROR);

    sptr<FakeAbilityRemote> sendFailRemote = new (std::nothrow) FakeAbilityRemote(ReplyMode::SEND_FAIL);
    ASSERT_NE(sendFailRemote, nullptr);
    DlpAbilityProxy proxySendFail(sendFailRemote);
    ret = proxySendFail.HandleGetWaterMark(stub, info);
    EXPECT_EQ(ret, DLP_IPC_SEND_REQUEST_ERROR);
}

/**
 * @tc.name: DlpAbilityProxy002
 * @tc.desc: DlpAbilityProxy HandleGetWaterMark covers reply parse branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityProxy002, TestSize.Level1)
{
    WaterMarkInfo info;
    sptr<DlpAbilityStub> stub = DlpAbilityStub::GetInstance(nullptr);
    ASSERT_NE(stub, nullptr);

    sptr<FakeAbilityRemote> replyCodeFail = new (std::nothrow) FakeAbilityRemote(ReplyMode::REPLY_CODE_FAIL);
    ASSERT_NE(replyCodeFail, nullptr);
    DlpAbilityProxy proxyReplyCodeFail(replyCodeFail);
    int32_t ret = proxyReplyCodeFail.HandleGetWaterMark(stub, info);
    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);

    sptr<FakeAbilityRemote> tokenMismatch = new (std::nothrow) FakeAbilityRemote(ReplyMode::TOKEN_MISMATCH);
    ASSERT_NE(tokenMismatch, nullptr);
    DlpAbilityProxy proxyTokenMismatch(tokenMismatch);
    ret = proxyTokenMismatch.HandleGetWaterMark(stub, info);
    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);

    sptr<FakeAbilityRemote> statusFail = new (std::nothrow) FakeAbilityRemote(ReplyMode::STATUS_FAIL);
    ASSERT_NE(statusFail, nullptr);
    DlpAbilityProxy proxyStatusFail(statusFail);
    ret = proxyStatusFail.HandleGetWaterMark(stub, info);
    EXPECT_LT(ret, 0);

    sptr<FakeAbilityRemote> maskEmpty = new (std::nothrow) FakeAbilityRemote(ReplyMode::MASK_EMPTY);
    ASSERT_NE(maskEmpty, nullptr);
    DlpAbilityProxy proxyMaskEmpty(maskEmpty);
    ret = proxyMaskEmpty.HandleGetWaterMark(stub, info);
    EXPECT_LT(ret, 0);

    sptr<FakeAbilityRemote> success = new (std::nothrow) FakeAbilityRemote(ReplyMode::SUCCESS);
    ASSERT_NE(success, nullptr);
    DlpAbilityProxy proxySuccess(success);
    ret = proxySuccess.HandleGetWaterMark(stub, info);
    EXPECT_GE(ret, 0);
}

/**
 * @tc.name: DlpAbilityStub001
 * @tc.desc: DlpAbilityStub GetInstance and OnRemoteRequest cover singleton and descriptor branches.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityConnProxyStubTest, DlpAbilityStub001, TestSize.Level1)
{
    DlpAbilityStub::singleton_ = nullptr;
    sptr<DlpAbilityStub> first = DlpAbilityStub::GetInstance(nullptr);
    ASSERT_NE(first, nullptr);
    sptr<DlpAbilityStub> second = DlpAbilityStub::GetInstance(nullptr);
    EXPECT_EQ(first.GetRefPtr(), second.GetRefPtr());

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t ret = first->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, DLP_IPC_DISMATCH_DESCRIPTOR);

    MessageParcel data2;
    MessageParcel reply2;
    MessageOption option2;
    data2.WriteInterfaceToken(first->GetDescriptor());
    ret = first->OnRemoteRequest(0, data2, reply2, option2);
    EXPECT_EQ(ret, DLP_OK);

    std::string jsonRes;
    first->OnResult(0, 0, jsonRes);
}
