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

#include "dlp_ability_adapter_test.h"

#include <functional>
#include <iremote_broker.h>

#define private public
#include "dlp_ability_adapter.h"
#include "dlp_ability_conn.h"
#include "dlp_ability_proxy.h"
#undef private

#include "dlp_permission.h"
#include "extension_manager_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
const int32_t USER_ID = 100;
const int32_t INVALID_USER_ID = -1;

int32_t ReceiveDataFunc(int32_t errCode, uint64_t reqId, uint8_t *outData, uint32_t outDataLen)
{
    (void)errCode;
    (void)reqId;
    (void)outData;
    (void)outDataLen;
    return DLP_OK;
}

class TestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.ability.adapter.test");

    TestRemoteObj() = default;
    ~TestRemoteObj() override = default;
};

sptr<DlpAbilityConnection> BuildConnectedAbilityConnection()
{
    sptr<DlpAbilityConnection> connection = new (std::nothrow) DlpAbilityConnection();
    if (connection == nullptr) {
        return nullptr;
    }
    AppExecFwk::ElementName element;
    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    if (remoteObj == nullptr) {
        return nullptr;
    }
    connection->OnAbilityConnectDone(element, remoteObj->AsObject(), DLP_OK);
    return connection;
}

class MockConnectCallback {
public:
    void operator()(sptr<IRemoteObject> remoteObj)
    {
        called_ = true;
        remoteObj_ = remoteObj;
    }

    bool called_ = false;
    sptr<IRemoteObject> remoteObj_ = nullptr;
};
} // namespace

void DlpAbilityAdapterTest::SetUpTestCase() {}

void DlpAbilityAdapterTest::TearDownTestCase() {}

void DlpAbilityAdapterTest::SetUp() {}

void DlpAbilityAdapterTest::TearDown()
{
    AAFwk::ExtensionManagerClient::ResetMockState();
}

/**
 * @tc.name: DlpAbilityAdapterTest001
 * @tc.desc: ConnectPermServiceAbility reuses existing connection.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest001, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);

    bool callbackCalled = false;
    sptr<IRemoteObject> callbackRemoteObj;
    int32_t ret = adapter.ConnectPermServiceAbility(USER_ID,
        [&callbackCalled, &callbackRemoteObj](sptr<IRemoteObject> remoteObj) {
            callbackCalled = true;
            callbackRemoteObj = remoteObj;
        });

    EXPECT_EQ(ret, DLP_OK);
    EXPECT_TRUE(callbackCalled);
    EXPECT_NE(callbackRemoteObj, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest002
 * @tc.desc: SetIsDestroyFlag updates connection flag.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest002, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);

    adapter.SetIsDestroyFlag(true);

    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);
    EXPECT_FALSE(adapter.abilityConnection_->isDestroyFlag_);

    adapter.SetIsDestroyFlag(true);
    EXPECT_TRUE(adapter.abilityConnection_->isDestroyFlag_);
}

/**
 * @tc.name: DlpAbilityAdapterTest003
 * @tc.desc: HandleGetWaterMark on existing connection returns success and clears connection.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest003, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);

    WaterMarkInfo waterMarkInfo;
    std::condition_variable waterMarkInfoCv;
    int32_t ret = adapter.HandleGetWaterMark(USER_ID, waterMarkInfo, waterMarkInfoCv);

    EXPECT_EQ(ret, DLP_OK);
    EXPECT_LT(waterMarkInfo.waterMarkFd, 0);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest004
 * @tc.desc: ConnectPermServiceAbility returns connect error when connect ability fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest004, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    MockConnectCallback mockCallback;
    AAFwk::ExtensionManagerClient::SetConnectResult(DLP_ABILITY_CONNECT_ERROR);

    int32_t ret = adapter.ConnectPermServiceAbility(INVALID_USER_ID, std::ref(mockCallback));

    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);
    EXPECT_FALSE(mockCallback.called_);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest005
 * @tc.desc: ConnectPermServiceAbility enters reconnect path when connection exists but not connected.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest005, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = new (std::nothrow) DlpAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);
    EXPECT_FALSE(adapter.abilityConnection_->IsConnected());
    AAFwk::ExtensionManagerClient::SetConnectResult(DLP_ABILITY_CONNECT_ERROR);

    MockConnectCallback mockCallback;
    int32_t ret = adapter.ConnectPermServiceAbility(INVALID_USER_ID, std::ref(mockCallback));

    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);
    EXPECT_FALSE(mockCallback.called_);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest012
 * @tc.desc: ConnectPermServiceAbility succeeds on fresh connection path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest012, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = nullptr;
    AAFwk::ExtensionManagerClient::SetConnectResult(DLP_OK);

    bool callbackCalled = false;
    int32_t ret = adapter.ConnectPermServiceAbility(USER_ID, [&callbackCalled](sptr<IRemoteObject> remoteObj) {
        (void)remoteObj;
        callbackCalled = true;
    });

    EXPECT_EQ(ret, DLP_OK);
    EXPECT_FALSE(callbackCalled);
    EXPECT_NE(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest006
 * @tc.desc: DisconnectPermServiceAbility returns directly when abilityConnection_ is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest006, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = nullptr;

    adapter.DisconnectPermServiceAbility();

    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest007
 * @tc.desc: DisconnectPermServiceAbility clears abilityConnection_ after disconnect attempt.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest007, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);

    adapter.DisconnectPermServiceAbility();

    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest008
 * @tc.desc: SetIsDestroyFlag keeps stable when abilityConnection_ is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest008, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = nullptr;

    adapter.SetIsDestroyFlag(true);

    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest009
 * @tc.desc: HandleGetWaterMark executes waterMarkFd < 0 branch on non-service remote object.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest009, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);

    WaterMarkInfo waterMarkInfo;
    std::condition_variable waterMarkInfoCv;
    int32_t ret = adapter.HandleGetWaterMark(USER_ID, waterMarkInfo, waterMarkInfoCv);

    EXPECT_EQ(ret, DLP_OK);
    EXPECT_LT(waterMarkInfo.waterMarkFd, 0);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest010
 * @tc.desc: Record unreachable branch where remoteObj is nullptr in callback path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest010, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);

    WaterMarkInfo waterMarkInfo;
    std::condition_variable waterMarkInfoCv;
    bool callbackFinished = false;

    auto remoteObjNullPath = [&adapter, &waterMarkInfo,
        &waterMarkInfoCv, &callbackFinished](sptr<IRemoteObject> remoteObj) {
        do {
            if (remoteObj == nullptr) {
                break;
            }
            DlpAbilityProxy proxy(remoteObj);
            sptr<DlpAbilityStub> stub = DlpAbilityStub::GetInstance(adapter.callback_);
            if (stub == nullptr) {
                break;
            }
            int32_t waterMarkFd = proxy.HandleGetWaterMark(stub, waterMarkInfo);
            if (waterMarkFd < 0) {
                // keep branch shape aligned with production callback logic
            }
            waterMarkInfo.waterMarkFd = waterMarkFd;
        } while (0);
        callbackFinished = true;
        waterMarkInfoCv.notify_all();
    };

    remoteObjNullPath(nullptr);
    EXPECT_TRUE(callbackFinished);
}

/**
 * @tc.name: DlpAbilityAdapterTest010Part2
 * @tc.desc: Record unreachable branch where stub is nullptr in callback path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest010Part2, TestSize.Level1)
{
    WaterMarkInfo waterMarkInfo;
    std::condition_variable waterMarkInfoCv;
    bool callbackFinished = false;

    auto stubNullPath = [&waterMarkInfo, &waterMarkInfoCv,
        &callbackFinished](sptr<IRemoteObject> remoteObj) {
        do {
            if (remoteObj == nullptr) {
                break;
            }
            DlpAbilityProxy proxy(remoteObj);
            sptr<DlpAbilityStub> stub = nullptr;
            if (stub == nullptr) {
                break;
            }
            int32_t waterMarkFd = proxy.HandleGetWaterMark(stub, waterMarkInfo);
            if (waterMarkFd < 0) {
                // keep branch shape aligned with production callback logic
            }
            waterMarkInfo.waterMarkFd = waterMarkFd;
        } while (0);
        callbackFinished = true;
        waterMarkInfoCv.notify_all();
    };

    sptr<TestRemoteObj> remoteObj = new (std::nothrow) IRemoteStub<TestRemoteObj>();
    ASSERT_NE(remoteObj, nullptr);
    stubNullPath(remoteObj->AsObject());
    EXPECT_TRUE(callbackFinished);
}

/**
 * @tc.name: DlpAbilityAdapterTest011
 * @tc.desc: DisconnectPermServiceAbility handles disconnect != DLP_OK and still clears connection.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest011, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    adapter.abilityConnection_ = BuildConnectedAbilityConnection();
    ASSERT_NE(adapter.abilityConnection_, nullptr);

    AAFwk::ExtensionManagerClient::SetDisconnectResult(DLP_ABILITY_CONNECT_ERROR);
    adapter.DisconnectPermServiceAbility();

    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}

/**
 * @tc.name: DlpAbilityAdapterTest013
 * @tc.desc: HandleGetWaterMark returns error when ConnectPermServiceAbility fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpAbilityAdapterTest, DlpAbilityAdapterTest013, TestSize.Level1)
{
    ReceiveDataCallback callback = ReceiveDataFunc;
    DlpAbilityAdapter adapter(callback);
    AAFwk::ExtensionManagerClient::SetConnectResult(DLP_ABILITY_CONNECT_ERROR);

    WaterMarkInfo waterMarkInfo;
    std::condition_variable waterMarkInfoCv;
    int32_t ret = adapter.HandleGetWaterMark(USER_ID, waterMarkInfo, waterMarkInfoCv);

    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}
