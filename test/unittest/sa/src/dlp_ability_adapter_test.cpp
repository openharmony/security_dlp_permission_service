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
#undef private

#include "dlp_permission.h"

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

void DlpAbilityAdapterTest::TearDown() {}

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

    int32_t ret = adapter.ConnectPermServiceAbility(INVALID_USER_ID, std::ref(mockCallback));

    EXPECT_EQ(ret, DLP_ABILITY_CONNECT_ERROR);
    EXPECT_FALSE(mockCallback.called_);
    EXPECT_EQ(adapter.abilityConnection_, nullptr);
}
