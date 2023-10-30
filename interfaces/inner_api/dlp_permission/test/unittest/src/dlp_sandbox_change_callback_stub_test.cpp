/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_sandbox_change_callback_stub_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_callback_info_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpSandboxChangeCallbackStubTest"};
constexpr uint32_t DLP_SANDBOX_STATE_CHANGE = 0;
}

void DlpSandboxChangeCallbackStubTest::SetUpTestCase() {}

void DlpSandboxChangeCallbackStubTest::TearDownTestCase() {}

void DlpSandboxChangeCallbackStubTest::SetUp() {}

void DlpSandboxChangeCallbackStubTest::TearDown() {}

class DlpSandboxChangeCallbackTest : public DlpSandboxChangeCallbackStub {
public:
    DlpSandboxChangeCallbackTest() = default;
    virtual ~DlpSandboxChangeCallbackTest() = default;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) override;
};

void DlpSandboxChangeCallbackTest::DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) {}

/**
 * @tc.name: OnLoadSystemAbilityFail001
 * @tc.desc: OnLoadSystemAbilityFail test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSandboxChangeCallbackStubTest, OnLoadSystemAbilityFail001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnLoadSystemAbilityFail001");

    uint32_t code = DLP_SANDBOX_STATE_CHANGE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto stub = new (std::nothrow) DlpSandboxChangeCallbackTest();
    ASSERT_FALSE(stub == nullptr);

    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ret);

    std::u16string descriptor = IDlpSandboxStateChangeCallback::GetDescriptor();
    data.WriteInterfaceToken(descriptor);
    ret = stub->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);

    delete stub;
}

/**
 * @tc.name: OnLoadSystemAbilityFail002
 * @tc.desc: OnLoadSystemAbilityFail test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSandboxChangeCallbackStubTest, OnLoadSystemAbilityFail002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnLoadSystemAbilityFail002");

    uint32_t code = DLP_SANDBOX_STATE_CHANGE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto stub = new (std::nothrow) DlpSandboxChangeCallbackTest();
    ASSERT_FALSE(stub == nullptr);

    std::u16string descriptor = IDlpSandboxStateChangeCallback::GetDescriptor();
    data.WriteInterfaceToken(descriptor);

    sptr<DlpSandboxCallbackInfoParcel> policyParcel = new (std::nothrow) DlpSandboxCallbackInfoParcel();
    ASSERT_FALSE(policyParcel == nullptr);
    data.WriteParcelable(policyParcel);

    int32_t ret = stub->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_OK, ret);

    delete stub;
}

/**
 * @tc.name: OnLoadSystemAbilityFail003
 * @tc.desc: OnLoadSystemAbilityFail test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSandboxChangeCallbackStubTest, OnLoadSystemAbilityFail003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnLoadSystemAbilityFail003");

    uint32_t code = DLP_SANDBOX_STATE_CHANGE + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    auto stub = new (std::nothrow) DlpSandboxChangeCallbackTest();
    ASSERT_FALSE(stub == nullptr);

    std::u16string descriptor = IDlpSandboxStateChangeCallback::GetDescriptor();
    data.WriteInterfaceToken(descriptor);

    stub->OnRemoteRequest(code, data, reply, option);
    ASSERT_NE(DLP_SANDBOX_STATE_CHANGE, code);

    delete stub;
}
