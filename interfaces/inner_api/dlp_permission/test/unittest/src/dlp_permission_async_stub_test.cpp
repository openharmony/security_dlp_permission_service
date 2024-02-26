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

#include "dlp_permission_async_stub_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_callback.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionAsyncStubTest"};
}

void DlpPermissionAsyncStubTest::SetUpTestCase() {}

void DlpPermissionAsyncStubTest::TearDownTestCase() {}

void DlpPermissionAsyncStubTest::SetUp() {}

void DlpPermissionAsyncStubTest::TearDown() {}

/**
 * @tc.name: OnGenerateDlpCertificate001
 * @tc.desc: OnGenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnGenerateDlpCertificate001");

    std::shared_ptr<GenerateDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t result = 0;
    std::vector<uint8_t> cert;

    callback->OnGenerateDlpCertificate(result, cert);
    ASSERT_EQ(nullptr, callback->generateDlpCertificateCallback_);
}

/**
 * @tc.name: OnGenerateDlpCertificate002
 * @tc.desc: OnGenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnGenerateDlpCertificate002");

    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t result = 0;
    std::vector<uint8_t> cert;

    callback->OnGenerateDlpCertificate(result, cert);
    ASSERT_NE(nullptr, callback->generateDlpCertificateCallback_);
}

/**
 * @tc.name: OnParseDlpCertificate001
 * @tc.desc: OnParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificate001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t result = 0;
    PermissionPolicy policy;
    std::vector<uint8_t> cert;

    callback->OnParseDlpCertificate(result, policy, cert);
    ASSERT_EQ(nullptr, callback->parseDlpCertificateCallback_);
}

/**
 * @tc.name: OnParseDlpCertificate002
 * @tc.desc: OnParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificate002");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 =
        std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t result = 0;
    PermissionPolicy policy;
    std::vector<uint8_t> cert;

    callback->OnParseDlpCertificate(result, policy, cert);
    ASSERT_NE(nullptr, callback->parseDlpCertificateCallback_);
}

/**
 * @tc.name: OnParseDlpCertificateStub001
 * @tc.desc: OnParseDlpCertificateStub test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificateStub001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    MessageParcel data;
    MessageParcel reply;

    int32_t ret = callback->OnParseDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: OnRemoteRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnRemoteRequest001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    int32_t ret = callback->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ret);
}