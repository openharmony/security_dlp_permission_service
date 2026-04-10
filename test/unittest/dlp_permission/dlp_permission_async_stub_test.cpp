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
#include "dlp_permission_service_ipc_interface_code.h"
#include "dlp_policy_parcel.h"

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
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificate001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnGenerateDlpCertificate001");

    std::shared_ptr<GenerateDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
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
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificate002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnGenerateDlpCertificate002");

    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
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
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificate001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificate001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
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
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificate002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificate002");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 =
        std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    int32_t result = 0;
    PermissionPolicy policy;
    std::vector<uint8_t> cert;

    callback->OnParseDlpCertificate(result, policy, cert);
    ASSERT_NE(nullptr, callback->parseDlpCertificateCallback_);
}

/**
 * @tc.name: OnGetDlpWaterMark001
 * @tc.desc: OnGetDlpWaterMark test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGetDlpWaterMark001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnGetDlpWaterMark001");

    std::shared_ptr<GetWaterMarkCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    int32_t result = 0;
    GeneralInfo info;

    callback->OnGetDlpWaterMark(result, info);
    ASSERT_EQ(nullptr, callback->getWaterMarkCallback_);
}

/**
 * @tc.name: OnGetDlpWaterMark002
 * @tc.desc: OnParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGetDlpWaterMark002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnGetDlpWaterMark002");

    std::shared_ptr<GetWaterMarkCallback> callback1 =
        std::make_shared<GetWaterMarkCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    int32_t result = 0;
    GeneralInfo info;

    callback->OnGetDlpWaterMark(result, info);
    ASSERT_EQ(result, DLP_OK);
}

/**
 * @tc.name: OnParseDlpCertificateStub001
 * @tc.desc: OnParseDlpCertificateStub test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnParseDlpCertificateStub001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
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
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnRemoteRequest001");

    std::shared_ptr<ParseDlpCertificateCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    int32_t ret = callback->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: OnRemoteRequest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "OnRemoteRequest002");

    std::shared_ptr<GetWaterMarkCallback> callback1 = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    int32_t ret = callback->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL, ret);
}

/**
 * @tc.name: OnGenerateDlpCertificateStub000
 * @tc.desc: OnGenerateDlpCertificateStub read int32 fail branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificateStub000, TestSize.Level0)
{
    std::shared_ptr<GenerateDlpCertificateCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = callback->OnGenerateDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}

/**
 * @tc.name: OnGenerateDlpCertificateStub001
 * @tc.desc: OnGenerateDlpCertificateStub returns DLP_OK when result != DLP_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificateStub001, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL));

    int32_t ret = callback->OnGenerateDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnGenerateDlpCertificateStub002
 * @tc.desc: OnGenerateDlpCertificateStub fails when int32 is missing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificateStub002, TestSize.Level0)
{
    std::shared_ptr<GenerateDlpCertificateCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;

    int32_t ret = callback->OnGenerateDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}

/**
 * @tc.name: OnGenerateDlpCertificateStub003
 * @tc.desc: OnGenerateDlpCertificateStub success path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGenerateDlpCertificateStub003, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    std::vector<uint8_t> cert = {1, 2, 3};
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_OK));
    ASSERT_TRUE(data.WriteUInt8Vector(cert));

    int32_t ret = callback->OnGenerateDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnParseDlpCertificateStub002
 * @tc.desc: OnParseDlpCertificateStub returns DLP_OK when result != DLP_OK.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub002, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL));

    int32_t ret = callback->OnParseDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnParseDlpCertificateStub003
 * @tc.desc: OnParseDlpCertificateStub fails when policy parcel is missing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub003, TestSize.Level0)
{
    std::shared_ptr<ParseDlpCertificateCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_OK));

    int32_t ret = callback->OnParseDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}

/**
 * @tc.name: OnParseDlpCertificateStub004
 * @tc.desc: OnParseDlpCertificateStub returns DLP_OK when cert vector is missing.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub004, TestSize.Level0)
{
    std::shared_ptr<ParseDlpCertificateCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    ASSERT_NE(policyParcel, nullptr);
    uint8_t aesKey[16] = {0};
    uint8_t iv[16] = {0};
    policyParcel->policyParams_.SetAeskey(aesKey, sizeof(aesKey));
    policyParcel->policyParams_.SetIv(iv, sizeof(iv));
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_OK));
    ASSERT_TRUE(data.WriteParcelable(policyParcel));

    int32_t ret = callback->OnParseDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnParseDlpCertificateStub005
 * @tc.desc: OnParseDlpCertificateStub success path.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnParseDlpCertificateStub005, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    ASSERT_NE(policyParcel, nullptr);
    uint8_t aesKey[16] = {0};
    uint8_t iv[16] = {0};
    policyParcel->policyParams_.SetAeskey(aesKey, sizeof(aesKey));
    policyParcel->policyParams_.SetIv(iv, sizeof(iv));
    std::vector<uint8_t> cert = {4, 5, 6};
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_OK));
    ASSERT_TRUE(data.WriteParcelable(policyParcel));
    ASSERT_TRUE(data.WriteUInt8Vector(cert));

    int32_t ret = callback->OnParseDlpCertificateStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnGetDlpWaterMarkStub001
 * @tc.desc: OnGetDlpWaterMarkStub read int32 fail branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGetDlpWaterMarkStub001, TestSize.Level0)
{
    std::shared_ptr<GetWaterMarkCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = callback->OnGetDlpWaterMarkStub(data, reply);
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}

/**
 * @tc.name: OnGetDlpWaterMarkStub002
 * @tc.desc: OnGetDlpWaterMarkStub success branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnGetDlpWaterMarkStub002, TestSize.Level0)
{
    std::shared_ptr<GetWaterMarkCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    ASSERT_TRUE(data.WriteInt32(DLP_OK));
    int32_t ret = callback->OnGetDlpWaterMarkStub(data, reply);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: OnRemoteRequest dispatches ON_GENERATE_DLP_CERTIFICATE with matched descriptor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest003, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(DlpPermissionAsyncStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteInt32(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL));

    int32_t ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_GENERATE_DLP_CERTIFICATE), data, reply, option);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: OnRemoteRequest dispatches ON_PARSE_DLP_CERTIFICATE with matched descriptor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest004, TestSize.Level0)
{
    auto callbackImpl = std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(DlpPermissionAsyncStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteInt32(DLP_SERVICE_ERROR_IPC_REQUEST_FAIL));

    int32_t ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_PARSE_DLP_CERTIFICATE), data, reply, option);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: OnRemoteRequest dispatches ON_GET_DLP_WATERMARK with matched descriptor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest005, TestSize.Level0)
{
    std::shared_ptr<GetWaterMarkCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(DlpPermissionAsyncStub::GetDescriptor()));
    ASSERT_TRUE(data.WriteInt32(DLP_OK));

    int32_t ret = callback->OnRemoteRequest(
        static_cast<uint32_t>(DlpPermissionCallbackInterfaceCode::ON_GET_DLP_WATERMARK), data, reply, option);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: OnRemoteRequest default branch with matched descriptor.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionAsyncStubTest, OnRemoteRequest006, TestSize.Level0)
{
    std::shared_ptr<GetWaterMarkCallback> callbackImpl = nullptr;
    sptr<DlpPermissionAsyncStub> callback = new (std::nothrow) DlpPermissionAsyncStub(callbackImpl);
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    ASSERT_TRUE(data.WriteInterfaceToken(DlpPermissionAsyncStub::GetDescriptor()));

    int32_t ret = callback->OnRemoteRequest(100, data, reply, option);
    ASSERT_NE(DLP_OK, ret);
}