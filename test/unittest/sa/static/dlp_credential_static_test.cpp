/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 
 
#include "dlp_credential_static_test.h"
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include "account_adapt.h"
#include "cert_parcel.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_async_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_parcel.h"
#include "dlp_credential.cpp"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "securec.h"
 
namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
 
void DlpCredentialStaticTest::SetUpTestCase() {}
 
void DlpCredentialStaticTest::TearDownTestCase() {}
 
void DlpCredentialStaticTest::SetUp() {}
 
void DlpCredentialStaticTest::TearDown() {}
 
/**
 * @tc.name: DlpCredentialStaticTest001
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest001, TestSize.Level1)
{
 // Test DLP_SUCCESS case
    ASSERT_EQ(ConvertCredentialError(DLP_SUCCESS), DLP_OK);
 
    // Test IsEnterpriseError case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_ENTERPRISE_MIN), DLP_ERR_ENTERPRISE_MIN);
 
    // Test DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED), DLP_CREDENTIAL_ERROR_TIME_EXPIRED);
 
    // Test DLP_ERR_APPID_NOT_AUTHORIZED case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_APPID_NOT_AUTHORIZED), DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED);
 
    // Test DLP_ERR_CALLBACK_TIME_OUT case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_CALLBACK_TIME_OUT), DLP_CREDENTIAL_ERROR_SERVER_TIME_OUT_ERROR);
 
    // Test DLP_ERR_ACCOUNT_NOT_LOG_IN case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_ACCOUNT_NOT_LOG_IN), DLP_CREDENTIAL_ERROR_NO_ACCOUNT_ERROR);
 
    // Test DLP_ERR_CONNECTION_ALLOWED_OPEN_COUNT_INVALID case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_CONNECTION_ALLOWED_OPEN_COUNT_INVALID),
        DLP_CREDENTIAL_ERROR_ALLOWED_OPEN_COUNT_INVALID);
 
    // Test IsNoInternetError case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_CONNECTION_TIME_OUT), DLP_CREDENTIAL_ERROR_NO_INTERNET);
 
    // Test IsNoPermissionError case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_CONNECTION_NO_PERMISSION), DLP_CREDENTIAL_ERROR_NO_PERMISSION_ERROR);
 
    // Test IsDlpCredentialHuksError case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_GENERATE_KEY_FAILED), DLP_CREDENTIAL_ERROR_HUKS_ERROR);
 
    // Test IsDlpCredentialIpcError case
    ASSERT_EQ(ConvertCredentialError(DLP_ERR_IPC_INTERNAL_FAILED), DLP_CREDENTIAL_ERROR_IPC_ERROR);
}
 
/**
 * @tc.name: DlpCredentialStaticTest002
 * @tc.desc: Test IsDlpCredentialHuksError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest002, TestSize.Level1) {
    // Test IsDlpCredentialHuksError case
    ASSERT_FALSE(IsDlpCredentialHuksError(DLP_ERR_GENERATE_KEY_FAILED - 1));
    ASSERT_TRUE(IsDlpCredentialHuksError(DLP_ERR_GENERATE_KEY_FAILED));
    ASSERT_TRUE(IsDlpCredentialHuksError(DLP_ERR_IPC_INTERNAL_FAILED - 1));
    ASSERT_FALSE(IsDlpCredentialHuksError(DLP_ERR_IPC_INTERNAL_FAILED));
}
 
/**
 * @tc.name: DlpCredentialStaticTest003
 * @tc.desc: Test IsEnterpriseError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest003, TestSize.Level1) {
    // Test IsEnterpriseError case
    ASSERT_FALSE(IsEnterpriseError(DLP_ERR_ENTERPRISE_MIN - 1));
    ASSERT_TRUE(IsEnterpriseError(DLP_ERR_ENTERPRISE_MIN));
    ASSERT_TRUE(IsEnterpriseError(DLP_ERR_ENTERPRISE_MAX - 1));
    ASSERT_FALSE(IsEnterpriseError(DLP_ERR_ENTERPRISE_MAX));
}
 
/**
 * @tc.name: DlpCredentialStaticTest004
 * @tc.desc: Test IsDlpCredentialIpcError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest004, TestSize.Level1) {
    // Test IsDlpCredentialIpcError case
    ASSERT_FALSE(IsDlpCredentialIpcError(DLP_ERR_IPC_INTERNAL_FAILED - 1));
    ASSERT_TRUE(IsDlpCredentialIpcError(DLP_ERR_IPC_INTERNAL_FAILED));
    ASSERT_TRUE(IsDlpCredentialIpcError(DLP_ERR_CONNECTION_TIME_OUT - 1));
    ASSERT_FALSE(IsDlpCredentialIpcError(DLP_ERR_CONNECTION_TIME_OUT));
}
 
/**
 * @tc.name: DlpCredentialStaticTest005
 * @tc.desc: Test IsDlpCredentialServerError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest005, TestSize.Level1) {
    // Test IsDlpCredentialServerError case
    ASSERT_FALSE(IsDlpCredentialServerError(DLP_ERR_CONNECTION_TIME_OUT - 1));
    ASSERT_TRUE(IsDlpCredentialServerError(DLP_ERR_CONNECTION_TIME_OUT));
    ASSERT_TRUE(IsDlpCredentialServerError(DLP_ERR_FILE_PATH - 1));
    ASSERT_FALSE(IsDlpCredentialServerError(DLP_ERR_FILE_PATH));
}
 
/**
 * @tc.name: DlpCredentialStaticTest006
 * @tc.desc: Test IsNoPermissionError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest006, TestSize.Level1) {
    // Test IsNoPermissionError case
    ASSERT_TRUE(IsNoPermissionError(DLP_ERR_CONNECTION_VIP_RIGHT_EXPIRED));
    ASSERT_TRUE(IsNoPermissionError(DLP_ERR_CONNECTION_NO_PERMISSION));
}
 
/**
 * @tc.name: DlpCredentialStaticTest007
 * @tc.desc: Test IsNoInternetError case
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, DlpCredentialStaticTest007, TestSize.Level1) {
    // Test IsNoInternetError case
    ASSERT_TRUE(IsNoInternetError(DLP_ERR_CONNECTION_TIME_OUT));
    ASSERT_TRUE(IsNoInternetError(DLP_ERR_TOKEN_CONNECTION_TIME_OUT));
    ASSERT_TRUE(IsNoInternetError(DLP_ERR_TOKEN_CONNECTION_FAIL));
}
/**
 * @tc.name: RemovePresetDLPPolicyTest001
 * @tc.desc: Test RemovePresetDLPPolicy with non-empty appIdList
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, RemovePresetDLPPolicyTest001, TestSize.Level1) {
    std::vector<std::string> appIdList = {"testAppId"};
    ASSERT_EQ(RemovePresetDLPPolicy(appIdList), DLP_OK);
    ASSERT_EQ(appIdList.size(), 0);
}
 
/**
 * @tc.name: RemovePresetDLPPolicyTest002
 * @tc.desc: Test RemovePresetDLPPolicy with empty appIdList
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, RemovePresetDLPPolicyTest002, TestSize.Level1) {
    std::vector<std::string> appIdList;
    ASSERT_EQ(RemovePresetDLPPolicy(appIdList), DLP_OK);
    ASSERT_EQ(appIdList.size(), 0);
}
 
/**
 * @tc.name: GetNewCertTest001
 * @tc.desc: Test GetNewCert with valid policyCert
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, GetNewCertTest001, TestSize.Level1) {
    unordered_json plainPolicyJson;
    plainPolicyJson[POLICY_CERT] = unordered_json::object();
    std::vector<uint8_t> cert;
    DlpAccountType ownerAccountType = DlpAccountType::ENTERPRISE_ACCOUNT;
    ASSERT_EQ(GetNewCert(plainPolicyJson, cert, ownerAccountType), DLP_OK);
}
 
/**
 * @tc.name: GetNewCertTest002
 * @tc.desc: Test GetNewCert with invalid policyCert
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, GetNewCertTest002, TestSize.Level1) {
    unordered_json plainPolicyJson;
    std::vector<uint8_t> cert;
    DlpAccountType ownerAccountType = DlpAccountType::ENTERPRISE_ACCOUNT;
    ASSERT_EQ(GetNewCert(plainPolicyJson, cert, ownerAccountType), DLP_OK);
}
 
 
/**
 * @tc.name: CheckDebugPermissionTest001
 * @tc.desc: Test CheckDebugPermission with non-debug app
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, CheckDebugPermissionTest001, TestSize.Level1) {
    RequestInfo requestInfo;
    requestInfo.appProvisionType = AppExecFwk::Constants::APP_PROVISION_TYPE_RELEASE;
    PermissionPolicy policyInfo;
    ASSERT_EQ(CheckDebugPermission(requestInfo, policyInfo), DLP_OK);
}
 
 
/**
 * @tc.name: CheckDebugPermissionTest003
 * @tc.desc: Test CheckDebugPermission with debug app and non-developer mode
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, CheckDebugPermissionTest003, TestSize.Level1) {
    RequestInfo requestInfo;
    requestInfo.appProvisionType = AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG;
    PermissionPolicy policyInfo;
    policyInfo.debug_ = false;
    ASSERT_EQ(CheckDebugPermission(requestInfo, policyInfo), DLP_SERVICE_ERROR_PERMISSION_DENY);
}
 
/**
 * @tc.name: GetEnterpriseAccountNameTest001
 * @tc.desc: Test GetEnterpriseAccountName with valid appId
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, GetEnterpriseAccountNameTest001, TestSize.Level1) {
    AccountInfo accountCfg;
    std::string appId = "testAppId";
    bool isOwner = false;
    ASSERT_EQ(GetEnterpriseAccountName(accountCfg, appId, &isOwner), DLP_OK);
}
 
 
/**
 * @tc.name: AdapterDataTest001
 * @tc.desc: Test AdapterData with valid offlineCert
 * @tc.type: FUNC
 * @tc.require: 
 */
HWTEST_F(DlpCredentialStaticTest, AdapterDataTest001, TestSize.Level1) {
    std::vector<uint8_t> offlineCert = {1, 2, 3};
    bool isOwner = true;
    unordered_json jsonObj;
    DLP_EncPolicyData encPolicy;
    ASSERT_EQ(AdapterData(offlineCert, isOwner, jsonObj, encPolicy), DLP_SERVICE_ERROR_JSON_OPERATE_FAIL);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS