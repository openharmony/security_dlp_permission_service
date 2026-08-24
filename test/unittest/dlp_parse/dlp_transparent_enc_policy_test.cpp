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

#include "dlp_transparent_enc_policy_test.h"

#include "dlp_transparent_enc_policy.h"
#include "dlp_transparent_enc_manager.h"
#include "dlp_transparent_enc_policy_mock.h"
#include "dlp_permission.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::DlpPermission::TestMock;

namespace OHOS {
namespace Security {
namespace DlpPermission {

void DlpTransparentEncPolicyTest::SetUpTestCase() {}

void DlpTransparentEncPolicyTest::TearDownTestCase() {}

void DlpTransparentEncPolicyTest::SetUp()
{
    ResetAllMockState();
}

void DlpTransparentEncPolicyTest::TearDown() {}

// ===== CheckDockerPolicyPermission: no permission =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_NoPermission_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(-1);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckDockerPolicyPermission: SANDBOX_ACCESS_MANAGER granted =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_SandboxAccessGranted_Success, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckDockerPolicyPermission: FILE_ACCESS_MANAGER with docs URI =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_FileAccessDocsUri_Success, TestSize.Level1)
{
    SetVerifyAccessTokenResultForPerm(
        "ohos.permission.SANDBOX_ACCESS_MANAGER", -1);
    SetVerifyAccessTokenResultForPerm(
        "ohos.permission.FILE_ACCESS_MANAGER", 0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckDockerPolicyPermission: FILE_ACCESS with non-docs URI =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_FileAccessNonDocsUri_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResultForPerm(
        "ohos.permission.SANDBOX_ACCESS_MANAGER", -1);
    SetVerifyAccessTokenResultForPerm(
        "ohos.permission.FILE_ACCESS_MANAGER", 0);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://data/test", want));
}

// ===== IsEnvironmentValid: not enterprise platform =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_NotEnterprisePlatform_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResultForKey("const.dlp.functiontypes", "0");
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== IsEnvironmentValid: is DLP credential SA =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_IsDlpCredentialSa_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(100);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== IsEnvironmentValid: transparent crypto not ready =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_CryptoNotReady_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResultForKey("const.dlp.functiontypes", "1");
    SetGetParameterResultForKey("security.dlp.transparent.crypto.status", "3");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckEnterpriseEncryptedFile: not encrypted =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_NotEncrypted_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = false;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckEnterpriseEncryptedFile: encrypted but no sandbox =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_EncryptedNoSandbox_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = false;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== CheckEnterpriseEncryptedFile: encrypted need sandbox =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_EncryptedNeedSandbox_ReturnsTrue, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
    EXPECT_EQ(want.GetType(), "application/dlp");
}

// ===== GetDockerPolicy fail branch =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_GetDockerPolicyFail_ReturnsFalse, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_PARSE_ERROR_VALUE_INVALID);
    AAFwk::Want want;
    EXPECT_FALSE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== ConvertPermissionToCustomFlag: no networkAndSelinux → 0 =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_PermNoNetwork_ReturnsFlag0, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00000;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== ConvertPermissionToCustomFlag: READ_ONLY(38) =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_PermReadOnly_ReturnsFlag38, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== ConvertPermissionToCustomFlag: FULL_CONTROL(37) =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_PermFullControl_ReturnsFlag37, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResult("1");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b01001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

// ===== IsTransparentCryptoReady: value == "2" =====

HWTEST_F(DlpTransparentEncPolicyTest, Query_CryptoStatus2_Success, TestSize.Level1)
{
    SetVerifyAccessTokenResult(0);
    SetGetParameterResultForKey("const.dlp.functiontypes", "1");
    SetGetParameterResultForKey("security.dlp.transparent.crypto.status", "2");
    SetSelfTokenId(100);
    SetNativeTokenId(200);
    SetGetDockerPolicyResult(DLP_OK);
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00001;
    SetDockerPolicyInfo(info);
    AAFwk::Want want;
    EXPECT_TRUE(QueryDockerPolicyNeedSandbox("file://docs/test", want));
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
