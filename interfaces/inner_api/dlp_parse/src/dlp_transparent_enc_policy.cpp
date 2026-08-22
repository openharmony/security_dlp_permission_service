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

#include "dlp_transparent_enc_policy.h"

#ifdef DLP_PERMISSION_SERVICE_PC_FEATURE

#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_transparent_enc_manager.h"
#include "dlp_utils.h"
#include "ipc_skeleton.h"
#include "parameters.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
    "DlpTransparentEncPolicy"};
static const std::string VERSION_FOR_2B = "1";
static const char *TRANSPARENT_CRYPTO_STATUS_KEY = "security.dlp.transparent.crypto.status";
static const std::string DLP_CREDENTIAL_SA_NAME = "dlp_credential_service";
static const std::string DLP_PARAMS_CUSTOM_FLAG = "ohos.dlp.params.customFlag";
static bool IsEnterprisePlatform()
{
    std::string value = OHOS::system::GetParameter("const.dlp.functiontypes", "0");
    return value == VERSION_FOR_2B;
}

static bool IsDlpCredentialSa()
{
    Security::AccessToken::AccessTokenID selfToken = IPCSkeleton::GetSelfTokenID();
    Security::AccessToken::AccessTokenID credentialToken =
        Security::AccessToken::AccessTokenKit::GetNativeTokenId(DLP_CREDENTIAL_SA_NAME);
    return selfToken == credentialToken;
}

static bool IsTransparentCryptoReady()
{
    std::string value = OHOS::system::GetParameter(TRANSPARENT_CRYPTO_STATUS_KEY, "");
    // "1" = READY_NO_CHANGE, "2" = READY_NEED_CHANGE
    return value == "1" || value == "2";
}
}  // namespace

static bool IsEnvironmentValid(const AAFwk::Want &want)
{
    if (!IsEnterprisePlatform()) {
        DLP_LOG_ERROR(LABEL, "Not enterprise platform, skip docker policy query");
        return false;
    }
    if (IsDlpCredentialSa()) {
        DLP_LOG_ERROR(LABEL, "Current process is dlp_credential SA, skip docker policy query");
        return false;
    }
    if (!IsTransparentCryptoReady()) {
        DLP_LOG_ERROR(LABEL, "Transparent crypto not ready, skip docker policy query");
        return false;
    }
    return true;
}

static bool CheckEnterpriseEncryptedFile(const DockerPolicyInfo &dockerPolicy, AAFwk::Want &want)
{
    if (!dockerPolicy.isEncrypted) {
        DLP_LOG_ERROR(LABEL, "Docker policy isEncrypted is false");
        return false;
    }
    want.SetType(std::to_string(dockerPolicy.mimeType));
    if (!dockerPolicy.needSandbox) {
        DLP_LOG_ERROR(LABEL, "Docker policy needSandbox is false");
        return false;
    }
    want.SetParam(DLP_PARAMS_CUSTOM_FLAG, true);
    DLP_LOG_INFO(LABEL, "Docker policy needSandbox is true");
    return true;
}

//
bool QueryDockerPolicyNeedSandbox(const std::string &uri, AAFwk::Want &want)
{
    if (!IsEnvironmentValid(want)) {
        return false;
    }
    DockerPolicyInfo dockerPolicy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy(uri, dockerPolicy);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetDockerPolicy failed, ret=%{public}d", ret);
        return false;
    }
    return CheckEnterpriseEncryptedFile(dockerPolicy, want);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#else

namespace OHOS {
namespace Security {
namespace DlpPermission {

bool QueryDockerPolicyNeedSandbox(const std::string &path, AAFwk::Want &want)
{
    return false;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif