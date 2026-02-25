/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "watermarkproxy_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include "ability_info.h"
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"
#include "want.h"
#include "dlp_permission_service_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "iremote_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace {
static constexpr int32_t DLP_PERMISSION_SERVICE_SA_ID = 3521;
constexpr int32_t SA_LOAD_TIME = 4 * 1000;
const uint32_t BUFFER_LENGTH = 64;
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
}

namespace OHOS {
class GenerateDlpCertificateFuzzerTest : public IRemoteStub<IDlpPermissionCallback> {
public:
    GenerateDlpCertificateFuzzerTest() {}
    ~GenerateDlpCertificateFuzzerTest() override {}

    void OnGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override {};
    void OnParseDlpCertificate(int32_t result, const PermissionPolicy& policy,
        const std::vector<uint8_t>& cert) override {};
    void OnGetDlpWaterMark(int32_t result, const GeneralInfo& info) override {};
};
static sptr<DlpPermissionServiceProxy> GetProxy()
{
    auto saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        return nullptr;
    }
    auto daSa = saMgr->CheckSystemAbility(DLP_PERMISSION_SERVICE_SA_ID);
    if (daSa != nullptr) {
        return iface_cast<DlpPermissionServiceProxy>(daSa);
    }
    daSa = saMgr->LoadSystemAbility(DLP_PERMISSION_SERVICE_SA_ID, SA_LOAD_TIME);
    if (daSa == nullptr) {
        return nullptr;
    }
    return iface_cast<DlpPermissionServiceProxy>(daSa);
}
static void WaterMarkFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    sptr<DlpPermissionServiceProxy> proxy = GetProxy();
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> callbackRemote;
    sptr<GenerateDlpCertificateFuzzerTest> dlpPermissionCallback =
        new (std::nothrow) GenerateDlpCertificateFuzzerTest();
    if (dlpPermissionCallback == nullptr) {
        return;
    }
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    proxy->GetWaterMark(true, nullptr);
    proxy->GetWaterMark(false, nullptr);
    proxy->GetWaterMark(false, dlpPermissionCallback);
    proxy->GetWaterMark(true, dlpPermissionCallback);
    proxy->SetWaterMark(pid);
    proxy->UnRegisterOpenDlpFileCallback(callbackRemote);
    std::string accountNameInfo;
    proxy->GetDomainAccountNameInfo(accountNameInfo);
    OHOS::AAFwk::Want want;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    proxy->GetAbilityInfos(want, flags, userId, abilityInfos);
}

bool PermissionProxyFuzzer(const uint8_t* data, size_t size)
{
    WaterMarkFuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::PermissionProxyFuzzer(data, size);
    return 0;
}
