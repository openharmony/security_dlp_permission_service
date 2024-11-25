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

#include "cleansandboxconfigstub_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_manager_adapter.h"
#include "bundle_mgr_interface.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
const int32_t DEFAULT_USERID = 100;
constexpr uint8_t STATUS_NUM = 2;

int32_t GetCallingUserId(void)
{
    return DEFAULT_USERID;
}
namespace OHOS {
namespace Security {
namespace DlpPermission {
bool BundleManagerAdapter::GetBundleInfo(const std::string &bundleName, int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    return true;
}
}
}
}
namespace OHOS {
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::CLEAN_SANDBOX_APP_CONFIG);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);

    MessageParcel datas1;
    datas1.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    MessageParcel reply1;
    MessageOption option1;
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service1->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service1->OnRemoteRequest(code, datas1, reply1, option1);
}

bool SetSandboxConfigFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetSandboxConfigFuzzTest(data, size);
    return 0;
}
