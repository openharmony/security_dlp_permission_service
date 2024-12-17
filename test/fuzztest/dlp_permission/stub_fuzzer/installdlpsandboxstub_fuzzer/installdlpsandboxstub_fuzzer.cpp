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

#include "installdlpsandboxstub_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
const std::string TEST_URI = "datashare:///media/file/8";
constexpr uint32_t MIN_SIZE = 4 * sizeof(int32_t);
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    DLPFileAccess dlpFileAccess = static_cast<DLPFileAccess>(fdp.ConsumeIntegral<int32_t>());
    std::string uri = fdp.ConsumeBytesAsString(size - sizeof(int32_t) - sizeof(int32_t));
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    std::string  bundleName = "com.ohos.dlpmanager";
    if (!datas.WriteString(bundleName)) {
        return;
    }
    uint32_t type = static_cast<uint32_t>(dlpFileAccess);
    if (!datas.WriteUint32(type)) {
        return;
    }
    if (!datas.WriteInt32(userId)) {
        return;
    }
    if (!datas.WriteString(uri)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::INSTALL_DLP_SANDBOX);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

bool InstallDlpSandboxFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::InstallDlpSandboxFuzzTest(data, size);
    return 0;
}
