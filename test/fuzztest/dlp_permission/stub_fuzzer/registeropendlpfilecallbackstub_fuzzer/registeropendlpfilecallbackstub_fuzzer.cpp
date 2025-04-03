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

#include "registeropendlpfilecallbackstub_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_service_ipc_interface_code.h"
#include "open_dlp_file_callback.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
constexpr u_int8_t STATUS_NUM = 2;

class RegisterOpenDlpFileCallbackStubFuzzer : public OpenDlpFileCallbackCustomize {
public:
    RegisterOpenDlpFileCallbackStubFuzzer() {}
    ~RegisterOpenDlpFileCallbackStubFuzzer() override {}

    void OnOpenDlpFile(OpenDlpFileCallbackInfo& result) override {}
};

namespace OHOS {
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

static void FuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    std::shared_ptr<OpenDlpFileCallbackCustomize> callback = std::make_shared<RegisterOpenDlpFileCallbackStubFuzzer>();
    sptr<OpenDlpFileCallback> asyncStub = new (std::nothrow) OpenDlpFileCallback(callback);
    if (!datas.WriteRemoteObject(asyncStub->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::REGISTER_OPEN_DLP_FILE_CALLBACK);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);

    MessageParcel datas1;
    datas1.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    std::shared_ptr<OpenDlpFileCallbackCustomize> callback1 = std::make_shared<RegisterOpenDlpFileCallbackStubFuzzer>();
    sptr<OpenDlpFileCallback> asyncStub1 = new (std::nothrow) OpenDlpFileCallback(callback1);
    if (!datas1.WriteRemoteObject(asyncStub1->AsObject())) {
        return;
    }
    MessageParcel reply1;
    MessageOption option1;
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service1->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service1->OnRemoteRequest(code, datas1, reply1, option1);
}

bool RegisterRegisterOpenDlpFileCallbackStubFuzzer(const uint8_t* data, size_t size)
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
    OHOS::RegisterRegisterOpenDlpFileCallbackStubFuzzer(data, size);
    return 0;
}
