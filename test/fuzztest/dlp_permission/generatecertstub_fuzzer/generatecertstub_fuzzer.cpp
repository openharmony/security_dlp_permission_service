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

#include "generatecertstub_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "GenerateCertFuzzTest" };

static void FuzzTest(const uint8_t* data, size_t size)
{
    std::string name(reinterpret_cast<const char*>(data), size);
    auto seed = std::time(nullptr);
    std::srand(seed);
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    PermissionPolicy encPolicy;
    encPolicy.ownerAccount_ = name;
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    encPolicy.SetIv(nullptr, 0);
    encPolicy.SetAeskey(nullptr, 0);
    int userNum = rand() % (size + 1) + 1;
    DLP_LOG_INFO(LABEL, "before for:%{public}d,%{public}zu", userNum, size);
    for (int user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo;
        perminfo.authAccount = name;
        perminfo.authPerm = static_cast<DLPFileAccess>(1 + rand() % 3); // perm type 1 to 3
        perminfo.permExpiryTime = curTime + rand() % 200;              // time range 0 to 200
        perminfo.authAccountType = DOMAIN_ACCOUNT;
        encPolicy.authUsers_.emplace_back(perminfo);
    }
    DlpPolicyParcel parcel;
    parcel.policyParams_ = encPolicy;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionStub::GetDescriptor())) {
        return;
    }
    if (!datas.WriteParcelable(&parcel)) {
        return;
    }
    std::shared_ptr<GenerateDlpCertificateCallback> callback = std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (!datas.WriteRemoteObject(asyncStub->AsObject())) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(IDlpPermissionService::InterfaceCode::GENERATE_DLP_CERTIFICATE);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->OnRemoteRequest(code, datas, reply, option);
}

bool GenerateCertFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GenerateCertFuzzTest(data, size);
    return 0;
}
