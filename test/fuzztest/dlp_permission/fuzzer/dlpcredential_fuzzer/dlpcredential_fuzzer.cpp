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

#include "dlpcredential_fuzzer.h"
#include <dlfcn.h>
#include <iostream>
#include <fcntl.h>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "dlp_file.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "nlohmann/json.hpp"
#include "securec.h"
#include "token_setproc.h"
#include "hex_string.h"
#include "dlp_credential.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using Json = nlohmann::json;

namespace OHOS {
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string ENC_ACCOUNT_TYPE = "accountType";
const uint32_t BUFFER_LENGTH = 30;
const uint32_t HEX_BUFFER_LENGTH = 64;

static void InitCertJson(const uint8_t* data, size_t size, Json &certJson)
{
    certJson[ENC_DATA_LEN] = size;
    char hexStrBuffer[HEX_BUFFER_LENGTH] = {0};
    uint8_t byteBuffer[BUFFER_LENGTH] = {0};
    for (uint32_t i = 0; i < BUFFER_LENGTH; i++) {
        byteBuffer[i] = *(reinterpret_cast<const uint8_t*>(data + i));
    }
    int res = ByteToHexString(byteBuffer, sizeof(byteBuffer), hexStrBuffer, sizeof(hexStrBuffer));
    if (res != DLP_OK) {
        return;
    }
    certJson[ENC_DATA] = hexStrBuffer;
    certJson[ENC_ACCOUNT_TYPE] = DlpAccountType::CLOUD_ACCOUNT;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }

    std::shared_ptr<GenerateDlpCertificateCallback> callback =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback1 = new (std::nothrow) DlpPermissionAsyncStub(callback);
    FuzzedDataProvider fdp(data, size);
    std::string policy = fdp.ConsumeBytesAsString(size);
    std::string account = fdp.ConsumeBytesAsString(size);
    DlpAccountType accountType = DlpAccountType::CLOUD_ACCOUNT;
    DlpCredential::GetInstance().GenerateDlpCertificate(policy, account, accountType, callback1);

    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    Json certJson;
    InitCertJson(data, size, certJson);
    std::string certStr = certJson.dump();
    std::vector<uint8_t> cert;
    cert.assign(certStr.begin(), certStr.end());
    certParcel->cert = cert;
    sptr<IDlpPermissionCallback> callback2;
    std::string appId = fdp.ConsumeBytesAsString(size);
    AppExecFwk::ApplicationInfo applicationInfo;
    DlpCredential::GetInstance().ParseDlpCertificate(certParcel, callback2, appId, true, applicationInfo);
}

bool DlpCredentialFuzzTest(const uint8_t* data, size_t size)
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
    OHOS::DlpCredentialFuzzTest(data, size);
    return 0;
}
