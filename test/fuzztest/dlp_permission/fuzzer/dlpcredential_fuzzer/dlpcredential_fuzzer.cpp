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
#include <memory>
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
#include "dlp_permission_client.h"
#include "dlp_utils.h"
#include "dlp_policy_mgr_client.h"


using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using Json = nlohmann::json;

namespace OHOS {
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string ENC_ACCOUNT_TYPE = "accountType";
const uint32_t BUFFER_LENGTH = 64;
const uint32_t HEX_BUFFER_LENGTH = 64;
static const uint8_t TWO = 2;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const uint8_t KEY_LEN = 16;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

class UnregisterOpenDlpFileCallbackFuzzer : public OpenDlpFileCallbackCustomize {
public:
    UnregisterOpenDlpFileCallbackFuzzer() {}
    ~UnregisterOpenDlpFileCallbackFuzzer() override {}

    void OnOpenDlpFile(OpenDlpFileCallbackInfo& result) override {}
};

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
    std::vector<std::string> appIdList;
    DlpCredential::GetInstance().SetMDMPolicy(appIdList);
    DlpCredential::GetInstance().GetMDMPolicy(appIdList);
    DlpCredential::GetInstance().RemoveMDMPolicy();
    std::string bundleName = fdp.ConsumeBytesAsString(size);
    DlpCredential::GetInstance().CheckMdmPermission(bundleName, fdp.ConsumeIntegral<int32_t>());
}

static DlpAccountType GenerateDlpAccountType(const uint8_t* data)
{
    int8_t typeNum = (data[0]/TWO + data[1]/TWO) % (sizeof(DlpAccountType) / sizeof(INVALID_ACCOUNT));
    if (typeNum == 0) {
        return DlpAccountType::DOMAIN_ACCOUNT;
    } else if (typeNum == 1) {
        return DlpAccountType::CLOUD_ACCOUNT;
    } else {
        return DlpAccountType::APPLICATION_ACCOUNT;
    }
}

static void GenerateRandStr(uint32_t len, const uint8_t *data, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = data[i] % ARRAY_CHAR_SIZE;
        res.push_back(CHAR_ARRAY[index]);
    }
}

static void ClientFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DlpPermissionClient::GetInstance().OnRemoteDiedHandle();
    DlpPermissionClient::GetInstance().FinishStartSAFail();
    std::shared_ptr<UnregisterOpenDlpFileCallbackFuzzer> callback =
        std::make_shared<UnregisterOpenDlpFileCallbackFuzzer>();
    DlpPermissionClient::GetInstance().UnRegisterOpenDlpFileCallback(callback);
    PermissionPolicy policy;
    policy.ownerAccount_ = fdp.ConsumeBytesAsString(size);
    policy.ownerAccountId_ = fdp.ConsumeBytesAsString(size);
    policy.ownerAccountType_ = GenerateDlpAccountType(data);
    uint32_t offset = 0;
    std::string iv;
    GenerateRandStr(KEY_LEN, data + offset, iv);
    policy.SetIv(reinterpret_cast<uint8_t*>(strdup(iv.c_str())), iv.length());
    std::string aes;
    GenerateRandStr(KEY_LEN, data + offset, aes);
    policy.SetIv(reinterpret_cast<uint8_t*>(strdup(aes.c_str())), aes.length());
    std::string hmac;
    GenerateRandStr(KEY_LEN, data + offset, hmac);
    policy.SetIv(reinterpret_cast<uint8_t*>(strdup(hmac.c_str())), hmac.length());
    std::shared_ptr<ClientGenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    DlpPermissionClient::GetInstance().GenerateDlpCertificate(policy, callback1);
}

static void GenerateDlpFileType(uint32_t data, std::string& filePath)
{
    if (data % TWO == 0) {
        filePath = "/data/file_test.txt";
    } else {
        filePath = "/data/file_test.jpg";
    }
}

static void UtilTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DlpUtils::GetBundleMgrProxy();
    std::string cfgFile = fdp.ConsumeBytesAsString(size);
    std::string type = fdp.ConsumeBytesAsString(size);
    std::vector<std::string> authPolicy;
    DlpUtils::GetAuthPolicyWithType(cfgFile, type, authPolicy);
    std::string srcFile;
    std::string filePath;
    GenerateDlpFileType(fdp.ConsumeIntegral<uint32_t>(), filePath);
    int fd = open(filePath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpUtils::GetFileNameWithFd(fd, srcFile);
    DlpUtils::GetRealTypeWithFd(fd);
    close(fd);
}

static PolicyType GenerateRandPolicyType(uint32_t data)
{
    if (data % TWO == 0) {
        return AUTHORIZED_APPLICATION_LIST;
    } else {
        return FILE_CLASSIFICATION_POLICY;
    }
}

static void CredentialClientFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    uint32_t policyLen = fdp.ConsumeIntegral<uint32_t>();
    PolicyType randType = GenerateRandPolicyType(policyLen);
    DLP_AddPolicy(randType, nullptr, policyLen);
    DLP_RemovePolicy(randType);
    DLP_GetPolicy(randType, nullptr, &policyLen);
    PolicyHandle handle;
    DLP_CheckPermission(randType, handle);
}

bool DlpCredentialFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    ClientFuzzTest(data, size);
    UtilTest(data, size);
    CredentialClientFuzzTest(data, size);
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
