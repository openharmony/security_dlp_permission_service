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
#define private public
#include "dlp_permission_client.h"
#undef private
#include "dlp_utils.h"
#include "dlp_utils.cpp"
#include "dlp_policy_mgr_client.h"
#include "dlp_zip.h"


using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using Json = nlohmann::json;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
} // namespace

namespace OHOS {
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string ENC_ACCOUNT_TYPE = "accountType";
const uint32_t BUFFER_LENGTH = 64;
const uint32_t HEX_BUFFER_LENGTH = 64;
static const uint8_t ONE = 1;
static const uint8_t TWO = 2;
static const uint8_t FOUR = 4;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const uint8_t KEY_LEN = 16;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const std::string DLP_AUTH_POLICY = "/system/etc/dlp_auth_policy.json";
static const std::string DLP_FILE = "dlp_auth_policy.txt.dlp";
static const std::string DLP_HIAE_TYPE = "mkv";
static const uint32_t STRING_LENGTH = 10;

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
    std::string policy = fdp.ConsumeBytesAsString(size / FOUR - ONE);
    std::string account = fdp.ConsumeBytesAsString(size / FOUR - ONE);
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
    std::string appId = fdp.ConsumeBytesAsString(size / FOUR - ONE);
    AppExecFwk::ApplicationInfo applicationInfo;
    DlpCredential::GetInstance().ParseDlpCertificate(certParcel, callback2, appId, true, applicationInfo);
    std::vector<std::string> appIdList;
    DlpCredential::GetInstance().SetMDMPolicy(appIdList);
    DlpCredential::GetInstance().GetMDMPolicy(appIdList);
    DlpCredential::GetInstance().RemoveMDMPolicy();
    std::string bundleName = fdp.ConsumeBytesAsString(size / FOUR - ONE);
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
    std::shared_ptr<UnregisterOpenDlpFileCallbackFuzzer> callback = nullptr;
    (void)DlpPermissionClient::GetInstance().UnRegisterOpenDlpFileCallback(callback);
    (void)DlpPermissionClient::GetInstance().RegisterOpenDlpFileCallback(callback);
    callback = std::make_shared<UnregisterOpenDlpFileCallbackFuzzer>();
    DlpPermissionClient::GetInstance().UnRegisterOpenDlpFileCallback(callback);
    PermissionPolicy policy;
    policy.ownerAccount_ = fdp.ConsumeBytesAsString(size / TWO);
    policy.ownerAccountId_ = fdp.ConsumeBytesAsString(size / TWO);
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

    FileInfo fileInfo;
    fileInfo.isNotOwnerAndReadOnce = true;
    std::string uri = "";
    (void)DlpPermissionClient::GetInstance().SetFileInfo(uri, fileInfo);
    uri = "uri";
    fileInfo.isNotOwnerAndReadOnce = false;
    (void)DlpPermissionClient::GetInstance().SetFileInfo(uri, fileInfo);

    sptr<IRemoteObject> remoteObject;
    DlpPermissionClient::GetInstance().GetProxyFromRemoteObject(nullptr);
    DlpPermissionClient::GetInstance().GetProxyFromRemoteObject(remoteObject);

    std::string policyStr = "policy";
    (void)DlpPermissionClient::GetInstance().SetEnterprisePolicy(policyStr);

    uint32_t dlpFeatureInfo = 0;
    bool statusSetInfo;
    (void)DlpPermissionClient::GetInstance().SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    dlpFeatureInfo = 1;
    (void)DlpPermissionClient::GetInstance().SetDlpFeature(dlpFeatureInfo, statusSetInfo);
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
    std::string cfgFile = fdp.ConsumeBytesAsString(size / FOUR - TWO);
    std::string type = fdp.ConsumeBytesAsString(size / FOUR - TWO);
    std::vector<std::string> authPolicy;
    DlpUtils::GetAuthPolicyWithType(cfgFile, type, authPolicy);
    DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, type, authPolicy);
    std::string srcFile;
    std::string filePath;
    GenerateDlpFileType(fdp.ConsumeIntegral<uint32_t>(), filePath);
    int fd = open(filePath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpUtils::GetFileNameWithFd(fd, srcFile);
    bool isFromUriName = false;
    std::string generateInfoStr;
    DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr);
    std::string dlpFile;
    DlpUtils::GetFileNameWithDlpFd(fd, dlpFile);
    DlpUtils::GetFileType(DLP_HIAE_TYPE);
    std::string str = fdp.ConsumeBytesAsString(size / FOUR - TWO);
    DlpUtils::ToLowerString(str);
    std::string suffix = fdp.ConsumeBytesAsString(size / FOUR - TWO);
    DlpUtils::GetFileTypeBySuffix(str, true);
    DlpUtils::GetFileTypeBySuffix(str, false);
    std::string path;
    DlpUtils::GetFilePathWithFd(fd, path);
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

static void DLPUtilTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    bool isFromUriName;
    std::string dlpFileName = fdp.ConsumeBytesAsString(STRING_LENGTH) + DLP_FILE;
    (void)DlpUtils::GetDlpFileRealSuffix(dlpFileName, isFromUriName);
    std::string dlpFileName = fdp.ConsumeBytesAsString(STRING_LENGTH);
    (void)DlpUtils::GetDlpFileRealSuffix(dlpFileName, isFromUriName);

    (void)IsExistFile(fdp.ConsumeBytesAsString(STRING_LENGTH));
    (void)GetFileContent(fdp.ConsumeBytesAsString(STRING_LENGTH));
    dlpFileName = DLP_AUTH_POLICY;
    (void)GetFileContent(dlpFileName);
    dlpFileName = "";
    (void)RemoveCachePath(dlpFileName);
    int32_t fd = -1;
    (void)GetGenerateInfoStr(fd);

    int32_t allowedOpenCount = 0;
    bool waterMarkConfig = fdp.ConsumeBool(fd, allowedOpenCount, waterMarkConfig);
    (void)DlpUtils::GetRawFileAllowedOpenCount(fd, allowedOpenCount, waterMarkConfig);
    dlpFileName = fdp.ConsumeBytesAsString(STRING_LENGTH);
    (void)DlpUtils::GetExtractRealType(dlpFileName);
    dlpFileName = fdp.ConsumeBytesAsString(STRING_LENGTH);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    (void)DlpUtils::GetAppIdentifierByAppId(dlpFileName, userId);

}

bool DlpCredentialFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    ClientFuzzTest(data, size);
    UtilTest(data, size);
    CredentialClientFuzzTest(data, size);
    DLPUtilTest(data, size);
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
    OHOS::DlpCredentialFuzzTest(data, size);
    return 0;
}
