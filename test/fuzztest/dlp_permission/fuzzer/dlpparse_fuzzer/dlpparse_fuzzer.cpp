/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlpparse_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_credential_client_defines.h"
#define private public
#include "dlp_file_manager.h"
#include "dlp_file.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_kit.h"
#include "ohos_account_kits.h"
#include "securec.h"
#include "system_ability_definition.h"
#include "token_setproc.h"
#include "dlp_zip.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "DlpFileFuzzTest" };
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
static const std::string DLP_TEST_DIR = "/data";
static const std::string LOGIN_EVENT = "Ohos.account.event.LOGIN";
static const std::string LOGOUT_EVENT = "Ohos.account.event.LOGOUT";
constexpr int32_t MIN_LENGTH = 100;
static const uint64_t TRUNC_LEN = 10000;
static const uint64_t OFFSET_LEN = 11111;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const uint8_t TWO = 2;
static const uint8_t ACCOUNT_LEN = 10;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

static void GenerateRandStr(uint32_t len, const uint8_t *data, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = data[i] % ARRAY_CHAR_SIZE;
        res.push_back(CHAR_ARRAY[index]);
    }
}

static DlpAccountType GenerateDlpAccountType(const uint8_t* data)
{
    int8_t typeNum = (data[0] / TWO + data[1] / TWO) % (sizeof(DlpAccountType) / sizeof(INVALID_ACCOUNT));
    if (typeNum == 0) {
        return DlpAccountType::INVALID_ACCOUNT;
    } else if (typeNum == 1) {
        return DlpAccountType::CLOUD_ACCOUNT;
    } else if (typeNum == TWO) {
        return DlpAccountType::DOMAIN_ACCOUNT;
    } else {
        return DlpAccountType::APPLICATION_ACCOUNT;
    }
}

static void RawFileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= sizeof(uint8_t) * MIN_LENGTH)) {
        return;
    }
    int plainFileFd = open("/data/file_test.jpg", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    int dlpFileFd = open("/data/file_test.jpg.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    std::string text = "text";
    write(plainFileFd, text.c_str(), text.length());
    std::string appId = "test_appId_passed";
    struct DlpProperty prop;
    FuzzedDataProvider fdp(data, size);
    std::string account;
    GenerateRandStr(ACCOUNT_LEN, data, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGIN_EVENT);
    prop.ownerAccount = account;
    prop.ownerAccountId = account;
    prop.contactAccount = account;
    prop.ownerAccountType = GenerateDlpAccountType(data);
    prop.offlineAccess = false;
    prop.supportEveryone = true;
    prop.everyonePerm = DLPFileAccess::FULL_CONTROL;
    prop.expireTime = 0;
    prop.actionUponExpiry = ActionType::OPEN;
    DlpFileManager::DlpFileMes dlpFileMes = {
        .plainFileFd = plainFileFd,
        .dlpFileFd = dlpFileFd,
        .realFileType = "jpg",
    };
    int32_t res = DlpFileManager::GetInstance().GenRawDlpFile(dlpFileMes, prop, g_Dlpfile);
    DLP_LOG_INFO(LABEL, "GenerateDlpFile res=%{public}d", res);
    int recoveryFileFd = open("/data/file_test.jpg.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    res = DlpFileManager::GetInstance().OpenRawDlpFile(dlpFileFd, g_Dlpfile, appId, "jpg");
    DLP_LOG_INFO(LABEL, "OpenRawDlpFile res=%{public}d", res);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGOUT_EVENT);
    g_Dlpfile->authPerm_ = DLPFileAccess::FULL_CONTROL;
    uint64_t arraySize = TRUNC_LEN;
    g_Dlpfile->Truncate(arraySize);
    uint64_t offset = OFFSET_LEN;
    std::string bufdata = "bufdata";
    void* buf = reinterpret_cast<void*>(strdup(bufdata.c_str()));
    uint32_t bufLen = bufdata.length();
    g_Dlpfile->DlpFileWrite(offset, buf, bufLen);
    g_Dlpfile->RemoveDlpPermission(recoveryFileFd);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    free(buf);
    close(plainFileFd);
    close(dlpFileFd);
    close(recoveryFileFd);
}

static void ZipFileFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= sizeof(uint8_t) * MIN_LENGTH)) {
        return;
    }
    int plainFileFd = open("/data/file_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    int dlpFileFd = open("/data/file_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    std::string text = "text";
    write(plainFileFd, text.c_str(), text.length());
    std::string appId = "test_appId_passed";
    struct DlpProperty prop;
    FuzzedDataProvider fdp(data, size);
    std::string account;
    GenerateRandStr(ACCOUNT_LEN, data, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGIN_EVENT);
    prop.ownerAccount = account;
    prop.ownerAccountId = account;
    prop.contactAccount = account;
    prop.ownerAccountType = GenerateDlpAccountType(data);
    prop.offlineAccess = false;
    prop.supportEveryone = true;
    prop.everyonePerm = DLPFileAccess::FULL_CONTROL;
    prop.expireTime = 0;
    prop.actionUponExpiry = ActionType::OPEN;
    DlpFileManager::DlpFileMes dlpFileMes = {
        .plainFileFd = plainFileFd,
        .dlpFileFd = dlpFileFd,
        .realFileType = "txt",
    };
    int32_t res = DlpFileManager::GetInstance().GenZipDlpFile(dlpFileMes, prop, g_Dlpfile, DLP_TEST_DIR);
    DLP_LOG_INFO(LABEL, "GenerateDlpFile res=%{public}d", res);
    int recoveryFileFd = open("/data/file_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    res = DlpFileManager::GetInstance().OpenZipDlpFile(dlpFileFd, g_Dlpfile, DLP_TEST_DIR, appId, "txt");
    DLP_LOG_INFO(LABEL, "OpenZipDlpFile res=%{public}d", res);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGOUT_EVENT);
    g_Dlpfile->authPerm_ = DLPFileAccess::FULL_CONTROL;
    uint64_t arraySize = TRUNC_LEN;
    g_Dlpfile->Truncate(arraySize);
    uint64_t offset = OFFSET_LEN;
    std::string bufdata = "bufdata";
    void* buf = reinterpret_cast<void*>(strdup(bufdata.c_str()));
    uint32_t bufLen = bufdata.length();
    g_Dlpfile->DlpFileWrite(offset, buf, bufLen);
    g_Dlpfile->RemoveDlpPermission(recoveryFileFd);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    free(buf);
    close(plainFileFd);
    close(dlpFileFd);
    close(recoveryFileFd);
}

bool DlpFileFuzzTest(const uint8_t* data, size_t size)
{
    RawFileFuzzTest(data, size);
    ZipFileFuzzTest(data, size);
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
    OHOS::DlpFileFuzzTest(data, size);
    return 0;
}
