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

#include "dlpfile_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <fcntl.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_credential_client_defines.h"
#include "dlp_file_manager.h"
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
namespace {
static const int ACCOUNT_NAME_SIZE = 20;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static std::string g_accountName = "ohosAnonymousName";
static const std::string DLP_SUFFIX = ".dlp";
}

static void GenerateRandStr(uint32_t len, const uint8_t *data, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = data[i] % ARRAY_CHAR_SIZE;
        res.push_back(CHAR_ARRAY[index]);
    }
}

bool IsAccountLogIn(uint32_t osAccountId, AccountType accountType, const DlpBlob* accountId)
{
    return true;
}

int8_t GetLocalAccountName(char** account, uint32_t userId)
{
    if (account == nullptr) {
        return -1;
    }
    *account = static_cast<char*>(malloc(ACCOUNT_NAME_SIZE * sizeof(char)));
    strcpy_s(*account, sizeof(**account), "ohosAnonymousName");
    return 0;
}

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "DlpFileFuzzTest" };
static const int32_t TEST_USER_COUNT = 1;
static const int32_t EXPIRT_TIME = 10000;
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
static const std::string DLP_TEST_DIR = "/data";
static const int32_t ARRRY_SIZE = 3;
static const std::string LOGIN_EVENT = "Ohos.account.event.LOGIN";
static const std::string LOGOUT_EVENT = "Ohos.account.event.LOGOUT";
static const int32_t TWO = 2;
static const int32_t FIVE = 5;
const int32_t TEXT_LENGTH = 5;
const int32_t ACCOUNT_LENGTH = 10;
const int32_t APPID_LENGTH = 30;
constexpr int32_t MIN_LENGTH = APPID_LENGTH + TEXT_LENGTH + ACCOUNT_LENGTH * 2 + 100;

static DlpAccountType GenerateDlpAccountType(const uint8_t* data)
{
    int8_t typeNum = (data[0]/TWO + data[1]/TWO) % (sizeof(DlpAccountType) / sizeof(INVALID_ACCOUNT));
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

static DLPFileAccess GenerateDLPFileAccess(const uint8_t* data)
{
    int8_t fileAccess = (data[0]/TWO + data[1]/TWO) % (sizeof(DLPFileAccess) / sizeof(DLPFileAccess::NO_PERMISSION));
    if (fileAccess == 0) {
        return DLPFileAccess::NO_PERMISSION;
    } else if (fileAccess == 1) {
        return DLPFileAccess::READ_ONLY;
    } else if (fileAccess == TWO) {
        return DLPFileAccess::CONTENT_EDIT;
    } else {
        return DLPFileAccess::FULL_CONTROL;
    }
}

static void GenerateDlpFileType(std::string& filePath, const uint8_t* data)
{
    int8_t realType = (data[0] / TWO + data[1] / TWO) % TWO;
    if (realType == 0) {
        filePath = "/data/file_test.txt";
    } else {
        filePath = "/data/file_test.jpg";
    }
}

static void GenerateRandProperty(struct DlpProperty& encProp, const uint8_t* data, size_t size)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string account;
    GenerateRandStr(ACCOUNT_LENGTH, data, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGOUT_EVENT);
    uint32_t offset = ACCOUNT_LENGTH;
    encProp.ownerAccount = account;
    encProp.ownerAccountId = account;
    std::string contactAccount = account;
    encProp.contactAccount = strdup(const_cast<char *>(contactAccount.c_str()));
    if (size % TWO == 0) {
        std::string testAccount;
        GenerateRandStr(ACCOUNT_LENGTH, data + offset, testAccount);
        g_accountName = testAccount;
    } else {
        g_accountName = account;
    }
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(g_accountName, g_accountName, LOGIN_EVENT);
    encProp.ownerAccountType = DlpAccountType::CLOUD_ACCOUNT;
    if (size % FIVE == 0) {
        encProp.supportEveryone = true;
        encProp.everyonePerm = DLPFileAccess::CONTENT_EDIT;
    }
    for (uint32_t user = 0; user < TEST_USER_COUNT; ++user) {
        std::string accountName = account + std::to_string(user);
        AuthUserInfo perminfo = {.authAccount = strdup(const_cast<char *>(accountName.c_str())),
            .authPerm = DLPFileAccess::READ_ONLY,
            .permExpiryTime = curTime + EXPIRT_TIME,
            .authAccountType = DlpAccountType::CLOUD_ACCOUNT};
        encProp.authUsers.emplace_back(perminfo);
    }
}

static void GenerateRandPropertyRand(struct DlpProperty& encProp, const uint8_t* data, size_t size)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::string account;
    GenerateRandStr(ACCOUNT_LENGTH, data, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGOUT_EVENT);
    uint32_t offset = ACCOUNT_LENGTH;
    encProp.ownerAccount = account;
    encProp.ownerAccountId = account;
    std::string contactAccount = account;
    encProp.contactAccount = strdup(const_cast<char *>(contactAccount.c_str()));
    if (size % TWO == 0) {
        std::string testAccount;
        GenerateRandStr(ACCOUNT_LENGTH, data + offset, testAccount);
        g_accountName = testAccount;
    } else {
        g_accountName = account;
    }
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(g_accountName, g_accountName, LOGIN_EVENT);
    encProp.ownerAccountType = GenerateDlpAccountType(data);
    if (size % FIVE == 0) {
        encProp.supportEveryone = true;
        encProp.everyonePerm = DLPFileAccess::CONTENT_EDIT;
    }
    for (uint32_t user = 0; user < TEST_USER_COUNT; ++user) {
        std::string accountName = account + std::to_string(user);
        AuthUserInfo perminfo = {.authAccount = strdup(const_cast<char *>(accountName.c_str())),
            .authPerm = GenerateDLPFileAccess(data),
            .permExpiryTime = curTime + EXPIRT_TIME,
            .authAccountType = GenerateDlpAccountType(data)};
        encProp.authUsers.emplace_back(perminfo);
    }
}

static void UpdateCertAndTextFuzzTest(DlpBlob offlineCert, const uint8_t* data, size_t size)
{
    std::vector<uint8_t> cert;
    g_Dlpfile->UpdateCertAndText(cert, offlineCert);
}

static void GDlpFileFuzzTest()
{
    g_Dlpfile->GetOfflineAccess();
    g_Dlpfile->NeedAdapter();
    g_Dlpfile->GetFsContentSize();
    g_Dlpfile->HmacCheck();
}

static void UnzipSpecificFileFUZZ(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    UnzipSpecificFile(fdp.ConsumeIntegral<int32_t>(), fdp.ConsumeBytesAsString(size).c_str(),
        fdp.ConsumeBytesAsString(size).c_str());
}

static void FuzzTest(const uint8_t* data, size_t size, bool flag)
{
    if ((data == nullptr) || (size <= sizeof(uint8_t) * MIN_LENGTH)) {
        return;
    }
    std::string filePath;
    GenerateDlpFileType(filePath, data);
    std::string dlpFilePath = filePath + DLP_SUFFIX;
    int plainFileFd = open(filePath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    int dlpFileFd = open(dlpFilePath.c_str(), O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    std::string text;
    std::string account;
    DlpBlob cert;
    DlpBlob offlineCert;
    GenerateRandStr(TEXT_LENGTH, data, text);
    uint32_t offset = TEXT_LENGTH;
    std::string appId = "test_appId_passed";
    write(plainFileFd, text.c_str(), text.length());
    struct DlpProperty prop;
    if (flag) {
        GenerateRandProperty(prop, data + offset, size - offset);
    } else {
        GenerateRandPropertyRand(prop, data + offset, size - offset);
    }
    int32_t res = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd,
        dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR);
    DLP_LOG_INFO(LABEL, "GenerateDlpFile res=%{public}d", res);
    int recoveryFileFd = open("/data/fuse_test.txt.recovery",
        O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    res = DlpFileManager::GetInstance().OpenDlpFile(dlpFileFd, g_Dlpfile, DLP_TEST_DIR, appId);
    DLP_LOG_INFO(LABEL, "OpenDlpFile res=%{public}d", res);
    g_Dlpfile->UpdateDlpFilePermission();
    DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, recoveryFileFd);
    g_Dlpfile->DlpFileWrite(0, const_cast<char *>(text.c_str()), text.length());
    uint8_t writeBuffer[ARRRY_SIZE] = {0x1};
    bool hasRead = true;
    Security::DlpPermission::CheckUnzipFileInfo(dlpFileFd);
    GDlpFileFuzzTest();
    g_Dlpfile->GetEncryptCert(cert);
    g_Dlpfile->GetOfflineCert(offlineCert);
    g_Dlpfile->GetOfflineCertSize();
    g_Dlpfile->DlpFileRead(0, writeBuffer, ARRRY_SIZE, hasRead, 0);
    g_Dlpfile->Truncate(ARRRY_SIZE);
    UpdateCertAndTextFuzzTest(offlineCert, data, size);
    close(plainFileFd);
    close(dlpFileFd);
    close(recoveryFileFd);
}

bool DlpFileFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size, true);
    FuzzTest(data, size, false);
    UnzipSpecificFileFUZZ(data, size);
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
