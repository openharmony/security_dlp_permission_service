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

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const std::string DLP_TEST_DIR = "/data";
static const std::string LOGIN_EVENT = "Ohos.account.event.LOGIN";
static const std::string LOGOUT_EVENT = "Ohos.account.event.LOGOUT";
static constexpr int32_t MIN_LENGTH = 100;
static constexpr uint64_t MAX_CONTENT_SIZE = 0xffffffff;
static constexpr uint64_t TRUNC_SHORT = 10;
static constexpr uint64_t TRUNC_LONG = 100000;
static constexpr uint64_t OFFSET_SHORT = 20;
static constexpr uint64_t OFFSET_LONG = 111111;
static constexpr uint8_t ARRAY_CHAR_SIZE = 62;
static constexpr uint8_t TWO = 2;
static constexpr uint8_t ACCOUNT_LEN = 10;
static constexpr uint8_t BUFF_LEN = 10;
}

namespace OHOS {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "DlpFileFuzzTest" };
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;

static void GenerateRandStr(uint32_t len, const uint8_t *data, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = data[i] % ARRAY_CHAR_SIZE;
        res.push_back(CHAR_ARRAY[index]);
    }
}

static void GenerateProp(DlpProperty& prop, const std::string& account)
{
    prop.ownerAccount = account;
    prop.ownerAccountId = account;
    prop.contactAccount = account;
    prop.ownerAccountType = DlpAccountType::CLOUD_ACCOUNT;
    prop.offlineAccess = false;
    prop.supportEveryone = true;
    prop.everyonePerm = DLPFileAccess::FULL_CONTROL;
    prop.expireTime = 0;
    prop.actionUponExpiry = ActionType::OPEN;
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
    FuzzedDataProvider fdp(data, size);
    std::string account;
    size_t offset = 0;
    GenerateRandStr(ACCOUNT_LEN, data + offset, account);
    offset += ACCOUNT_LEN;
    DlpProperty prop;
    GenerateProp(prop, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGIN_EVENT);
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
    res = g_Dlpfile->RemoveDlpPermission(recoveryFileFd);
    DLP_LOG_INFO(LABEL, "RemoveDlpPermission res=%{public}d", res);
    g_Dlpfile->Truncate(MAX_CONTENT_SIZE);
    g_Dlpfile->Truncate(TRUNC_SHORT);
    g_Dlpfile->Truncate(TRUNC_LONG);
    std::string bufdata;
    GenerateRandStr(BUFF_LEN, data + offset, bufdata);
    void* bufData = reinterpret_cast<void*>(strdup(bufdata.c_str()));
    uint32_t bufLen = bufdata.length();
    g_Dlpfile->DlpFileWrite(MAX_CONTENT_SIZE, bufData, bufLen);
    g_Dlpfile->DlpFileWrite(OFFSET_SHORT, bufData, bufLen);
    g_Dlpfile->DlpFileWrite(OFFSET_LONG, bufData, bufLen);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    free(bufData);
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
    FuzzedDataProvider fdp(data, size);
    std::string account;
    size_t offset = 0;
    GenerateRandStr(ACCOUNT_LEN, data + offset, account);
    offset += ACCOUNT_LEN;
    DlpProperty prop;
    GenerateProp(prop, account);
    AccountSA::OhosAccountKits::GetInstance().UpdateOhosAccountInfo(account, account, LOGIN_EVENT);
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
    res = g_Dlpfile->RemoveDlpPermission(recoveryFileFd);
    DLP_LOG_INFO(LABEL, "RemoveDlpPermission res=%{public}d", res);
    g_Dlpfile->Truncate(MAX_CONTENT_SIZE);
    g_Dlpfile->Truncate(TRUNC_SHORT);
    g_Dlpfile->Truncate(TRUNC_LONG);
    std::string bufdata;
    GenerateRandStr(BUFF_LEN, data + offset, bufdata);
    void* bufData = reinterpret_cast<void*>(strdup(bufdata.c_str()));
    uint32_t bufLen = bufdata.length();
    g_Dlpfile->DlpFileWrite(MAX_CONTENT_SIZE, bufData, bufLen);
    g_Dlpfile->DlpFileWrite(OFFSET_SHORT, bufData, bufLen);
    g_Dlpfile->DlpFileWrite(OFFSET_LONG, bufData, bufLen);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    free(bufData);
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
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(100, "com.ohos.dlpmanager", 0); // user_id = 100
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DlpFileFuzzTest(data, size);
    return 0;
}
