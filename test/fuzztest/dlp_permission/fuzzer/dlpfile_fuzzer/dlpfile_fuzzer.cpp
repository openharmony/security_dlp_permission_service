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
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace {
static const int ACCOUNT_NAME_SIZE = 20;
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
static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const int32_t TEST_USER_COUNT = 1;
static const int32_t EXPIRT_TIME = 10000;
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static const std::string TEST_APPID = "test_appId_passed";
static std::string g_eventLogin = "Ohos.account.event.LOGIN";
static const int32_t ARRRY_SIZE = 3;

static void GenerateRandProperty(struct DlpProperty& encProp, const uint8_t* data, size_t size)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    encProp.ownerAccount = DEFAULT_CURRENT_ACCOUNT;
    encProp.ownerAccountId = DEFAULT_CURRENT_ACCOUNT;
    encProp.ownerAccountType = DlpAccountType::CLOUD_ACCOUNT;
    for (uint32_t user = 0; user < TEST_USER_COUNT; ++user) {
        std::string accountName = "testaccountName";
        AuthUserInfo perminfo = {.authAccount = strdup(const_cast<char *>(accountName.c_str())),
            .authPerm = READ_ONLY,
            .permExpiryTime = curTime + EXPIRT_TIME,
            .authAccountType = DlpAccountType::CLOUD_ACCOUNT};
        encProp.authUsers.emplace_back(perminfo);
    }
    std::string accountName  = DEFAULT_CURRENT_ACCOUNT;
    encProp.contactAccount = strdup(const_cast<char *>(accountName.c_str()));
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    int plainFileFd = open("/data/file_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    int dlpFileFd = open("/data/file_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    char buffer[] = "123456";
    write(plainFileFd, buffer, sizeof(buffer));
    struct DlpProperty prop;
    GenerateRandProperty(prop, data, size);
    int32_t res = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd,
        dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR);
    DLP_LOG_INFO(LABEL, "GenerateDlpFile res=%{public}d", res);
    int recoveryFileFd = open("/data/fuse_test.txt.recovery",
        O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, recoveryFileFd);
    DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    res = DlpFileManager::GetInstance().OpenDlpFile(dlpFileFd, g_Dlpfile, DLP_TEST_DIR, TEST_APPID);
    DLP_LOG_INFO(LABEL, "OpenDlpFile res=%{public}d", res);
    g_Dlpfile->DlpFileWrite(0, const_cast<void*>(reinterpret_cast<const void*>(data)), size);
    uint8_t writeBuffer[ARRRY_SIZE] = {0x1};
    g_Dlpfile->DlpFileRead(0, writeBuffer, ARRRY_SIZE);
}

bool DlpFileFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0);  // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DlpFileFuzzTest(data, size);
    return 0;
}
