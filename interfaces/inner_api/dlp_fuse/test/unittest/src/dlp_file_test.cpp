/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlp_file_test.h"

#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <securec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include "dlp_file.h"
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileTest"};
// using for clean all link file
static const std::string MOUNT_POINT_DIR = "/data/fuse/";
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static const std::string FUSE_DEV = "/dev/fuse";
static const std::string FUSE_TYPE = "fuse";
static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const int32_t TEST_USER_COUNT = 2;
static const int32_t RAND_STR_SIZE = 16;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int32_t EXPIRT_TIME = 10000;
static int g_plainFileFd = -1;
static int g_dlpFileFd = -1;
static int g_recoveryFileFd = -1;
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
}

void DlpFileTest::SetUpTestCase()
{
    struct stat fstat;
    if (stat(DLP_TEST_DIR.c_str(), &fstat) != 0) {
        if (errno == ENOENT) {
            int32_t ret = mkdir(DLP_TEST_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
            if (ret < 0) {
                DLP_LOG_ERROR(LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "get mount point failed errno %{public}d", errno);
            return;
        }
    }
}

void DlpFileTest::TearDownTestCase()
{
    int ret = umount(MOUNT_POINT_DIR.c_str());
    DLP_LOG_INFO(LABEL, "umount ret %{public}d", ret);
    rmdir(MOUNT_POINT_DIR.c_str());
    rmdir(DLP_TEST_DIR.c_str());
}

void DlpFileTest::SetUp()
{}

void DlpFileTest::TearDown()
{}

namespace {
static uint8_t GetRandNum()
{
    uint8_t rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

static void GenerateRandStr(uint32_t len, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = GetRandNum() % ARRAY_CHAR_SIZE;
        DLP_LOG_INFO(LABEL, "%{public}u", index);
        res.push_back(CHAR_ARRAY[index]);
    }
    DLP_LOG_INFO(LABEL, "%{public}s", res.c_str());
}

static void GenerateRandProperty(struct DlpProperty& encProp)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    encProp.ownerAccount = DEFAULT_CURRENT_ACCOUNT;
    encProp.ownerAccountId = DEFAULT_CURRENT_ACCOUNT;
    encProp.ownerAccountType = CLOUD_ACCOUNT;
    for (uint32_t user = 0; user < TEST_USER_COUNT; ++user) {
        std::string accountName;
        GenerateRandStr(RAND_STR_SIZE, accountName);
        AuthUserInfo perminfo = {.authAccount = strdup(const_cast<char *>(accountName.c_str())),
            .authPerm = READ_ONLY,
            .permExpiryTime = curTime + EXPIRT_TIME,
            .authAccountType = CLOUD_ACCOUNT};
        encProp.authUsers.emplace_back(perminfo);
    }
    std::string accountName;
    GenerateRandStr(RAND_STR_SIZE, accountName);
    encProp.contactAccount = strdup(const_cast<char *>(accountName.c_str()));
}
}
/**
 * @tc.name: GenerateDlpFile001
 * @tc.desc: test dlp file generate, owner is current
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFileTest, GenerateDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile001");

    g_plainFileFd = open("/data/file_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/file_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_recoveryFileFd, 0);

    result = DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd);
    ASSERT_EQ(result, 0);

    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    char buffer2[16] = {0};
    result = read(g_recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, 6);
    ASSERT_EQ(result, 0);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: OpenDlpFile001
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFileTest, OpenDlpFile001, TestSize.Level1)
{
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);
    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    struct DlpProperty prop;
    GenerateRandProperty(prop);
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
    result = DlpFileManager::GetInstance().OpenDlpFile(g_dlpFileFd, g_Dlpfile, DLP_TEST_DIR, "test_appId_passed");
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    PermissionPolicy policy;
    g_Dlpfile->GetPolicy(policy);
    ASSERT_EQ(policy.ownerAccount_, prop.ownerAccount);
    std::vector<AuthUserInfo>& authUsers = policy.authUsers_;
    ASSERT_EQ(authUsers.size(), prop.authUsers.size());
    bool isEqual = false;
    for (int32_t i = 0; i < static_cast<int32_t>(authUsers.size()); i++) {
        for (int32_t j = 0; j < static_cast<int32_t>(prop.authUsers.size()); j++) {
            if (authUsers[i].authAccount == prop.authUsers[j].authAccount) {
                ASSERT_EQ(authUsers[i].authPerm, prop.authUsers[j].authPerm);
                ASSERT_EQ(authUsers[i].authAccountType, prop.authUsers[j].authAccountType);
                isEqual = true;
            }
        }
    }
    ASSERT_EQ(isEqual, true);
    std::string contactAccount;
    g_Dlpfile->GetContactAccount(contactAccount);
    ASSERT_EQ(contactAccount, prop.contactAccount);
    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_recoveryFileFd, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd), 0);
    lseek(g_recoveryFileFd, 0, SEEK_SET);
    char buffer2[16] = {0};
    result = read(g_recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: OpenDlpFile002
 * @tc.desc: test dlp fuse init，fd is right
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFileTest, OpenDlpFile002, TestSize.Level1)
{
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);
    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    struct DlpProperty prop;
    GenerateRandProperty(prop);
    prop.supportEveryone = true;
    prop.everyonePerm = READ_ONLY;
    int32_t result = DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    result = DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
    ASSERT_EQ(result, 0);
    g_Dlpfile = nullptr;
    std::string appId = "test_appId_passed";
    result = DlpFileManager::GetInstance().OpenDlpFile(g_dlpFileFd, g_Dlpfile, DLP_TEST_DIR, appId);
    ASSERT_EQ(result, 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    PermissionPolicy policy;
    g_Dlpfile->GetPolicy(policy);
    ASSERT_EQ(policy.ownerAccount_, prop.ownerAccount);
    ASSERT_EQ(policy.supportEveryone_, prop.supportEveryone);
    ASSERT_EQ(policy.everyonePerm_, prop.everyonePerm);
    const std::vector<AuthUserInfo>& authUsers = policy.authUsers_;
    ASSERT_EQ(authUsers.size(), prop.authUsers.size());

    std::string contactAccount;
    g_Dlpfile->GetContactAccount(contactAccount);
    ASSERT_EQ(contactAccount, prop.contactAccount);
    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_recoveryFileFd, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd), 0);
    lseek(g_recoveryFileFd, 0, SEEK_SET);
    char buffer2[16] = {0};
    result = read(g_recoveryFileFd, buffer2, 16);
    ASSERT_GE(result, 0);
    result = memcmp(buffer, buffer2, result);
    ASSERT_EQ(result, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
