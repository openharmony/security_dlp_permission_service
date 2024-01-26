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

#include "dlp_fuse_test.h"

#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <securec.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_file.h"
#include "dlp_file_manager.h"
#define private public
#include "dlp_link_file.h"
#include "dlp_link_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"
#include "token_setproc.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFuseTest"};
// using for clean all link file
static const uint32_t LINK_FD_ARRY_SIZE = 4;
static int32_t g_linkFdArry[LINK_FD_ARRY_SIZE] = {-1};
static const std::string MOUNT_POINT_DIR = "/data/fuse/";
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static const std::string FUSE_DEV = "/dev/fuse";
static const std::string FUSE_TYPE = "fuse";
static const int32_t KERNEL_OPT_MAXLEN = 128;
static const std::string TEST_LINK_FILE_NAME = "fuse_test.txt.link";
static const std::string TEST_LINK_FILE_PATH = MOUNT_POINT_DIR + "/" + TEST_LINK_FILE_NAME;
static int32_t g_mountFd = -1;
static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int32_t TEST_USER_COUNT = 2;
static const int32_t RAND_STR_SIZE = 16;
static const int32_t EXPIRT_TIME = 10000;
static int g_plainFileFd = -1;
static int g_dlpFileFd = -1;
static int g_recoveryFileFd = -1;
static std::shared_ptr<DlpFile> g_Dlpfile = nullptr;
static const int32_t DEFAULT_USERID = 100;
static AccessTokenID g_selfTokenId = 0;
constexpr int SIX = 6;
constexpr int SIXTEEN = 16;
constexpr int EIGHTEEN = 18;
}

void DlpFuseTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, "com.ohos.dlpmanager", 0);
    SetSelfTokenID(tokenId);
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

void DlpFuseTest::TearDownTestCase()
{
    g_mountFd = -1;
    int ret = umount(MOUNT_POINT_DIR.c_str());
    DLP_LOG_INFO(LABEL, "umount ret %{public}d", ret);
    rmdir(MOUNT_POINT_DIR.c_str());
    rmdir(DLP_TEST_DIR.c_str());

    SetSelfTokenID(g_selfTokenId);
}

void DlpFuseTest::SetUp()
{}

void DlpFuseTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown");
    for (uint32_t i = 0; i < LINK_FD_ARRY_SIZE; i++) {
        if (g_linkFdArry[i] != -1) {
            close(g_linkFdArry[i]);
            g_linkFdArry[i] = -1;
        }
    }
    if (g_plainFileFd != -1) {
        close(g_plainFileFd);
        g_plainFileFd = -1;
    }
    if (g_dlpFileFd != -1) {
        close(g_dlpFileFd);
        g_dlpFileFd = -1;
    }
    if (g_recoveryFileFd != -1) {
        close(g_recoveryFileFd);
        g_recoveryFileFd = -1;
    }

    if (g_Dlpfile != nullptr) {
        DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile);
        g_Dlpfile = nullptr;
    }
    DLP_LOG_INFO(LABEL, "TearDown end");
}

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

void PrepareDlpFuseFsMount()
{
    struct stat fstat;
    if (stat(MOUNT_POINT_DIR.c_str(), &fstat) != 0) {
        if (errno == ENOENT) {
            int32_t ret = mkdir(MOUNT_POINT_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
            if (ret < 0) {
                DLP_LOG_ERROR(LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "get mount point failed errno %{public}d", errno);
            return;
        }
    }

    g_mountFd = open(FUSE_DEV.c_str(), O_RDWR);
    if (g_mountFd == -1) {
        if (errno == ENODEV || errno == ENOENT) {
            DLP_LOG_ERROR(LABEL, "fuse device not found.");
        } else {
            DLP_LOG_ERROR(LABEL, "open fuse device failed.");
        }
        return;
    }

    dup2(g_mountFd, FUSE_DEV_FD);

    std::string source = FUSE_DEV;
    std::string mnt = MOUNT_POINT_DIR;
    std::string type = FUSE_TYPE;

    char kernelOpts[KERNEL_OPT_MAXLEN] = "";
    (void)snprintf_s(kernelOpts, KERNEL_OPT_MAXLEN, KERNEL_OPT_MAXLEN - 1,
        "fd=%d,rootmode=40000,user_id=%u,group_id=%u", g_mountFd, getuid(), getgid());
    DLP_LOG_INFO(LABEL, "kernelOpts %{public}s", kernelOpts);

    int32_t res = mount(source.c_str(), mnt.c_str(), type.c_str(), MS_NOSUID | MS_NODEV, kernelOpts);
    if (res != 0) {
        DLP_LOG_ERROR(LABEL, "mount failed, errno %{public}d", errno);
    }
}

void CheckLinkFd(int32_t linkfd1)
{
    DLP_LOG_INFO(LABEL, "CheckLinkFd");
    // offset 0 size 6
    char readBuf[64] = {0};
    ASSERT_NE(lseek(linkfd1, 0, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    // read hole data, offset 0x1000 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x1000, SEEK_SET), -1);
    ASSERT_GE(read(linkfd1, readBuf, SIX), SIX);
    char zeroBuf[6] = { 0 };
    ASSERT_EQ(memcmp(readBuf, zeroBuf, SIX), 0);
    // offset 1M size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x100000, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    // offset 1m+16 size 16
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x100010, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, SIXTEEN), SIXTEEN);
    ASSERT_EQ(strcmp(readBuf, "1234567890123456"), 0);
    // offset 1m+34 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x100022, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    // offset 1m+47 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x10002f, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);
    // offset 1m+63 size 18
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(linkfd1, 0x10003f, SEEK_SET), -1);
    ASSERT_EQ(read(linkfd1, readBuf, EIGHTEEN), EIGHTEEN);
    ASSERT_EQ(strcmp(readBuf, "1234567890abcdefgh"), 0);
}

void CheckRecoverFd()
{
    DLP_LOG_INFO(LABEL, "CheckRecoverFd");
    // offset 0 size 6
    char readBuf[64] = {0};
    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    // read hole data, offset 0x1000 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x1000, SEEK_SET), -1);
    ASSERT_GE(read(g_recoveryFileFd, readBuf, SIX), SIX);
    char zeroBuf[6] = { 0 };
    ASSERT_EQ(memcmp(readBuf, zeroBuf, SIX), 0);

    // offset 1M size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x100000, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    // offset 1m+16 size 16
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x100010, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, SIXTEEN), SIXTEEN);
    ASSERT_EQ(strcmp(readBuf, "1234567890123456"), 0);

    // offset 1m+34 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x100022, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    // offset 1m+47 size 6
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x10002f, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, SIX), SIX);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    // offset 1m+63 size 18
    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_NE(lseek(g_recoveryFileFd, 0x10003f, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, EIGHTEEN), EIGHTEEN);
    ASSERT_EQ(strcmp(readBuf, "1234567890abcdefgh"), 0);
}
}

/**
 * @tc.name: AddDlpLinkFile001
 * @tc.desc: test dlp link file read
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile001");
    PrepareDlpFuseFsMount();
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    ASSERT_NE(lseek(g_plainFileFd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    ASSERT_NE(lseek(g_plainFileFd, 0x10000f, SEEK_SET), -1);
    ASSERT_NE(write(g_plainFileFd, "1234567890abcdefgh", strlen("1234567890abcdefgh")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    char readBuf[64] = {0};
    ASSERT_GE(read(linkfd, readBuf, 6), 6);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_GE(lseek(linkfd, 0x100000, SEEK_SET), 0);
    ASSERT_EQ(read(linkfd, readBuf, 6), 6);
    ASSERT_EQ(strcmp(readBuf, "123456"), 0);

    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_GE(lseek(linkfd, 0x10000f, SEEK_SET), 0);
    ASSERT_EQ(read(linkfd, readBuf, 18), 18);
    ASSERT_EQ(strcmp(readBuf, "1234567890abcdefgh"), 0);

    memset_s(readBuf, sizeof(readBuf), 0, sizeof(readBuf));
    ASSERT_GE(lseek(linkfd, 0x100021, SEEK_SET), 0);
    ASSERT_EQ(read(linkfd, readBuf, 6), 0);
    close(linkfd);
    g_linkFdArry[0] = 0;

    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile002
 * @tc.desc: test dlp fuse write and check it from recovery file
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile002");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "111111";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("111111")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);
    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;
    // offset 0 size 6
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);
    // offset 1M size 6
    ASSERT_NE(lseek(linkfd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);
    // offset 1m+16 size 16
    ASSERT_NE(lseek(linkfd, 0x100010, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "1234567890123456", strlen("1234567890123456")), -1);
    // offset 1m+34 size 6
    ASSERT_NE(lseek(linkfd, 0x100022, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);
    // offset 1m+47 size 6
    ASSERT_NE(lseek(linkfd, 0x10002f, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);
    // offset 1m+63 size 18
    ASSERT_NE(lseek(linkfd, 0x10003f, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "1234567890abcdefgh", strlen("1234567890abcdefgh")), -1);
    close(linkfd);
    g_linkFdArry[0] = 0;
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_dlpFileFd, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
    CheckRecoverFd();
}

/**
 * @tc.name: AddDlpLinkFile003
 * @tc.desc: test dlp link read after write
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile003");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // offset 0 size 6
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);

    // offset 1M size 6
    ASSERT_NE(lseek(linkfd, 0x100000, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);

    // offset 1m+16 size 16
    ASSERT_NE(lseek(linkfd, 0x100010, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "1234567890123456", strlen("1234567890123456")), -1);

    // offset 1m+34 size 6
    ASSERT_NE(lseek(linkfd, 0x100022, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);

    // offset 1m+47 size 6
    ASSERT_NE(lseek(linkfd, 0x10002f, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "123456", strlen("123456")), -1);

    // offset 1m+63 size 18
    ASSERT_NE(lseek(linkfd, 0x10003f, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "1234567890abcdefgh", strlen("1234567890abcdefgh")), -1);

    CheckLinkFd(linkfd);
    close(linkfd);
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile004
 * @tc.desc: test dlp link file stat
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile004");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    struct stat fsStat;
    ASSERT_EQ(fstat(linkfd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 6);

    close(linkfd);
    g_linkFdArry[0] = 0;

    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile005
 * @tc.desc: test dlp link file open with trunc
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile005");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR | O_TRUNC);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    struct stat fsStat;
    ASSERT_EQ(fstat(linkfd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 0);

    close(linkfd);
    g_linkFdArry[0] = 0;

    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile006
 * @tc.desc: test dlp link file open with trunc
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile006");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR | O_TRUNC);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // get link file size
    struct stat fsStat;
    ASSERT_EQ(fstat(linkfd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 0);
    close(linkfd);
    g_linkFdArry[0] = 0;
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_dlpFileFd, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;

    ASSERT_EQ(fstat(g_recoveryFileFd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 0);
    close(g_recoveryFileFd);
    g_recoveryFileFd = 0;
}

/**
 * @tc.name: AddDlpLinkFile007
 * @tc.desc: test dlp link file truncate
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile007, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile007");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // truncate link file size to 3
    ASSERT_EQ(ftruncate(linkfd, 3), 0);

    // get link file size
    struct stat fsStat;
    ASSERT_EQ(fstat(linkfd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 3);
    close(linkfd);
    g_linkFdArry[0] = 0;
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);

    g_recoveryFileFd = open("/data/fuse_test.txt.recovery", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_dlpFileFd, 0);
    ASSERT_EQ(DlpFileManager::GetInstance().RecoverDlpFile(g_Dlpfile, g_recoveryFileFd), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;

    ASSERT_EQ(fstat(g_recoveryFileFd, &fsStat), 0);
    ASSERT_EQ(fsStat.st_size, 3);

    char readBuf[64] = {0};
    ASSERT_NE(lseek(g_recoveryFileFd, 0, SEEK_SET), -1);
    ASSERT_EQ(read(g_recoveryFileFd, readBuf, 6), 3);
    ASSERT_EQ(strcmp(readBuf, "123"), 0);
    close(g_recoveryFileFd);
    g_recoveryFileFd = 0;
}

/**
 * @tc.name: AddDlpLinkFile008
 * @tc.desc: test dlp link file changed size, dlp header txtSize also changed
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile008, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile008");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    // open link file
    int32_t linkfd = open(TEST_LINK_FILE_PATH.c_str(), O_RDWR);
    ASSERT_GE(linkfd, 0);
    g_linkFdArry[0] = linkfd;

    // truncate link file size to 3
    ASSERT_EQ(ftruncate(linkfd, 3), 0);

    // dlp header txtSize will 4
    ASSERT_NE(lseek(linkfd, 3, SEEK_SET), -1);
    ASSERT_NE(write(linkfd, "1", strlen("1")), -1);

    // write back cache enable, need fsync
    fsync(linkfd);
    close(linkfd);

    g_linkFdArry[0] = 0;
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: AddDlpLinkFile009
 * @tc.desc: test add link abnoral branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile009, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile009");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, ""), DLP_FUSE_ERROR_DLP_FILE_NULL);

    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    EXPECT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, ""), DLP_FUSE_ERROR_VALUE_INVALID);

    EXPECT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile"), DLP_OK);
    EXPECT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile"), DLP_FUSE_ERROR_LINKFILE_EXIST);

    DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr);
}

/**
 * @tc.name: AddDlpLinkFile010
 * @tc.desc: test add too many links
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, AddDlpLinkFile010, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpLinkFile010");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    for (int i = 0; i < 1000; i++) {
        std::string linkName = "AddDlpLinkFile010-" + std::to_string(i);
        std::shared_ptr<DlpFile> filePtr2 = std::make_shared<DlpFile>(-i, DLP_TEST_DIR, 0, false);
        DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr2, linkName);
    }
    EXPECT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile"), DLP_FUSE_ERROR_TOO_MANY_LINK_FILE);
    for (int i = 0; i < 1000; i++) {
        DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr);
    }
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.clear();
}

/**
 * @tc.name: DeleteDlpLinkFile001
 * @tc.desc: test delete link abnoral branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, DeleteDlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeleteDlpLinkFile001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr), DLP_FUSE_ERROR_DLP_FILE_NULL);

    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    EXPECT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr), DLP_FUSE_ERROR_LINKFILE_NOT_EXIST);

    DlpLinkFile *node = new (std::nothrow) DlpLinkFile("linkfile", nullptr);
    ASSERT_NE(node, nullptr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["null"] = nullptr;
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = node;

    EXPECT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr), DLP_FUSE_ERROR_LINKFILE_NOT_EXIST);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.erase("null");
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.erase("linkfile");
    delete(node);
}

/**
 * @tc.name: LookUpDlpLinkFile001
 * @tc.desc: test lookup link abnoral branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, LookUpDlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "LookUpDlpLinkFile001");
    EXPECT_EQ(DlpLinkManager::GetInstance().LookUpDlpLinkFile(""), nullptr);
    EXPECT_EQ(DlpLinkManager::GetInstance().LookUpDlpLinkFile("linkfile"), nullptr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().LookUpDlpLinkFile("linkfile"), nullptr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.erase("linkfile");
}

/**
 * @tc.name: DumpDlpLinkFile001
 * @tc.desc: test dump link file abnoral branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, DumpDlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DumpDlpLinkFile001");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpLinkFile *node = new (std::nothrow) DlpLinkFile("linkfile1", filePtr);
    ASSERT_NE(node, nullptr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = nullptr;
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = node;
    std::vector<DlpLinkFileInfo> linkList;
    DlpLinkManager::GetInstance().DumpDlpLinkFile(linkList);
    EXPECT_NE(static_cast<int>(linkList.size()), 0);
    if (linkList.size() > 0) {
        EXPECT_EQ(linkList[0].dlpLinkName, "linkfile1");
    }

    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.erase("linkfile");
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.erase("linkfile1");
    delete(node);
}

/**
 * @tc.name: ReadFuseDir001
 * @tc.desc: test fuse readdir
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, ReadFuseDir001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ReadFuseDir001");
    g_plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open("/data/fuse_test.txt.dlp", O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, strlen("123456")), -1);

    struct DlpProperty prop;
    GenerateRandProperty(prop);

    ASSERT_EQ(DlpFileManager::GetInstance().GenerateDlpFile(g_plainFileFd,
        g_dlpFileFd, prop, g_Dlpfile, DLP_TEST_DIR), 0);
    ASSERT_NE(g_Dlpfile, nullptr);
    ASSERT_EQ(DlpLinkManager::GetInstance().AddDlpLinkFile(g_Dlpfile, TEST_LINK_FILE_NAME), 0);

    DIR *dir = opendir(MOUNT_POINT_DIR.c_str());
    ASSERT_NE(dir, nullptr);

    struct dirent *entry = readdir(dir);
    ASSERT_NE(entry, nullptr); // "."
    entry = readdir(dir);
    ASSERT_NE(entry, nullptr); // ".."
    entry = readdir(dir);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(strcmp(TEST_LINK_FILE_NAME.c_str(), entry->d_name), 0);
    closedir(dir);
    ASSERT_EQ(DlpLinkManager::GetInstance().DeleteDlpLinkFile(g_Dlpfile), 0);
    ASSERT_EQ(DlpFileManager::GetInstance().CloseDlpFile(g_Dlpfile), 0);
    g_Dlpfile = nullptr;
}

/**
 * @tc.name: DlpLinkFile001
 * @tc.desc: test DlpLinkFile construction
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, DlpLinkFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpLinkFile001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);
    ASSERT_EQ(static_cast<int>(linkFile.fileStat_.st_mode), 0);
}

/**
 * @tc.name: SubAndCheckZeroRef001
 * @tc.desc: test link file subtract reference abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, SubAndCheckZeroRef001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SubAndCheckZeroRef001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);
    EXPECT_FALSE(linkFile.SubAndCheckZeroRef(-1));
    EXPECT_TRUE(linkFile.SubAndCheckZeroRef(5));
}

/**
 * @tc.name: IncreaseRef001
 * @tc.desc: test link file increase reference abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, IncreaseRef001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IncreaseRef001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);
    linkFile.refcount_ = 0;
    linkFile.IncreaseRef();
    ASSERT_NE(linkFile.refcount_, 1);
}

/**
 * @tc.name: GetLinkStat001
 * @tc.desc: test get link file state abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, GetLinkStat001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetLinkStat001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);
    struct stat fs = linkFile.GetLinkStat();
    ASSERT_EQ(fs.st_size, 0);
}

/**
 * @tc.name: LinkFileTruncate001
 * @tc.desc: test link file truncate abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, LinkFileTruncate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "LinkFileTruncate001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);

    EXPECT_EQ(linkFile.Truncate(-1), DLP_FUSE_ERROR_VALUE_INVALID);
    EXPECT_EQ(linkFile.Truncate(0xffffffff), DLP_FUSE_ERROR_VALUE_INVALID);
    EXPECT_EQ(linkFile.Truncate(0), DLP_FUSE_ERROR_DLP_FILE_NULL);
    filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);

    DlpLinkFile linkFile1("linkfile1", filePtr);
    EXPECT_EQ(linkFile1.Truncate(0), DLP_PARSE_ERROR_FILE_READ_ONLY);
}

/**
 * @tc.name: LinkFileWrite001
 * @tc.desc: test link file write abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, LinkFileWrite001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "LinkFileWrite001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);

    uint8_t buffer[16] = {0};
    EXPECT_EQ(linkFile.Write(0, buffer, 15), DLP_FUSE_ERROR_DLP_FILE_NULL);

    filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);

    DlpLinkFile linkFile1("linkfile1", filePtr);
    EXPECT_EQ(linkFile1.Write(0, buffer, 15), DLP_PARSE_ERROR_FILE_READ_ONLY);
}

/**
 * @tc.name: LinkFileRead001
 * @tc.desc: test link file read abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, LinkFileRead001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "LinkFileRead001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);

    uint8_t buffer[16] = {0};
    EXPECT_EQ(linkFile.Read(0, buffer, 15), DLP_FUSE_ERROR_DLP_FILE_NULL);

    filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);

    DlpLinkFile linkFile1("linkfile1", filePtr);
    EXPECT_EQ(linkFile1.Read(0, buffer, 15), DLP_PARSE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: Truncate001
 * @tc.desc: test dlp link file truncate
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, Truncate001, TestSize.Level1)
{
    std::shared_ptr<DlpFile> filePtr = nullptr;
    DlpLinkFile linkFile("linkfile", filePtr);
    linkFile.stopLinkFlag_ = true;
    EXPECT_EQ(linkFile.Truncate(-1), DLP_LINK_FILE_NOT_ALLOW_OPERATE);
    uint8_t buffer[16] = {0};
    EXPECT_EQ(linkFile.Write(0, buffer, 15), DLP_LINK_FILE_NOT_ALLOW_OPERATE);
    EXPECT_EQ(linkFile.Read(0, buffer, 15), DLP_LINK_FILE_NOT_ALLOW_OPERATE);
}

/**
 * @tc.name: StopDlpLinkFile001
 * @tc.desc: StopDlpLinkFile
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, StopDlpLinkFile001, TestSize.Level1)
{
    std::shared_ptr<DlpFile> filePtr = nullptr;
    std::shared_ptr<DlpFile> filePtr2 = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().StopDlpLinkFile(filePtr), DLP_FUSE_ERROR_DLP_FILE_NULL);
    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    filePtr2 = std::make_shared<DlpFile>(1001, DLP_TEST_DIR, 0, false);

    DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile");
    EXPECT_EQ(DlpLinkManager::GetInstance().StopDlpLinkFile(filePtr2), DLP_FUSE_ERROR_LINKFILE_NOT_EXIST);
    DlpLinkFile* node = new (std::nothrow) DlpLinkFile("linkfile1", filePtr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = node;
    EXPECT_EQ(DlpLinkManager::GetInstance().StopDlpLinkFile(filePtr), DLP_OK);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = nullptr;
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().StopDlpLinkFile(filePtr), DLP_FUSE_ERROR_DLP_FILE_NULL);
    delete (node);
}

/**
 * @tc.name: RestartDlpLinkFile001
 * @tc.desc: RestartDlpLinkFile
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, RestartDlpLinkFile001, TestSize.Level1)
{
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.clear();
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().RestartDlpLinkFile(filePtr), DLP_FUSE_ERROR_DLP_FILE_NULL);
    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    std::shared_ptr<DlpFile> filePtr2 = nullptr;
    filePtr2 = std::make_shared<DlpFile>(1001, DLP_TEST_DIR, 0, false);

    DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile");
    EXPECT_EQ(DlpLinkManager::GetInstance().RestartDlpLinkFile(filePtr2), DLP_FUSE_ERROR_LINKFILE_NOT_EXIST);
    DlpLinkFile* node = new (std::nothrow) DlpLinkFile("linkfile1", filePtr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = node;
    EXPECT_EQ(DlpLinkManager::GetInstance().RestartDlpLinkFile(filePtr), DLP_OK);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = nullptr;
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().RestartDlpLinkFile(filePtr), DLP_FUSE_ERROR_DLP_FILE_NULL);
    delete (node);
}

/**
 * @tc.name: ReplaceDlpLinkFile001
 * @tc.desc: ReplaceDlpLinkFile
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(DlpFuseTest, ReplaceDlpLinkFile001, TestSize.Level1)
{
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().ReplaceDlpLinkFile(filePtr, "test"), DLP_FUSE_ERROR_DLP_FILE_NULL);
    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);

    DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "linkfile");
    EXPECT_EQ(DlpLinkManager::GetInstance().ReplaceDlpLinkFile(filePtr, ""), DLP_FUSE_ERROR_VALUE_INVALID);
    EXPECT_EQ(DlpLinkManager::GetInstance().ReplaceDlpLinkFile(filePtr, "test"), DLP_FUSE_ERROR_LINKFILE_NOT_EXIST);
    DlpLinkFile* node = new (std::nothrow) DlpLinkFile("linkfile1", filePtr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile1"] = node;
    EXPECT_EQ(DlpLinkManager::GetInstance().ReplaceDlpLinkFile(filePtr, "linkfile1"), DLP_OK);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_["linkfile"] = nullptr;
    EXPECT_EQ(DlpLinkManager::GetInstance().ReplaceDlpLinkFile(filePtr, "linkfile"), DLP_FUSE_ERROR_DLP_FILE_NULL);
    delete (node);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
