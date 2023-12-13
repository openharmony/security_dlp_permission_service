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
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "c_mock_common.h"
#define private public
#include "dlp_link_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "FuseDaemonTest"};

static const fuse_ino_t ROOT_INODE = 1;
static const int DEFAULT_ATTR_TIMEOUT = 10000;
static const uint32_t MAX_FUSE_READ_BUFF_SIZE = 10 * 1024 * 1024; // 10M
static const uint32_t MAX_READ_DIR_BUF_SIZE = 100 * 1024;  // 100K

static int g_fuseReplyErr = 0;
static struct fuse_file_info g_fuseReplyOpen;
static struct fuse_entry_param g_fuseReplyEntry;
static struct stat g_fuseReplyAttr;
static double g_fuseReplyAttrTimeout = 0.0F;
static size_t g_fuseReplyBufSize = 0;
static int g_session;
static const std::string DLP_TEST_DIR = "/data/dlpTest/";

static int FuseReplyErrMock(fuse_req_t req, int err)
{
    (void)req;
    g_fuseReplyErr = err;
    return 0;
}

static int FuseReplyOpenMock(fuse_req_t req, const struct fuse_file_info *f)
{
    (void)req;
    g_fuseReplyOpen = *f;
    return 0;
}

int FuseReplyEntryMock(fuse_req_t req, const struct fuse_entry_param *e)
{
    (void)req;
    g_fuseReplyEntry = *e;
    return 0;
}

int FuseReplyAttrMock(fuse_req_t req, const struct stat *attr, double attr_timeout)
{
    (void)req;
    g_fuseReplyAttr = *attr;
    g_fuseReplyAttrTimeout = attr_timeout;
    return 0;
}

static const size_t ADD_DIRENTRY_BUFF_LEN = 100;
size_t FuseAddDirentryMockCurDirFail(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)name;
    (void)stbuf;
    (void)off;
    return ADD_DIRENTRY_BUFF_LEN + 1;
}

size_t FuseAddDirentryMockUpperDirFail(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)stbuf;
    (void)off;
    if (strcmp(name, ".") == 0) {
        return strlen(".");
    }
    return ADD_DIRENTRY_BUFF_LEN + 1;
}

size_t FuseAddDirentryMockTestFileFail(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off)
{
    (void)req;
    (void)buf;
    (void)bufsize;
    (void)stbuf;
    (void)off;
    if (strcmp(name, "test") != 0) {
        return strlen(name);
    }
    return ADD_DIRENTRY_BUFF_LEN + 1;
}

int FuseReplyBufMock(fuse_req_t req, const char *buf, size_t size)
{
    (void)req;
    (void)buf;
    (void)size;
    g_fuseReplyBufSize = 0;
    return 0;
}


struct fuse_session *FuseSessionNewMock(struct fuse_args *args, const struct fuse_lowlevel_ops *op,
    size_t opSize, void *userdata)
{
    (void)args;
    (void)op;
    (void)opSize;
    (void)userdata;
    return reinterpret_cast<struct fuse_session *>(&g_session);
}

int FuseSessionMountMock(struct fuse_session *se, const char *mountpoint)
{
    (void)se;
    (void)mountpoint;
    return 0;
}
}

class FuseDaemonTest : public testing::Test {
public:
    static void SetUpTestCase()
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
    };

    static void TearDownTestCase()
    {
        rmdir(DLP_TEST_DIR.c_str());
    };

    void SetUp() {};

    void TearDown() {};
};

/**
 * @tc.name: FuseDaemonLookup001
 * @tc.desc: test fuse lookup callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonLookup001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonLookup001");
    DlpLinkFile linkfile("test", nullptr);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));
    fuse_req_t req = nullptr;

    // file name null
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.lookup(req, ROOT_INODE, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // ino != ROOT_INODE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.lookup(req, ino, "test");
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // name = '.'
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_entry", condition);
    SetMockCallback("fuse_reply_entry", reinterpret_cast<CommonMockFuncT>(FuseReplyEntryMock));
    (void)memset_s(&g_fuseReplyEntry, sizeof(g_fuseReplyEntry), 0, sizeof(g_fuseReplyEntry));
    FuseDaemon::fuseDaemonOper_.lookup(req, ROOT_INODE, ".");
    EXPECT_EQ(ROOT_INODE, g_fuseReplyEntry.ino);
    CleanMockConditions();

    // name = '..'
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_entry", condition);
    SetMockCallback("fuse_reply_entry", reinterpret_cast<CommonMockFuncT>(FuseReplyEntryMock));
    (void)memset_s(&g_fuseReplyEntry, sizeof(g_fuseReplyEntry), 0, sizeof(g_fuseReplyEntry));
    FuseDaemon::fuseDaemonOper_.lookup(req, ROOT_INODE, "..");
    EXPECT_EQ(ROOT_INODE, g_fuseReplyEntry.ino);
    CleanMockConditions();

    // name = '..'
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.lookup(req, ROOT_INODE, "test");
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonGetattr001
 * @tc.desc: test fuse getattr callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonGetattr001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonGetattr001");
    fuse_req_t req = nullptr;

    // get ROOT_INODE attr
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_attr", condition);
    SetMockCallback("fuse_reply_attr", reinterpret_cast<CommonMockFuncT>(FuseReplyAttrMock));
    (void)memset_s(&g_fuseReplyAttr, sizeof(g_fuseReplyAttr), 0, sizeof(g_fuseReplyAttr));
    g_fuseReplyAttrTimeout = 0.0F;
    FuseDaemon::fuseDaemonOper_.getattr(req, ROOT_INODE, nullptr);
    EXPECT_EQ(memcmp(&FuseDaemon::rootFileStat_, &g_fuseReplyAttr, sizeof(struct stat)), 0);
    EXPECT_EQ(DEFAULT_ATTR_TIMEOUT, g_fuseReplyAttrTimeout);
    CleanMockConditions();

    // get not exist link file
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.getattr(req, 0, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonOpen001
 * @tc.desc: test fuse open callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonOpen001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonOpen001");
    fuse_req_t req = nullptr;

    // open ROOT_INODE
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.open(req, ROOT_INODE, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // open null file
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.open(req, 0, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // open readonly dlp with O_TRUNC
    std::shared_ptr<DlpFile> dlpFile = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(dlpFile, nullptr);
    DlpLinkFile linkfile("test", dlpFile);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));
    struct fuse_file_info fi;
    fi.flags = O_TRUNC;

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.open(req, ino, &fi);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    fi.flags = O_RDWR;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_open", condition);
    SetMockCallback("fuse_reply_open", reinterpret_cast<CommonMockFuncT>(FuseReplyOpenMock));
    (void)memset_s(&g_fuseReplyOpen, sizeof(g_fuseReplyOpen), 0, sizeof(g_fuseReplyOpen));
    FuseDaemon::fuseDaemonOper_.open(req, ino, &fi);
    EXPECT_EQ(O_RDWR, g_fuseReplyOpen.flags);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonRead001
 * @tc.desc: test fuse read callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonRead001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonRead001");
    fuse_req_t req = nullptr;

    // offset < 0
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, ROOT_INODE, 1, -1, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // offset > DLP_MAX_CONTENT_SIZE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, ROOT_INODE, 1, DLP_MAX_CONTENT_SIZE + 1, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // size > MAX_FUSE_READ_BUFF_SIZE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, ROOT_INODE, MAX_FUSE_READ_BUFF_SIZE + 1, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonRead002
 * @tc.desc: test fuse read callback abnormal branch2
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonRead002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonRead002");
    fuse_req_t req = nullptr;

    // ino ROOT_INODE
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, ROOT_INODE, 10, 0, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // ino 0
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, 0, 10, 0, nullptr);
    EXPECT_EQ(EBADF, g_fuseReplyErr);
    CleanMockConditions();

    // can not read dlp file
    std::shared_ptr<DlpFile> dlpFile = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(dlpFile, nullptr);
    DlpLinkFile linkfile("test", dlpFile);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.read(req, ino, 10, 0, nullptr);
    EXPECT_EQ(EIO, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonWrite001
 * @tc.desc: test fuse write callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonWrite001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonWrite001");
    fuse_req_t req = nullptr;

    // offset < 0
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.write(req, ROOT_INODE, nullptr, 1, -1, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // offset > DLP_MAX_CONTENT_SIZE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.write(req, ROOT_INODE, nullptr, 1, DLP_MAX_CONTENT_SIZE + 1, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // size > DLP_FUSE_MAX_BUFFLEN
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.write(req, ROOT_INODE, nullptr, DLP_FUSE_MAX_BUFFLEN + 1, 100, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // ino ROOT_INODE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.write(req, ROOT_INODE, nullptr, 1, 0, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // can not write dlp file
    std::shared_ptr<DlpFile> dlpFile = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(dlpFile, nullptr);
    DlpLinkFile linkfile("test", dlpFile);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.write(req, ino, nullptr, 1, 0, nullptr);
    EXPECT_EQ(EIO, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonForget001
 * @tc.desc: test fuse forget callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonForget001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonForget001");
    fuse_req_t req = nullptr;

    // ino ROOT_INODE
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.forget(req, ROOT_INODE, 1);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.forget(req, 0, 1);
    EXPECT_EQ(EBADF, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonReadDir001
 * @tc.desc: test fuse read dir callback abnormal branch
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir001");
    fuse_req_t req = nullptr;

    // off < 0
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, 10, -1, nullptr);
    EXPECT_EQ(ENOTDIR, g_fuseReplyErr);

    // off > DLP_MAX_CONTENT_SIZE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, 10, DLP_MAX_CONTENT_SIZE + 1, nullptr);
    EXPECT_EQ(ENOTDIR, g_fuseReplyErr);
    CleanMockConditions();

    // ino != ROOT_INODE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, 0, 10, 0, nullptr);
    EXPECT_EQ(ENOTDIR, g_fuseReplyErr);
    CleanMockConditions();

    // size > MAX_READ_DIR_BUF_SIZE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, MAX_READ_DIR_BUF_SIZE + 1, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonReadDir002
 * @tc.desc: test fuse AddDirentry callback CUR_DIR entry too large
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir002");
    fuse_req_t req = nullptr;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = { true };
    SetMockConditions("fuse_add_direntry", condition1);
    SetMockCallback("fuse_add_direntry", reinterpret_cast<CommonMockFuncT>(FuseAddDirentryMockCurDirFail));

    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, ADD_DIRENTRY_BUFF_LEN, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonReadDir003
 * @tc.desc: test fuse AddDirentry callback UPPER_DIR entry too large
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir003");
    fuse_req_t req = nullptr;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = { true, true, true };
    SetMockConditions("fuse_add_direntry", condition1);
    SetMockCallback("fuse_add_direntry", reinterpret_cast<CommonMockFuncT>(FuseAddDirentryMockUpperDirFail));

    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, ADD_DIRENTRY_BUFF_LEN, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonReadDir004
 * @tc.desc: test fuse AddDirentry callback test file entry fail
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir004");
    fuse_req_t req = nullptr;
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpLinkManager::GetInstance().g_DlpLinkFileNameMap_.clear();
    DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "test");

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = { true, true, true, true, true };
    SetMockConditions("fuse_add_direntry", condition1);
    SetMockCallback("fuse_add_direntry", reinterpret_cast<CommonMockFuncT>(FuseAddDirentryMockTestFileFail));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, ADD_DIRENTRY_BUFF_LEN, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr);
}

/**
 * @tc.name: FuseDaemonReadDir005
 * @tc.desc: test fuse AddDirentry callback test file entry fail
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir005");
    fuse_req_t req = nullptr;
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    DlpLinkManager::GetInstance().AddDlpLinkFile(filePtr, "test");
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = { true, true, true, true, true };
    SetMockConditions("fuse_add_direntry", condition1);
    SetMockCallback("fuse_add_direntry", reinterpret_cast<CommonMockFuncT>(FuseAddDirentryMockTestFileFail));

    DlpCMockCondition condition2;
    condition2.mockSequence = { true };
    SetMockConditions("fuse_reply_buf", condition2);
    SetMockCallback("fuse_reply_buf", reinterpret_cast<CommonMockFuncT>(FuseReplyBufMock));

    g_fuseReplyBufSize = 1;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, ADD_DIRENTRY_BUFF_LEN, ADD_DIRENTRY_BUFF_LEN + 1, nullptr);
    EXPECT_EQ(static_cast<size_t>(1), g_fuseReplyBufSize);
    CleanMockConditions();
    DlpLinkManager::GetInstance().DeleteDlpLinkFile(filePtr);
}

/**
 * @tc.name: FuseDaemonReadDir006
 * @tc.desc: test fuse AddDirentry callback CUR_DIR entry too large
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonReadDir006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir006");
    fuse_req_t req = nullptr;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = { true };
    SetMockConditions("fuse_add_direntry", condition1);
    SetMockCallback("fuse_add_direntry", reinterpret_cast<CommonMockFuncT>(FuseAddDirentryMockCurDirFail));

    DlpCMockCondition condition2;
    condition2.mockSequence = { true };
    SetMockConditions("fuse_reply_buf", condition2);
    SetMockCallback("fuse_reply_buf", reinterpret_cast<CommonMockFuncT>(FuseReplyBufMock));

    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.readdir(req, ROOT_INODE, ADD_DIRENTRY_BUFF_LEN + 1, DLP_MAX_CONTENT_SIZE, nullptr);
    EXPECT_EQ(static_cast<size_t>(0), g_fuseReplyBufSize);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonSetAttr001
 * @tc.desc: test fuse set attr callback abnormal test
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonSetAttr001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonReadDir005");
    fuse_req_t req = nullptr;

    // attr = nullptr
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.setattr(req, 0, nullptr, 0, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    // ino = ROOT_INODE
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    struct stat attr;
    FuseDaemon::fuseDaemonOper_.setattr(req, ROOT_INODE, &attr, 0, nullptr);
    EXPECT_EQ(EACCES, g_fuseReplyErr);
    CleanMockConditions();

    // ino = 0
    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    FuseDaemon::fuseDaemonOper_.setattr(req, 0, &attr, 0, nullptr);
    EXPECT_EQ(ENOENT, g_fuseReplyErr);
    CleanMockConditions();

    // truncate fail
    std::shared_ptr<DlpFile> dlpFile = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(dlpFile, nullptr);
    DlpLinkFile linkfile("test", dlpFile);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    g_fuseReplyErr = 0;
    attr.st_size = 0;
    FuseDaemon::fuseDaemonOper_.setattr(req, ino, &attr, FUSE_SET_ATTR_SIZE, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonSetAttr002
 * @tc.desc: test fuse set attr callback abnormal test
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonSetAttr002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonSetAttr002");
    fuse_req_t req = nullptr;

    // attr = nullptr
    DlpCMockCondition condition;

    std::shared_ptr<DlpFile> dlpFile = std::make_shared<DlpFile>(-1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(dlpFile, nullptr);
    DlpLinkFile linkfile("test", dlpFile);
    fuse_ino_t ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(&linkfile));
    struct stat attr;
    g_fuseReplyErr = 0;

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    attr.st_size = DLP_MAX_CONTENT_SIZE + 1;
    FuseDaemon::fuseDaemonOper_.setattr(req, ino, &attr, FUSE_SET_ATTR_SIZE, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("fuse_reply_err", condition);
    SetMockCallback("fuse_reply_err", reinterpret_cast<CommonMockFuncT>(FuseReplyErrMock));
    attr.st_size = -1;
    FuseDaemon::fuseDaemonOper_.setattr(req, ino, &attr, FUSE_SET_ATTR_SIZE, nullptr);
    EXPECT_EQ(EINVAL, g_fuseReplyErr);
    CleanMockConditions();
}

/**
 * @tc.name: InitFuseFs001
 * @tc.desc: test fuse daemon init
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, InitFuseFs001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "InitFuseFs001");
    FuseDaemon::init_ = false;
    EXPECT_EQ(-1, FuseDaemon::InitFuseFs(-1));
    // second init will fail whatever last init result is.
    EXPECT_EQ(-1, FuseDaemon::InitFuseFs(-1));

    // fuse fd is wrong
    FuseDaemon::init_ = false;
    EXPECT_EQ(-1, FuseDaemon::InitFuseFs(1000));
}

/**
 * @tc.name: FuseFsDaemonThread001
 * @tc.desc: test fuse daemon thread abnormal
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseFsDaemonThread001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseFsDaemonThread001");

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_opt_add_arg", condition);
    DlpCMockCondition condition1;
    condition1.mockSequence = { true };
    SetMockConditions("fuse_session_new", condition1);
    DlpCMockCondition condition2;
    condition2.mockSequence = { true };
    SetMockConditions("fuse_opt_free_args", condition2);
    FuseDaemon::FuseFsDaemonThread(1);
    EXPECT_EQ(-1, FuseDaemon::WaitDaemonEnable());
    CleanMockConditions();
}

/**
 * @tc.name: FuseFsDaemonThread002
 * @tc.desc: test fuse daemon thread abnormal
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseFsDaemonThread002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseFsDaemonThread002");

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_opt_add_arg", condition);
    DlpCMockCondition condition1;
    condition1.mockSequence = { true };
    SetMockConditions("fuse_session_new", condition1);
    SetMockCallback("fuse_session_new", reinterpret_cast<CommonMockFuncT>(FuseSessionNewMock));
    DlpCMockCondition condition2;
    condition2.mockSequence = { true };
    SetMockConditions("fuse_session_mount", condition2);
    DlpCMockCondition condition3;
    condition3.mockSequence = { true };
    SetMockConditions("fuse_session_destroy", condition3);
    DlpCMockCondition condition4;
    condition4.mockSequence = { true };
    SetMockConditions("fuse_opt_free_args", condition4);

    FuseDaemon::FuseFsDaemonThread(1);
    EXPECT_EQ(-1, FuseDaemon::WaitDaemonEnable());
    CleanMockConditions();
}

/**
 * @tc.name: FuseFsDaemonThread003
 * @tc.desc: test fuse daemon thread abnormal
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseFsDaemonThread003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseFsDaemonThread003");

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("fuse_opt_add_arg", condition);
    DlpCMockCondition condition1;
    condition1.mockSequence = { true };
    SetMockConditions("fuse_session_new", condition1);
    SetMockCallback("fuse_session_new", reinterpret_cast<CommonMockFuncT>(FuseSessionNewMock));
    DlpCMockCondition condition2;
    condition2.mockSequence = { true };
    SetMockConditions("fuse_session_mount", condition2);
    SetMockCallback("fuse_session_mount", reinterpret_cast<CommonMockFuncT>(FuseSessionMountMock));
    DlpCMockCondition condition3;
    condition3.mockSequence = { true };
    SetMockConditions("fuse_session_destroy", condition3);
    DlpCMockCondition condition4;
    condition4.mockSequence = { true };
    SetMockConditions("fuse_opt_free_args", condition4);
    DlpCMockCondition condition5;
    condition5.mockSequence = { true };
    SetMockConditions("fuse_session_loop", condition5);

    FuseDaemon::FuseFsDaemonThread(1);
    EXPECT_EQ(0, FuseDaemon::WaitDaemonEnable());
    CleanMockConditions();
}

/**
 * @tc.name: FuseDaemonInit001
 * @tc.desc: FuseDaemonInit
 * @tc.type: FUNC
 * @tc.require:AR000GVIGC
 */
HWTEST_F(FuseDaemonTest, FuseDaemonInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FuseDaemonInit001");

    FuseDaemon::fuseDaemonOper_.init(nullptr, nullptr);

    fuse_conn_info conn = { 0 };
    FuseDaemon::fuseDaemonOper_.init(nullptr, &conn);
    EXPECT_EQ(FUSE_CAP_WRITEBACK_CACHE, conn.want);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS