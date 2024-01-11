/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlp_file_manager_test.h"
#include "c_mock_common.h"
#define private public
#include "dlp_file_manager.h"
#undef private
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace std;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileManagerTest"};
static int g_fdDlp = -1;
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
}

void DlpFileManagerTest::SetUpTestCase()
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

void DlpFileManagerTest::TearDownTestCase()
{
    if (g_fdDlp != -1) {
        close(g_fdDlp);
        unlink("/data/fuse_test_dlp.txt");
        g_fdDlp = -1;
    }
    rmdir(DLP_TEST_DIR.c_str());
}

void DlpFileManagerTest::SetUp() {}

void DlpFileManagerTest::TearDown() {}

/**
 * @tc.name: OperDlpFileNode001
 * @tc.desc: test add/remove/get dlp file node.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OperDlpFileNode001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OperDlpFileNode001");

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_ALREADY_OPENED);
    EXPECT_NE(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_OK);
    EXPECT_EQ(DlpFileManager::GetInstance().GetDlpFile(1), nullptr);
    DlpFileManager::GetInstance().g_DlpFileMap_[1] = filePtr;
    EXPECT_EQ(DlpFileManager::GetInstance().GetDlpFile(1), filePtr);
    DlpFileManager::GetInstance().g_DlpFileMap_.clear();
    EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr), DLP_PARSE_ERROR_FILE_NOT_OPENED);
}

/**
 * @tc.name: OperDlpFileNode002
 * @tc.desc: test add too many dlp file nodes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OperDlpFileNode002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OperDlpFileNode002");

    std::shared_ptr<DlpFile> openDlpFiles[1000];

    for (int i = 0; i < 1000; i++) {
        std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(i, DLP_TEST_DIR, i, false);
        openDlpFiles[i] = filePtr;
        EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr), DLP_OK);
    }

    std::shared_ptr<DlpFile> filePtr1 = std::make_shared<DlpFile>(1001, DLP_TEST_DIR, 0, false);
    EXPECT_EQ(DlpFileManager::GetInstance().AddDlpFileNode(filePtr1), DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE);

    for (int i = 0; i < 1000; i++) {
        EXPECT_EQ(DlpFileManager::GetInstance().RemoveDlpFileNode(openDlpFiles[i]), DLP_OK);
    }
}

/**
 * @tc.name: GenerateCertData001
 * @tc.desc: Generate cert data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateCertData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateCertData001");

    PermissionPolicy policy;
    struct DlpBlob certData;
    EXPECT_EQ(DlpFileManager::GetInstance().GenerateCertData(policy, certData), DLP_SERVICE_ERROR_VALUE_INVALID);

    policy.aeskey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.aeskey_, nullptr);
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.iv_, nullptr);
    policy.ivLen_ = 16;
    policy.hmacKey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.hmacKey_, nullptr);
    policy.hmacKeyLen_ = 16;

    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    policy.ownerAccount_ = std::string(DLP_MAX_CERT_SIZE + 1, 'a');
    policy.ownerAccountId_ = std::string(DLP_MAX_CERT_SIZE + 1, 'a');
    EXPECT_EQ(DlpFileManager::GetInstance().GenerateCertData(policy, certData), DLP_PARSE_ERROR_VALUE_INVALID);

    policy.ownerAccount_ = "test";
    policy.ownerAccountId_ = "test";
    DlpCMockCondition condition;
    condition.mockSequence = { false, false, true, false, false };
    SetMockConditions("memcpy_s", condition);
    int res = DlpFileManager::GetInstance().GenerateCertData(policy, certData);
    EXPECT_TRUE(res == DLP_OK || res == DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL);
    DLP_LOG_INFO(LABEL, "GenerateCertData001 %{public}d", GetMockConditionCounts("memcpy_s"));
    CleanMockConditions();
}

/**
 * @tc.name: PrepareDlpEncryptParms001
 * @tc.desc: test prepare dlp encrypt params error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, PrepareDlpEncryptParms001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "PrepareDlpEncryptParms001");

    PermissionPolicy policy;
    policy.aeskey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.aeskey_, nullptr);
    policy.aeskeyLen_ = 16;
    policy.iv_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.iv_, nullptr);
    policy.ivLen_ = 16;

    policy.hmacKey_ = new (std::nothrow) uint8_t[16];
    ASSERT_NE(policy.hmacKey_, nullptr);
    policy.hmacKeyLen_ = 16;

    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    policy.ownerAccount_ = "test";
    policy.ownerAccountId_ = "test";
    struct DlpBlob key;
    struct DlpUsageSpec usage;
    struct DlpBlob certData;
    struct DlpBlob hmacKey;

    // key create fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData, hmacKey));
    CleanMockConditions();

    // iv create fail
    condition.mockSequence = { false, true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData, hmacKey));
    CleanMockConditions();

    // create cert data failed with memcpy_s fail
    condition.mockSequence = { false, false, false, false, false, false, false, false, false, false, true };
    SetMockConditions("memcpy_s", condition);
    int res = DlpFileManager::GetInstance().PrepareDlpEncryptParms(policy, key, usage, certData, hmacKey);
    EXPECT_TRUE(res == DLP_OK || res == DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL);
    DLP_LOG_INFO(LABEL, "PrepareDlpEncryptParms001 %{public}d", GetMockConditionCounts("memcpy_s"));
    CleanMockConditions();
}

/**
 * @tc.name: ParseDlpFileFormat001
 * @tc.desc: test parse dlp file format error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFileContentSize001");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    std::string appId = "test_appId_passed";

    filePtr->dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, "", appId));
    filePtr->dlpFd_ = g_fdDlp;

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 64,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 32,
        .contactAccountOffset = sizeof(struct DlpHeader) + 32,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    uint8_t buffer[64] = {0};
    write(g_fdDlp, buffer, 64);
    lseek(g_fdDlp, 0, SEEK_SET);
    EXPECT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL,
        DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, "", appId));

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: ParseDlpFileFormat002
 * @tc.desc: test parse dlp file formate error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpFileFormat002");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);

    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 256 + 32,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 256,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    write(g_fdDlp, certStr.c_str(), certStr.length());
    lseek(g_fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(g_fdDlp, buffer, 32);

    lseek(g_fdDlp, 0, SEEK_SET);
    std::string appId = "test_appId_passed";
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, "", appId));

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: ParseDlpFileFormat003
 * @tc.desc: test parse dlp file formate error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ParseDlpFileFormat003");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .version = 1,
        .txtOffset = sizeof(struct DlpHeader) + 256 + 32,
        .txtSize = 0,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 256,
        .contactAccountSize = 32
    };

    write(g_fdDlp, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":1}";
    write(g_fdDlp, certStr.c_str(), certStr.length());
    lseek(g_fdDlp, sizeof(struct DlpHeader) + 256, SEEK_SET);
    uint8_t buffer[32] = {0};
    write(g_fdDlp, buffer, 32);

    lseek(g_fdDlp, 0, SEEK_SET);

    // make SetCipher failed
    DlpCMockCondition condition;
    condition.mockSequence = { false, false, false, false, false, false, false, true };
    SetMockConditions("memcpy_s", condition);
    std::string appId = "test_appId_passed";
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, "", appId));
    CleanMockConditions();

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: ParseDlpFileFormat004
 * @tc.desc: test parse dlp file formate error with offineAccess is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, ParseDlpFileFormat004, TestSize.Level1)
{
        DLP_LOG_INFO(LABEL, "UpdateDlpFileContentSize001");
    g_fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(g_fdDlp, -1);
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(g_fdDlp, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    filePtr->SetOfflineAccess(true);

    std::string appId = "test_appId_passed";
    filePtr->dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, DlpFileManager::GetInstance().ParseDlpFileFormat(filePtr, "", appId));

    close(g_fdDlp);
    unlink("/data/fuse_test_dlp.txt");
    g_fdDlp = -1;
}

/**
 * @tc.name: FreeChiperBlob001
 * @tc.desc: test free chiper blob abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, FreeChiperBlob001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FreeChiperBlob001");
    struct DlpBlob key = {
        .data = nullptr,
        .size = 0
    };
    struct DlpBlob certData = {
        .data = nullptr,
        .size = 0
    };

    struct DlpUsageSpec spec = {
        .algParam = nullptr
    };

    struct DlpBlob hmacKey = {
        .data = nullptr,
        .size = 0
    };

    // algparm nullptr
    DlpFileManager::GetInstance().FreeChiperBlob(key, certData, spec, hmacKey);

    // algparm iv nullptr
    spec.algParam = new (std::nothrow) struct DlpCipherParam;
    ASSERT_NE(spec.algParam, nullptr);
    spec.algParam->iv.data = nullptr;
    DlpFileManager::GetInstance().FreeChiperBlob(key, certData, spec, hmacKey);

    ASSERT_EQ(spec.algParam, nullptr);
}

/**
 * @tc.name: SetDlpFileParams001
 * @tc.desc: test set dlp file params with prepare ciper failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams001");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // PrepareDlpEncryptParms fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("RAND_bytes", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();

    // SetCipher fail
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    condition.mockSequence = { false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, true };
    SetMockConditions("memcpy_s", condition);
    int res = DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property);
    EXPECT_TRUE(res == DLP_OK || res == DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL);
    DLP_LOG_INFO(LABEL, "SetDlpFileParams001 %{public}d", GetMockConditionCounts("memcpy_s"));
    CleanMockConditions();
}

/**
 * @tc.name: SetDlpFileParams002
 * @tc.desc: test set dlp file params with set policy failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams002");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "";
    property.ownerAccountId = "";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
}

/**
 * @tc.name: SetDlpFileParams003
 * @tc.desc: test set dlp file params with set cert failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams003");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "account";
    property.ownerAccountType = CLOUD_ACCOUNT;

    DlpCMockCondition condition;
    condition.mockSequence = {
        false, false, false, false, false, false,
        false, false, false, false, true
    };
    SetMockConditions("memcpy_s", condition);
    int res = DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property);
    EXPECT_TRUE(res == DLP_OK || res == DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL);
    CleanMockConditions();
}

/**
 * @tc.name: SetDlpFileParams004
 * @tc.desc: test set dlp file params with contact account empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, SetDlpFileParams004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetDlpFileParams004");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;

    // SetPolicy fail
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property));
    CleanMockConditions();
}

/**
 * @tc.name: GenerateDlpFile001
 * @tc.desc: test generate dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile001");
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    DlpProperty property;
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().GenerateDlpFile(-1, 1000, property, filePtr, DLP_TEST_DIR));

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, -1, property, filePtr, DLP_TEST_DIR));

    DlpFileManager::GetInstance().AddDlpFileNode(filePtr);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_ALREADY_OPENED,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr, DLP_TEST_DIR));
    DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr);
}

/**
 * @tc.name: GenerateDlpFile002
 * @tc.desc: test generate dlp file with wrong property
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile002");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "";
    property.ownerAccountId = "";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr, DLP_TEST_DIR));
}

/**
 * @tc.name: GenerateDlpFile003
 * @tc.desc: test generate dlp file with generate real file failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, GenerateDlpFile003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GenerateDlpFile003");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        DlpFileManager::GetInstance().GenerateDlpFile(1000, 1000, property, filePtr, DLP_TEST_DIR));
}

/**
 * @tc.name: OpenDlpFile001
 * @tc.desc: test open dlp file params with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, OpenDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OpenDlpFile001");
    std::shared_ptr<DlpFile> filePtr;
    DlpProperty property;
    property.ownerAccount = "owner";
    property.ownerAccountId = "owner";
    property.contactAccount = "owner";
    property.ownerAccountType = DOMAIN_ACCOUNT;
    std::string appId = "test_appId_passed";
    std::string appIdFake = "test_appId_failed";

    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().OpenDlpFile(-1, filePtr, "", appId));
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().OpenDlpFile(-1, filePtr, "", appIdFake));

    std::shared_ptr<DlpFile> filePtr1 = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr1, nullptr);
    DlpFileManager::GetInstance().AddDlpFileNode(filePtr1);

    EXPECT_EQ(DLP_OK,
        DlpFileManager::GetInstance().OpenDlpFile(1000, filePtr, "", appId));
    EXPECT_EQ(filePtr1, filePtr);
    DlpFileManager::GetInstance().RemoveDlpFileNode(filePtr1);

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL,
        DlpFileManager::GetInstance().OpenDlpFile(1000, filePtr, "", appId));
}

/**
 * @tc.name: CloseDlpFile001
 * @tc.desc: test close dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, CloseDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CloseDlpFile001");
    EXPECT_EQ(DLP_PARSE_ERROR_PTR_NULL,
        DlpFileManager::GetInstance().CloseDlpFile(nullptr));
}

/**
 * @tc.name: RecoverDlpFile001
 * @tc.desc: test close dlp file with wrong params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileManagerTest, RecoverDlpFile001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RecoverDlpFile001");
    std::shared_ptr<DlpFile> filePtr = nullptr;
    EXPECT_EQ(DLP_PARSE_ERROR_PTR_NULL,
        DlpFileManager::GetInstance().RecoverDlpFile(filePtr, 1000));

    filePtr = std::make_shared<DlpFile>(1000, DLP_TEST_DIR, 0, false);
    ASSERT_NE(filePtr, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR,
        DlpFileManager::GetInstance().RecoverDlpFile(filePtr, -1));
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS