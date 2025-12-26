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

#include "dlp_zip_file_test.h"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#define private public
#include "dlp_file.h"
#include "dlp_raw_file.h"
#include "dlp_zip_file.h"
#include "dlp_file_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_zip.h"
#include "c_mock_common.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpZipFileTest"};
static constexpr int32_t SECOND = 2;

void initDlpFileCiper(DlpZipFile &testFile)
{
    uint8_t keyData[16] = {};
    struct DlpBlob key = {
        .data = keyData,
        .size = 16
    };

    uint8_t ivData[16] = {};
    struct DlpCipherParam param;
    param.iv.data = ivData;
    param.iv.size = IV_SIZE;
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    testFile.policy_.dlpVersion_ = SECOND;
    testFile.version_ = SECOND;

    testFile.SetCipher(key, spec, hmacKey);
    uint8_t* cert = new (std::nothrow) uint8_t[16];
    if (cert == nullptr) {
        return;
    }
    struct DlpBlob certKey = {
        .data = cert,
        .size = 16
    };
    testFile.SetEncryptCert(certKey);
    delete[] certKey.data;
    certKey.data = nullptr;
    certKey.size = 0;
}
}

void DlpZipFileTest::SetUpTestCase() {}

void DlpZipFileTest::TearDownTestCase() {}

void DlpZipFileTest::SetUp() {}

void DlpZipFileTest::TearDown() {}

/**
 * @tc.name: AddFileContextToZip001
 * @tc.desc: test AddFileContextToZip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, IsZipFile, TestSize.Level0)
{
    std::vector<uint8_t> cert;
    DlpBlob certBlob = { 0, nullptr };
    std::shared_ptr<DlpZipFile> filePtr = std::make_shared<DlpZipFile>(-1, DLP_TEST_DIR, 0, "txt");
    ASSERT_EQ(filePtr->UpdateCertAndText(cert, certBlob), DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL);
    ASSERT_NE(filePtr->GenFile(-1), DLP_OK);
    ASSERT_NE(filePtr->GenFile(0), DLP_OK);
}

/**
 * @tc.name: GetOfflineCertSizeTest
 * @tc.desc: test GetOfflineCertSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, GetOfflineCertSizeTest, TestSize.Level0)
{
    std::vector<uint8_t> cert;
    std::shared_ptr<DlpZipFile> filePtr = std::make_shared<DlpZipFile>(-1, DLP_TEST_DIR, 0, "txt");
    ASSERT_EQ(filePtr->GetOfflineCertSize(), 0);
}

/**
 * @tc.name: SetOfflineAccessTest001
 * @tc.desc: SetOfflineAccess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, SetOfflineAccessTest001, TestSize.Level0)
{
    std::shared_ptr<DlpZipFile> testFile = std::make_shared<DlpZipFile>(1000, DLP_TEST_DIR, 0, "txt");
    ASSERT_NE(testFile, nullptr);

    int32_t allowedOpenCount = 0;
    bool flag = true;

    testFile->SetOfflineAccess(flag, allowedOpenCount);
    EXPECT_EQ(1, testFile->offlineAccess_);

    allowedOpenCount = 1;
    testFile->SetOfflineAccess(flag, allowedOpenCount);
    EXPECT_NE(1, testFile->offlineAccess_);
}

/**
 * @tc.name: CheckDlpFile001
 * @tc.desc: CheckDlpFile test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, CheckDlpFile001, TestSize.Level0)
{
    std::shared_ptr<DlpZipFile> testFile = std::make_shared<DlpZipFile>(1000, DLP_TEST_DIR, 0, "txt");
    ASSERT_NE(testFile, nullptr);

    EXPECT_EQ(DLP_OK, testFile->CheckDlpFile());
}

/**
 * @tc.name: CheckDlpFile002
 * @tc.desc: CheckDlpFile test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, CheckDlpFile002, TestSize.Level0)
{
    std::shared_ptr<DlpZipFile> testFile = std::make_shared<DlpZipFile>(0, DLP_TEST_DIR, 0, "txt");
    ASSERT_NE(testFile, nullptr);

    testFile->SetLinkStatus();

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_LINKING, testFile->CheckDlpFile());
}

/**
 * @tc.name: SetEncryptCert001
 * @tc.desc: test set encrypt cert params invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, SetEncryptCert001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert001");

    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);
    struct DlpBlob cert = {
        .data = nullptr,
        .size = 0
    };

    // size = 0
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetEncryptCert(cert));
    // size too large
    uint8_t data[16] = {};
    cert.data = data;
    cert.size = DLP_MAX_CERT_SIZE + 1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetEncryptCert(cert));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: SetEncryptCert002
 * @tc.desc: test set encrypt cert when cert has exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, SetEncryptCert002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert002");

    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);
    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = 32
    };
    uint8_t *oldCert = new (std::nothrow) uint8_t[16];
    testFile.cert_.data = oldCert;
    testFile.cert_.size = 16;
    ASSERT_NE(testFile.cert_.data, nullptr);

    EXPECT_EQ(DLP_OK, testFile.SetEncryptCert(cert));
    EXPECT_NE(oldCert, testFile.cert_.data);

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: SetEncryptCert003
 * @tc.desc: test set encrypt cert when copy blob fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, SetEncryptCert003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetEncryptCert003");

    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = 0
    };

    EXPECT_EQ(DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL, testFile.SetEncryptCert(cert));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: SetContactAccount001
 * @tc.desc: test set contact account invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, SetContactAccount001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetContactAccount001");

    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    EXPECT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetContactAccount(""));
    std::string invalidAccount(DLP_MAX_CERT_SIZE + 1, 'a');
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.SetContactAccount(invalidAccount));
    ASSERT_EQ(DLP_OK, testFile.SetContactAccount("testAccount"));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: UpdateDlpFileContentSize001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, UpdateDlpFileContentSize001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UpdateDlpFileContentSize001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.UpdateDlpFileContentSize());
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.UpdateDlpFileContentSize());
    CleanMockConditions();
    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_FORMAT_ERROR, testFile.UpdateDlpFileContentSize());
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DlpFileRead001
 * @tc.desc: test dlp file read
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, DlpFileRead001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpFileRead001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    int32_t uid = getuid();
    bool hasRead = true;
    // isFuseLink_ true
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, nullptr, 10, hasRead, uid));
    uint8_t buffer[16] = {};
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 0, hasRead, uid));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(DLP_MAX_RAW_CONTENT_SIZE, buffer, 1, hasRead, uid));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, DLP_FUSE_MAX_BUFFLEN + 1, hasRead, uid));
    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 16, hasRead, uid));
    testFile.dlpFd_ = fdDlp;
    testFile.cipher_.encKey.size = 0;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileRead(0, buffer, 16, hasRead, uid));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: WriteFirstBlockData001
 * @tc.desc: test write dlp file first block
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, WriteFirstBlockData001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "WriteFirstBlockData001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    uint8_t writeBuffer[16] = {0x1};
    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    testFile.dlpFd_ = fdDlp;
    DlpCMockCondition condition;
    // lseek fail
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();
    // write fail
    lseek(fdDlp, 0, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.WriteFirstBlockData(4, writeBuffer, 16));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DoDlpFileWrite001
 * @tc.desc: test do dlp file write
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, DoDlpFileWrite001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DoDlpFileWrite001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    uint8_t writeBuffer[18] = {0x1};
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();
    condition.mockSequence = { true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("memcpy_s", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();
    condition.mockSequence = { true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();
    condition.mockSequence = { false, true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();
    condition.mockSequence = { false, true };
    lseek(fdDlp, 0, SEEK_SET);
    SetMockConditions("write", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_OPERATE_FAIL, testFile.DoDlpFileWrite(0, writeBuffer, 18));
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: DlpFileWrite001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, DlpFileWrite001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpFileWrite001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    uint8_t writeBuffer[16] = {0x1};
    testFile.authPerm_ = DLPFileAccess::READ_ONLY;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, testFile.DlpFileWrite(4, writeBuffer, 16));
    testFile.authPerm_ = DLPFileAccess::FULL_CONTROL;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, nullptr, 16));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 0));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(DLP_MAX_RAW_CONTENT_SIZE, writeBuffer, 1));
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, DLP_FUSE_MAX_BUFFLEN + 1));
    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 16));
    testFile.dlpFd_ = fdDlp;
    testFile.cipher_.encKey.size = 0;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.DlpFileWrite(4, writeBuffer, 16));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

/**
 * @tc.name: Truncate001
 * @tc.desc: test get dlp file content size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipFileTest, Truncate001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "Truncate001");
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdPlain, -1);
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fdDlp, -1);

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, 0, "txt");
    initDlpFileCiper(testFile);

    testFile.authPerm_ = DLPFileAccess::READ_ONLY;
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, testFile.Truncate(16));
    testFile.authPerm_ = DLPFileAccess::FULL_CONTROL;
    testFile.dlpFd_ = -1;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.Truncate(16));
    testFile.dlpFd_ = fdDlp;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, testFile.Truncate(0xffffffff));

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}