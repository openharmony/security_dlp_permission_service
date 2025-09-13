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

#include "dlp_raw_file_test.h"
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
#include "dlp_crypt.h"
#include "dlp_permission.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static const uint64_t DLP_CERT_SIZE = 1024 * 1024;
static const uint32_t DLP_HEAD_SIZE = 10 * 1024 * 1024;
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static constexpr int32_t SECOND = 2;
}

void DlpRawFileTest::SetUpTestCase() {}

void DlpRawFileTest::TearDownTestCase() {}

void DlpRawFileTest::SetUp() {}

void DlpRawFileTest::TearDown() {}

/**
 * @tc.name: ParseRawDlpHeaderTest
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest, TestSize.Level0)
{
    uint64_t fileLen = DLP_CERT_SIZE;
    uint32_t dlpHeaderSize = DLP_HEAD_SIZE;
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_EQ(filePtr->ParseRawDlpHeader(fileLen, dlpHeaderSize), DLP_PARSE_ERROR_FD_ERROR);
}

/**
 * @tc.name: ParseRawDlpHeaderTest002
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest002, TestSize.Level0)
{
    int32_t fd = open("/data/fuse_test_dlp.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = 10,
        .offlineAccess = 0,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + 108,
        .txtSize = 100,
        .hmacOffset = sizeof(struct DlpHeader) + 208,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + 272,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 8,
        .contactAccountSize = 100,
        .offlineCertOffset = sizeof(struct DlpHeader) + 272,
        .offlineCertSize = 0
    };
    uint32_t version = 3;
    uint32_t dlpHeaderSize = sizeof(struct DlpHeader);
    write(fd, &version, sizeof(struct DlpHeader));
    write(fd, &dlpHeaderSize, sizeof(struct DlpHeader));
    uint8_t buffer[800] = {0};
    write(fd, buffer, 800);

    lseek(fd, 8, SEEK_SET);
    write(fd, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    lseek(fd, header.certOffset, SEEK_SET);
    write(fd, certStr.c_str(), certStr.length());
    lseek(fd, 0, SEEK_SET);
    filePtr->ParseRawDlpHeader(dlpHeaderSize, dlpHeaderSize);
    close(fd);
    unlink("/data/fuse_test_dlp.txt");
    fd = -1;
}

/**
 * @tc.name: ParseRawDlpHeaderTest003
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest003, TestSize.Level0)
{
    int32_t fd = open("/data/fuse_test_dlp.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = 10,
        .offlineAccess = 0,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + 108,
        .txtSize = 100,
        .hmacOffset = sizeof(struct DlpHeader) + 208,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + 272,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 8,
        .contactAccountSize = 100,
        .offlineCertOffset = sizeof(struct DlpHeader) + 272,
        .offlineCertSize = 0
    };
    uint32_t version = 3;
    uint32_t dlpHeaderSize = sizeof(struct DlpHeader);
    write(fd, &version, sizeof(struct DlpHeader));
    write(fd, &dlpHeaderSize, sizeof(struct DlpHeader));
    uint8_t buffer[800] = {0};
    write(fd, buffer, 800);

    lseek(fd, 8, SEEK_SET);
    write(fd, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    lseek(fd, header.certOffset, SEEK_SET);
    write(fd, certStr.c_str(), certStr.length());
    lseek(fd, 0, SEEK_SET);
    filePtr->ParseRawDlpHeader(DLP_HEAD_SIZE + 808, DLP_HEAD_SIZE);
    close(fd);
    unlink("/data/fuse_test_dlp.txt");
    fd = -1;
}

/**
 * @tc.name: ParseRawDlpHeaderTest004
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest004, TestSize.Level0)
{
    int32_t fd = open("/data/fuse_test_dlp.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = 10,
        .offlineAccess = 0,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + 108,
        .txtSize = 100,
        .hmacOffset = sizeof(struct DlpHeader) + 208,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + 272,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 8,
        .contactAccountSize = 100,
        .offlineCertOffset = sizeof(struct DlpHeader) + 272,
        .offlineCertSize = 0
    };
    uint32_t version = 3;
    uint32_t dlpHeaderSize = sizeof(struct DlpHeader);
    write(fd, &version, sizeof(struct DlpHeader));
    write(fd, &dlpHeaderSize, sizeof(struct DlpHeader));
    uint8_t buffer[800] = {0};
    write(fd, buffer, 800);

    lseek(fd, 8, SEEK_SET);
    write(fd, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    lseek(fd, header.certOffset, SEEK_SET);
    write(fd, certStr.c_str(), certStr.length());
    lseek(fd, 0, SEEK_SET);
    filePtr->ParseRawDlpHeader(808, dlpHeaderSize);
    close(fd);
    unlink("/data/fuse_test_dlp.txt");
    fd = -1;
}

/**
 * @tc.name: ParseRawDlpHeaderTest005
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest005, TestSize.Level0)
{
    int32_t fd = open("/data/fuse_test_dlp.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = 10,
        .offlineAccess = 0,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + 108,
        .txtSize = 0,
        .hmacOffset = sizeof(struct DlpHeader) + 108,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + 172,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 8,
        .contactAccountSize = 100,
        .offlineCertOffset = sizeof(struct DlpHeader) + 272,
        .offlineCertSize = 0
    };
    uint32_t version = 3;
    uint32_t dlpHeaderSize = sizeof(struct DlpHeader);
    write(fd, &version, sizeof(struct DlpHeader));
    write(fd, &dlpHeaderSize, sizeof(struct DlpHeader));
    uint8_t buffer[800] = {0};
    write(fd, buffer, 800);

    lseek(fd, 8, SEEK_SET);
    write(fd, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    lseek(fd, header.certOffset, SEEK_SET);
    write(fd, certStr.c_str(), certStr.length());
    lseek(fd, 0, SEEK_SET);
    filePtr->ParseRawDlpHeader(400, dlpHeaderSize);
    close(fd);
    unlink("/data/fuse_test_dlp.txt");
    fd = -1;
}

/**
 * @tc.name: ParseRawDlpHeaderTest006
 * @tc.desc: test ParseRawDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseRawDlpHeaderTest006, TestSize.Level0)
{
    int32_t fd = open("/data/fuse_test_dlp.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr, nullptr);

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = 10,
        .offlineAccess = 0,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + 108,
        .txtSize = 0,
        .hmacOffset = sizeof(struct DlpHeader) + 108,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + 172,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + 8,
        .contactAccountSize = 100,
        .offlineCertOffset = sizeof(struct DlpHeader) + 272,
        .offlineCertSize = 0
    };
    uint32_t version = 3;
    uint32_t dlpHeaderSize = sizeof(struct DlpHeader);
    write(fd, &version, sizeof(struct DlpHeader));
    write(fd, &dlpHeaderSize, sizeof(struct DlpHeader));
    uint8_t buffer[800] = {0};
    write(fd, buffer, 800);

    lseek(fd, 8, SEEK_SET);
    write(fd, &header, sizeof(struct DlpHeader));
    std::string certStr = "{\"aeskeyLen\":16, \"aeskey\":\"11223344556677889900112233445566\",\"ivLen\":16,"
        "\"iv\":\"11223344556677889900112233445566\",\"ownerAccount\":\"test\",\"ownerAccountId\":\"test\","
        "\"ownerAccountType\":0}";
    lseek(fd, header.certOffset, SEEK_SET);
    write(fd, certStr.c_str(), certStr.length());
    lseek(fd, 0, SEEK_SET);
    filePtr->ParseRawDlpHeader(808, dlpHeaderSize);
    close(fd);
    unlink("/data/fuse_test_dlp.txt");
    fd = -1;
}

/**
 * @tc.name: HmacCheckTest
 * @tc.desc: test HmacCheck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, HmacCheckTest, TestSize.Level0)
{
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    filePtr->version_ = SECOND;
    ASSERT_EQ(filePtr->HmacCheck(), DLP_OK);
}

/**
 * @tc.name: GetOfflineCertSizeTest
 * @tc.desc: test GetOfflineCertSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, GetOfflineCertSizeTest, TestSize.Level0)
{
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_EQ(filePtr->GetOfflineCertSize(), 0);
}

/**
 * @tc.name: DoDlpHIAECryptOperationTest
 * @tc.desc: test DoDlpHIAECryptOperation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, DoDlpHIAECryptOperationTest, TestSize.Level0)
{
    DlpBlob message1 = { 0, nullptr };
    DlpBlob message2 = { 0, nullptr };
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_EQ(filePtr->DoDlpHIAECryptOperation(message1, message2, 0, true), DLP_PARSE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: ParseEnterpriseFileId
 * @tc.desc: test ParseEnterpriseFileId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, ParseEnterpriseFileIdTest, TestSize.Level1)
{
    std::shared_ptr<DlpRawFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_NE(filePtr->ParseEnterpriseFileId(0, 0), DLP_OK);
}
