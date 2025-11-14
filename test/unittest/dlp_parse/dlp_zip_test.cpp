/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dlp_zip_test.h"
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
#include "dlp_file_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_zip.h"
#include "c_mock_common.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileTest"};

static const std::string DLP_TEST_DIR = "/data/dlpTest/";
static constexpr int32_t DLP_ZIP_OK = 0;
static constexpr int32_t DLP_ZIP_FAIL = -1;

static int ZipCloseFileInZipReply(zipFile file)
{
    zipCloseFileInZip(file);
    return DLP_ZIP_FAIL;
}

static int ZipCloseReply(zipFile file, const char* globalComment)
{
    zipClose(file, NULL);
    return DLP_ZIP_FAIL;
}

static int UnzGetFileInfoReply(unzFile file, unz_file_info64* pfile_info,
                               char* szFileName, uLong fileNameBufferSize,
                               void* extraField, uLong extraFiledBufferSize,
                               char* szComment, uLong commentBufferSize)
{
    static bool success = true;
    unzGetCurrentFileInfo64(file, pfile_info, szFileName, fileNameBufferSize,
                            extraField, extraFiledBufferSize, szComment, commentBufferSize);
    if (success) {
            pfile_info->compressed_size = 0;
            pfile_info->uncompressed_size = 1;
    } else {
            pfile_info->compressed_size = 0;
            pfile_info->uncompressed_size = 1;
    }
    success = false;
    return UNZ_OK;
}

static int UnzCloseReply(zipFile file)
{
    unzClose(file);
    return DLP_ZIP_FAIL;
}

static void CloseAndUnlink(int32_t fd, const char* path)
{
    close(fd);
    unlink(path);
}

void initDlpFileCiper(DlpFile &testFile)
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

    testFile.SetCipher(key, spec, hmacKey);
}
}

void DlpZipTest::SetUpTestCase()
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

void DlpZipTest::TearDownTestCase()
{
    rmdir(DLP_TEST_DIR.c_str());
}

void DlpZipTest::SetUp() {}

void DlpZipTest::TearDown() {}

/**
 * @tc.name: AddBuffToZip001
 * @tc.desc: test AddBuffToZip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip001");
    std::string buf("123");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t res = AddBuffToZip(buf.c_str(), buf.size(), inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, -1);

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    res = AddBuffToZip(buf.c_str(), buf.size(), inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, 0);

    res = AddBuffToZip(buf.c_str(), buf.size(), inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, 0);

    CloseAndUnlink(fd, zipFile.c_str());
}

/**
 * @tc.name: AddBuffToZip002
 * @tc.desc: AddBuffToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip002");

    std::string buf("123");
    std::string nameInZip("dlp_general_info");
    std::string zipName("dlp_test_zip");

    int32_t fd = open(zipName.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipOpenNewFileInZip3_64", condition);

    int32_t res = AddBuffToZip(nullptr, 0, nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at buf == nullptr
    res = AddBuffToZip(buf.c_str(), buf.size(), nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at zipOpenNewFileInZip3_64

    CleanMockConditions();
    CloseAndUnlink(fd, zipName.c_str());
}

/**
 * @tc.name: AddBuffToZip003
 * @tc.desc: AddBuffToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip003");

    std::string buf("123");
    std::string nameInZip("dlp_general_info");
    std::string zipName("dlp_test_zip");

    int32_t fd = open(zipName.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    
    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipWriteInFileInZip", condition);

    int32_t res = AddBuffToZip(buf.c_str(), buf.size(), nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at zipWriteInFileInZip

    CleanMockConditions();
    CloseAndUnlink(fd, zipName.c_str());
}

/**
 * @tc.name: AddBuffToZip004
 * @tc.desc: AddBuffToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip004");

    std::string buf("123");
    std::string nameInZip("dlp_general_info");
    std::string zipName("dlp_test_zip");

    int32_t fd = open(zipName.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipWriteInFileInZip", condition);

    int32_t res = AddBuffToZip(buf.c_str(), buf.size(), nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at AddZeroBuffToZip

    CleanMockConditions();
    CloseAndUnlink(fd, zipName.c_str());
}

/**
 * @tc.name: AddBuffToZip005
 * @tc.desc: AddBuffToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip005");

    std::string buf("123");
    std::string nameInZip("dlp_general_info");
    std::string zipName("dlp_test_zip");

    int32_t fd = open(zipName.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipCloseFileInZip", condition);
    SetMockCallback("zipCloseFileInZip", reinterpret_cast<CommonMockFuncT>(ZipCloseFileInZipReply));

    int32_t res = AddBuffToZip(buf.c_str(), buf.size(), nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at zipCloseFileInZip

    CleanMockConditions();
    CloseAndUnlink(fd, zipName.c_str());
}

/**
 * @tc.name: AddBuffToZip006
 * @tc.desc: AddBuffToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddBuffToZip006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip006");

    std::string buf("123");
    std::string nameInZip("dlp_general_info");
    std::string zipName("dlp_test_zip");

    int32_t fd = open(zipName.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipClose", condition);
    SetMockCallback("zipClose", reinterpret_cast<CommonMockFuncT>(ZipCloseReply));

    int32_t res = AddBuffToZip(buf.c_str(), buf.size(), nameInZip.c_str(), zipName.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);   // fail at zipClose

    CleanMockConditions();
    CloseAndUnlink(fd, zipName.c_str());
}

/**
 * @tc.name: AddFileContextToZip001
 * @tc.desc: test AddFileContextToZip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip001");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t res = AddFileContextToZip(-1, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, -1);

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, 0);

    res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, 0);

    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip002
 * @tc.desc: AddFileContextToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip002");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd2, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipOpenNewFileInZip3_64", condition);

    int32_t res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_FAIL);  // fail at zipOpenNewFileInZip3_64

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip003
 * @tc.desc: AddFileContextToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip003");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd2, -1);
    std::string data = "123";
    write(fd2, data.c_str(), data.size());
    lseek(fd2, 0, SEEK_SET);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipWriteInFileInZip", condition);

    int32_t res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_FAIL);  // fail at zipWriteInFileInZip

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip004
 * @tc.desc: AddFileContextToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip004");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd2, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("read", condition);

    int32_t res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_FAIL);  // fail at read

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip005
 * @tc.desc: AddFileContextToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip005");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd2, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipCloseFileInZip", condition);
    SetMockCallback("zipCloseFileInZip", reinterpret_cast<CommonMockFuncT>(ZipCloseFileInZipReply));

    int32_t res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_FAIL);  // fail at zipCloseFileInZip

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip006
 * @tc.desc: AddFileContextToZip abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip006");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd, -1);

    int32_t fd2 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_NE(fd2, -1);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("zipClose", condition);
    SetMockCallback("zipClose", reinterpret_cast<CommonMockFuncT>(ZipCloseReply));

    int32_t res = AddFileContextToZip(fd2, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_FAIL);  // fail at zipClose

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: CheckUnzipFileInfo001
 * @tc.desc: CheckUnzipFileInfo abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, CheckUnzipFileInfo001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "CheckUnzipFileInfo001");

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzOpen2", condition);

    int32_t res = CheckUnzipFileInfo(-1);
    ASSERT_EQ(false, res);  // fail at unzOpen2

    CleanMockConditions();
}


/**
 * @tc.name: CheckUnzipFileInfo002
 * @tc.desc: CheckUnzipFileInfo abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, CheckUnzipFileInfo002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "CheckUnzipFileInfo002");

    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd2 = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t res = AddFileContextToZip(fd, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);
    res = IsZipFile(fd2);
    ASSERT_EQ(true, res);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzGetGlobalInfo64", condition);

    res = CheckUnzipFileInfo(fd2);
    ASSERT_EQ(false, res); // fail at unzGetGlobalInfo64

    CleanMockConditions();
    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: CheckUnzipFileInfo003
 * @tc.desc: CheckUnzipFileInfo abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, CheckUnzipFileInfo003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "CheckUnzipFileInfo003");

    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t fd = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd2 = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t res = AddFileContextToZip(fd, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);
    res = IsZipFile(fd2);
    ASSERT_EQ(true, res);

    res = CheckUnzipFileInfo(fd2);
    ASSERT_EQ(false, res); // fail at checkout FILE_COUNT

    CloseAndUnlink(fd, inZip.c_str());
    CloseAndUnlink(fd2, zipFile.c_str());
}

/**
 * @tc.name: CheckUnzipFileInfo004
 * @tc.desc: CheckUnzipFileInfo abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, CheckUnzipFileInfo004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "CheckUnzipFileInfo004");

    std::string inZipInfo("dlp_general_info");
    std::string inZipCert("dlp_cert");
    std::string inZipData("encrypted_data");
    std::string zipFile("test_zip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd1 = open(inZipInfo.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd2 = open(inZipCert.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd3 = open(inZipData.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t res = AddFileContextToZip(fd1, inZipInfo.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);
    res = AddFileContextToZip(fd2, inZipCert.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);
    res = AddFileContextToZip(fd3, inZipData.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);

    res = IsZipFile(fd);
    ASSERT_EQ(true, res);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzGetCurrentFileInfo64", condition);

    res = CheckUnzipFileInfo(fd);
    ASSERT_EQ(false, res); // fail at unzGetCurrentFileInfo64

    CleanMockConditions();
    CloseAndUnlink(fd, zipFile.c_str());
    CloseAndUnlink(fd1, inZipInfo.c_str());
    CloseAndUnlink(fd2, inZipCert.c_str());
    CloseAndUnlink(fd3, inZipData.c_str());
}

/**
 * @tc.name: IsZipFile001
 * @tc.desc: test IsZipFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, IsZipFile, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "IsZipFile");
    std::string inZip1("dlp_general_info1");
    std::string inZip2("dlp_general_info");
    std::string zipFile("test_zip");

    int32_t res = IsZipFile(-1);
    ASSERT_EQ(res, false);

    int32_t fd = open(zipFile.c_str(), O_WRONLY | O_CREAT, 0666);
    res = IsZipFile(-1);
    ASSERT_EQ(res, false);

    int32_t fd2 = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    res = IsZipFile(fd2);
    ASSERT_EQ(res, false);

    int32_t fd3 = open(inZip1.c_str(), O_RDWR | O_CREAT, 0666);
    res = AddFileContextToZip(fd3, inZip1.c_str(), zipFile.c_str());
    res = IsZipFile(fd2);
    ASSERT_EQ(res, false);

    int32_t fd4 = open(inZip2.c_str(), O_RDWR | O_CREAT, 0666);
    res = AddFileContextToZip(fd4, inZip2.c_str(), zipFile.c_str());
    res = IsZipFile(fd2);
    ASSERT_EQ(res, true);

    close(fd);
    close(fd2);
    close(fd3);
    close(fd4);

    unlink(inZip1.c_str());
    unlink(inZip2.c_str());
    unlink(zipFile.c_str());
}

/**
 * @tc.name: UnzipSpecificFile000
 * @tc.desc: UnzipSpecificFile normal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, UnzipSpecificFile000, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnzipSpecificFile000");

    std::string unZip("unzip");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");
    
    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd1 = open(inZip.c_str(), O_RDWR | O_CREAT, 0666);
    std::string data = "123";
    write(fd1, data.c_str(), data.size());
    lseek(fd1, 0, SEEK_SET);
    
    int32_t res = AddFileContextToZip(fd1, inZip.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);

    res = UnzipSpecificFile(fd, inZip.c_str(), unZip.c_str());
    ASSERT_EQ(DLP_ZIP_OK, res);

    CleanMockConditions();
}

/**
 * @tc.name: UnzipSpecificFile001
 * @tc.desc: UnzipSpecificFile abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, UnzipSpecificFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnzipSpecificFile001");

    std::string unZip("unzip");
    std::string inZip("dlp_general_info");
    std::string zipFile("test_zip");

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzOpen2", condition);

    int32_t res = UnzipSpecificFile(-1, inZip.c_str(), unZip.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);  // fail at OpenZipFile

    CleanMockConditions();
}

/**
 * @tc.name: UnzipSpecificFile002
 * @tc.desc: UnzipSpecificFile abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, UnzipSpecificFile002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnzipSpecificFile002");

    std::string inZipInfo("dlp_general_info");
    std::string zipFile("test_zip");
    std::string unZip("unzip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd1 = open(inZipInfo.c_str(), O_RDWR | O_CREAT, 0666);
    std::string data = "123";
    write(fd1, data.c_str(), data.size());
    lseek(fd1, 0, SEEK_SET);
    
    int32_t res = AddFileContextToZip(fd1, inZipInfo.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);

    res = IsZipFile(fd);
    ASSERT_EQ(true, res);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzLocateFile", condition);

    res = UnzipSpecificFile(fd, inZipInfo.c_str(), unZip.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);  // fail at unzLocateFile
    CleanMockConditions();
    CloseAndUnlink(fd, zipFile.c_str());
    CloseAndUnlink(fd1, inZipInfo.c_str());
}

/**
 * @tc.name: UnzipSpecificFile003
 * @tc.desc: UnzipSpecificFile abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, UnzipSpecificFile003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnzipSpecificFile003");

    std::string inZipInfo("dlp_general_info");
    std::string zipFile("test_zip");
    std::string unZip("unzip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd1 = open(inZipInfo.c_str(), O_RDWR | O_CREAT, 0666);
    std::string data = "123";
    write(fd1, data.c_str(), data.size());
    lseek(fd1, 0, SEEK_SET);
    
    int32_t res = AddFileContextToZip(fd1, inZipInfo.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);

    res = IsZipFile(fd);
    ASSERT_EQ(true, res);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzOpenCurrentFile", condition);

    res = UnzipSpecificFile(fd, inZipInfo.c_str(), unZip.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);  // fail at unzOpenCurrentFile
    CleanMockConditions();
    CloseAndUnlink(fd, zipFile.c_str());
    CloseAndUnlink(fd1, inZipInfo.c_str());
}

/**
 * @tc.name: UnzipSpecificFile004
 * @tc.desc: UnzipSpecificFile abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, UnzipSpecificFile004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnzipSpecificFile004");

    std::string inZipInfo("dlp_general_info");
    std::string zipFile("test_zip");
    std::string unZip("unzip");

    int32_t fd = open(zipFile.c_str(), O_RDWR | O_CREAT, 0666);
    int32_t fd1 = open(inZipInfo.c_str(), O_RDWR | O_CREAT, 0666);
    std::string data = "123";
    write(fd1, data.c_str(), data.size());
    lseek(fd1, 0, SEEK_SET);
    
    int32_t res = AddFileContextToZip(fd1, inZipInfo.c_str(), zipFile.c_str());
    ASSERT_EQ(res, DLP_ZIP_OK);

    res = IsZipFile(fd);
    ASSERT_EQ(true, res);

    DlpCMockCondition condition;
    condition.mockSequence = {true};
    SetMockConditions("unzReadCurrentFile", condition);

    DlpCMockCondition condition1;
    condition1.mockSequence = {true};
    SetMockConditions("unzCloseCurrentFile", condition1);

    DlpCMockCondition condition2;
    condition2.mockSequence = {true};
    SetMockConditions("unzClose", condition2);
    SetMockCallback("unzClose", reinterpret_cast<CommonMockFuncT>(UnzCloseReply));

    res = UnzipSpecificFile(fd, inZipInfo.c_str(), unZip.c_str());
    ASSERT_EQ(DLP_ZIP_FAIL, res);
    CleanMockConditions();
    CloseAndUnlink(fd, zipFile.c_str());
    CloseAndUnlink(fd1, inZipInfo.c_str());
}