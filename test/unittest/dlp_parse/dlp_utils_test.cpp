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

#include "dlp_utils_test.h"
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include "dlp_file.h"
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_utils.cpp"
#include "c_mock_common.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel UT_LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpUtilsTest"};
static const int32_t DEFAULT_USERID = 100;
static const std::string TXT_STRINGS = "txt";
static const std::string PPT_STRINGS = "ppt";
const int32_t FILEID_SIZE_VALID = 1;
}

void DlpUtilsTest::SetUpTestCase() {}

void DlpUtilsTest::TearDownTestCase() {}

void DlpUtilsTest::SetUp() {}

void DlpUtilsTest::TearDown() {}

/**
 * @tc.name: GetBundleMgrProxy001
 * @tc.desc: test GetBundleMgrProxy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetBundleMgrProxy, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetBundleMgrProxy");
    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        ASSERT_EQ(bundleMgrProxy, nullptr);
    } else {
        ASSERT_NE(bundleMgrProxy, nullptr);
    }
}

/**
 * @tc.name: GetAuthPolicyWithType001
 * @tc.desc: test GetAuthPolicyWithType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetAuthPolicyWithType, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetAuthPolicyWithType");
    std::vector<std::string> authPolicy;
    std::string fileType = "txt";
    DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy);
    fileType = "dlp";
    DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy);
    fileType = "pdf";
    DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy);
    fileType = "wer";
    bool ret = DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy);
    if (ret == false) {
        ASSERT_EQ(ret, false);
    } else {
        ASSERT_EQ(ret, true);
    }
}

/**
 * @tc.name: GetFileTypeBySuffix001
 * @tc.desc: test GetFileTypeBySuffix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFileTypeBySuffix, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFileTypeBySuffix");
    std::string fileType = "txt";
    DlpUtils::GetFileTypeBySuffix(fileType, true);
    fileType = "pdf";
    DlpUtils::GetFileTypeBySuffix(fileType, true);
    fileType = "pic";
    DlpUtils::GetFileTypeBySuffix(fileType, true);
    fileType = "svg";
    DlpUtils::GetFileTypeBySuffix(fileType, true);
    fileType = "txt";
    DlpUtils::GetFileTypeBySuffix(fileType, false);
    fileType = "pdf";
    DlpUtils::GetFileTypeBySuffix(fileType, false);
    fileType = "pic";
    DlpUtils::GetFileTypeBySuffix(fileType, false);
    fileType = "svg";
    DlpUtils::GetFileTypeBySuffix(fileType, false);
    fileType = "aaaa";
    ASSERT_EQ(DlpUtils::GetFileTypeBySuffix(fileType, false), "");
}

/**
 * @tc.name: GetDlpFileRealSuffix001
 * @tc.desc: test GetDlpFileRealSuffix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetDlpFileRealSuffix, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetDlpFileRealSuffix");
    bool isFromUriName = true;
    std::string fileType = "txt";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "pdf";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "pic";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "svg.dlp";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    isFromUriName = false;
    fileType = "txt";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "pdf.dlp";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "pic";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "svg";
    DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName);
    fileType = "aaaa";
    ASSERT_EQ(DlpUtils::GetDlpFileRealSuffix(fileType, isFromUriName), "");
}

/**
 * @tc.name: GetFileNameWithFd001
 * @tc.desc: test GetFileNameWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFileNameWithFd, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFileNameWithFd");
    std::string fileName;
    int32_t fd = 0;
    DlpUtils::GetFileNameWithFd(fd, fileName);
    fd = 1;
    DlpUtils::GetFileNameWithFd(fd, fileName);
    fd = 2;
    DlpUtils::GetFileNameWithFd(fd, fileName);
    fd = -1;
    DlpUtils::GetFileNameWithFd(fd, fileName);
    fd = 3;
    DlpUtils::GetFileNameWithFd(fd, fileName);
    fd = 0;
    ASSERT_NE(DlpUtils::GetFileNameWithFd(fd, fileName), DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID);
}

/**
 * @tc.name: GetFileNameWithDlpFd001
 * @tc.desc: test GetFileNameWithDlpFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFileNameWithDlpFd, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFileNameWithDlpFd");
    std::string fileName;
    int32_t fd = 0;
    DlpUtils::GetFileNameWithDlpFd(fd, fileName);
    fd = 1;
    DlpUtils::GetFileNameWithDlpFd(fd, fileName);
    fd = 2;
    DlpUtils::GetFileNameWithDlpFd(fd, fileName);
    fd = -1;
    DlpUtils::GetFileNameWithDlpFd(fd, fileName);
    fd = 3;
    DlpUtils::GetFileNameWithDlpFd(fd, fileName);
    fd = 0;
    ASSERT_NE(DlpUtils::GetFileNameWithDlpFd(fd, fileName), DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID);
}

/**
 * @tc.name: GetRealTypeWithRawFile001
 * @tc.desc: test GetRealTypeWithRawFile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithRawFile, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithRawFile");
    int32_t fd = 0;
    DlpUtils::GetRealTypeWithRawFile(fd);
    fd = 1;
    DlpUtils::GetRealTypeWithRawFile(fd);
    fd = 2;
    DlpUtils::GetRealTypeWithRawFile(fd);
    fd = -1;
    DlpUtils::GetRealTypeWithRawFile(fd);
    fd = 3;
    DlpUtils::GetRealTypeWithRawFile(fd);
    fd = 0;
    ASSERT_NE(DlpUtils::GetRealTypeWithRawFile(fd), "txt");
}

/**
 * @tc.name: GetFilePathWithFd001
 * @tc.desc: test GetFilePathWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFilePathWithFd, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFilePathWithFd");
    std::string srcFilePath;
    int32_t fd = 0;
    DlpUtils::GetFilePathWithFd(fd, srcFilePath);
    fd = 1;
    DlpUtils::GetFilePathWithFd(fd, srcFilePath);
    fd = 2;
    DlpUtils::GetFilePathWithFd(fd, srcFilePath);
    fd = -1;
    ASSERT_NE(DlpUtils::GetFilePathWithFd(fd, srcFilePath), DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID);
}

/**
 * @tc.name: GetRealTypeWithFd001
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd001, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithFd001");

    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 1,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header));
    lseek(fd, 0, SEEK_SET);
    bool isFromUriName = true;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, true), TXT_STRINGS);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, false), TXT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRealTypeWithFd002
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd002, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithFd002");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 5,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header));
    lseek(fd, 0, SEEK_SET);
    bool isFromUriName = true;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, true), PPT_STRINGS);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, false), PPT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRealTypeWithFd003
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd003, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithFd003");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 1000,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header));
    lseek(fd, 0, SEEK_SET);
    bool isFromUriName = true;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, true), TXT_STRINGS);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, false), DEFAULT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRealTypeWithFd004
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd004, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithFd004");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 1000,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header) - 1);
    lseek(fd, 0, SEEK_SET);
    bool isFromUriName = true;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, true), TXT_STRINGS);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, false), DEFAULT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRealTypeWithFd005
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd005, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRealTypeWithFd004");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 10001,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header) - 1);
    lseek(fd, 0, SEEK_SET);
    bool isFromUriName = true;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, true), TXT_STRINGS);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr, false), DEFAULT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRawFileAllowedOpenCount01
 * @tc.desc: test GetRawFileAllowedOpenCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRawFileAllowedOpenCount01, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRawFileAllowedOpenCount01");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[FILEID_SIZE] = {0};
    write(fd, buffer, FILEID_SIZE);
    std::string field = "1111111111111111111111111111111111111111111111";
    lseek(fd, FILEID_SIZE_OPPOSITE, SEEK_END);
    write(fd, field.c_str(), field.size());
    int32_t allowedOpenCount;
    bool watermark = false;
    ASSERT_NE(DlpUtils::GetRawFileAllowedOpenCount(fd, allowedOpenCount, watermark), DLP_OK);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRawFileAllowedOpenCount02
 * @tc.desc: test GetRawFileAllowedOpenCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRawFileAllowedOpenCount02, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRawFileAllowedOpenCount02");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[FILEID_SIZE] = {0};
    write(fd, buffer, FILEID_SIZE);
    std::string field = "111";
    lseek(fd, FILEID_SIZE_OPPOSITE, SEEK_END);
    write(fd, field.c_str(), field.size());
    int32_t allowedOpenCount;
    bool watermark = false;
    ASSERT_NE(DlpUtils::GetRawFileAllowedOpenCount(fd, allowedOpenCount, watermark), DLP_OK);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRawFileAllowedOpenCount03
 * @tc.desc: test GetRawFileAllowedOpenCount
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRawFileAllowedOpenCount03, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetRawFileAllowedOpenCount03");
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[FILEID_SIZE_VALID] = {0};
    write(fd, buffer, FILEID_SIZE_VALID);
    std::string field = "";
    lseek(fd, FILEID_SIZE_VALID, SEEK_END);
    write(fd, field.c_str(), field.size());
    int32_t allowedOpenCount;
    bool watermark = false;
    ASSERT_NE(DlpUtils::GetRawFileAllowedOpenCount(fd, allowedOpenCount, watermark), DLP_OK);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetFileType
 * @tc.desc: test GetFileType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFileType, TestSize.Level1)
{
    std::string realFileType = "1234567890";
    ASSERT_EQ(DlpUtils::GetFileType(realFileType), false);
    realFileType = "12";
    ASSERT_EQ(DlpUtils::GetFileType(realFileType), false);
    realFileType = DLP_HIAE_TYPE;
    ASSERT_EQ(DlpUtils::GetFileType(realFileType), true);
}

/**
 * @tc.name: GetRealTypeWithFd
 * @tc.desc: test GetRealTypeWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeWithFd, TestSize.Level1)
{
    bool isFromUriName = false;
    std::string generateInfoStr;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(-1, isFromUriName, generateInfoStr), DEFAULT_STRINGS);
    isFromUriName = true;
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(-1, isFromUriName, generateInfoStr), DEFAULT_STRINGS);
    int fd = open("/data/fuse_test.txt.dlp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = 20,
        .contactAccountSize = 20,
        .fileType = 1000,
    };
    uint8_t buffer[8] = {0};
    write(fd, buffer, 8);
    write(fd, &header, sizeof(header));
    lseek(fd, 0, SEEK_SET);
    ASSERT_EQ(DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr), DEFAULT_STRINGS);
    close(fd);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetBundleInfoWithBundleName
 * @tc.desc: test GetBundleInfoWithBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetBundleInfoWithBundleName, TestSize.Level1)
{
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    ASSERT_EQ(DlpUtils::GetBundleInfoWithBundleName("", 0, bundleInfo, 0), false);
    std::string appId;
    ASSERT_EQ(DlpUtils::GetAppIdFromToken(appId), false);
    int32_t userId = 0;
    (void)DlpUtils::GetUserIdByForegroundAccount(userId);
}

/**
 * @tc.name: GetAppIdentifierByAppId
 * @tc.desc: test GetAppIdentifierByAppId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetAppIdentifierByAppId, TestSize.Level1)
{
    std::string result = DlpUtils::GetAppIdentifierByAppId("test_appId", DEFAULT_USERID);
    ASSERT_EQ(result, DEFAULT_STRINGS);

    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    ASSERT_NE(bundleMgrProxy, nullptr);
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    int ret = bundleMgrProxy->GetBundleInfoV9("com.ohos.dlpmanager",
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO),
        bundleInfo, DEFAULT_USERID);
    ASSERT_EQ(ret, 0);

    (void)DlpUtils::GetAppIdentifierByAppId(bundleInfo.appId, DEFAULT_USERID);
}

/**
 * @tc.name: GetFilePathByFd001
 * @tc.desc: test GetFilePathByFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFilePathByFd001, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFilePathByFd001");
    std::string filePath;
    int32_t fd = 0;
    ASSERT_EQ(DlpUtils::GetFilePathByFd(fd, filePath), DLP_OK);
}

/**
 * @tc.name: GetExtractRealType001
 * @tc.desc: test GetExtractRealType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetExtractRealType001, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetExtractRealType001");
    std::string typeStr1 = "_txt";
    std::string typeStr2 = "txt";
    std::string reslTypeStr = "txt";
    ASSERT_EQ(DlpUtils::GetExtractRealType(typeStr1), reslTypeStr);
    ASSERT_EQ(DlpUtils::GetExtractRealType(typeStr2), reslTypeStr);
}

/**
 * @tc.name: GetFileContent001
 * @tc.desc: test GetFileContent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetFileContent001, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetFileContent001");
    std::string invalidPath = "";
    ASSERT_EQ(GetFileContent(invalidPath), DEFAULT_STRINGS);
    std::string validPath = "test";
    ASSERT_EQ(GetFileContent(validPath), DEFAULT_STRINGS);
    RemoveCachePath(validPath)
}

/**
 * @tc.name: GetGenerateInfoStr001
 * @tc.desc: test GetGenerateInfoStr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetGenerateInfoStr001, TestSize.Level0)
{
    DLP_LOG_INFO(UT_LABEL, "GetGenerateInfoStr001");
    int32_t fd = 0;
    ASSERT_EQ(GetGenerateInfoStr(fd), DEFAULT_STRINGS);
}
