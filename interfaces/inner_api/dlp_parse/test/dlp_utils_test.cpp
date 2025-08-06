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
#include "dlp_utils.h"
#include "c_mock_common.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpUtilsTest"};
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
    DLP_LOG_INFO(LABEL, "GetBundleMgrProxy");
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
    DLP_LOG_INFO(LABEL, "GetAuthPolicyWithType");
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
    DLP_LOG_INFO(LABEL, "GetFileTypeBySuffix");
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
    DLP_LOG_INFO(LABEL, "GetDlpFileRealSuffix");
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
    DLP_LOG_INFO(LABEL, "GetFileNameWithFd");
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
    DLP_LOG_INFO(LABEL, "GetFileNameWithDlpFd");
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
    DLP_LOG_INFO(LABEL, "GetRealTypeWithRawFile");
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
    DLP_LOG_INFO(LABEL, "GetFilePathWithFd");
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
 * @tc.name: GetRealTypeForEnterpriseWithFd001
 * @tc.desc: test GetRealTypeForEnterpriseWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeForEnterpriseWithFd001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetRealTypeForEnterpriseWithFd001");

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
    DlpUtils::GetRealTypeForEnterpriseWithFd(fd, isFromUriName);
    unlink("/data/fuse_test.txt.dlp");
}

/**
 * @tc.name: GetRealTypeForEnterpriseWithFd002
 * @tc.desc: test GetRealTypeForEnterpriseWithFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpUtilsTest, GetRealTypeForEnterpriseWithFd002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetRealTypeForEnterpriseWithFd002");
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
    DlpUtils::GetRealTypeForEnterpriseWithFd(fd, isFromUriName);
    unlink("/data/fuse_test.txt.dlp");
}