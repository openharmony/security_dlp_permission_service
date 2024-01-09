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
HWTEST_F(DlpZipTest, AddBuffToZip, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddBuffToZip");
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

    unlink(zipFile.c_str());
}

/**
 * @tc.name: AddFileContextToZip001
 * @tc.desc: test AddFileContextToZip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, AddFileContextToZip, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddFileContextToZip");
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

    unlink(inZip.c_str());
    unlink(zipFile.c_str());
}


/**
 * @tc.name: AddFileContextToZip001
 * @tc.desc: test AddFileContextToZip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpZipTest, IsZipFile, TestSize.Level1)
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