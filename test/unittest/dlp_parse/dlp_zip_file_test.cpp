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