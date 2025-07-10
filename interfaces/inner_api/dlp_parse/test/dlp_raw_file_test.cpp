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

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static const uint32_t DLP_MAX_CERT_SIZE = 1024 * 1024;
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
    uint64_t fileLen = DLP_MAX_CERT_SIZE;
    uint32_t dlpHeaderSize = DLP_MAX_CERT_SIZE;
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_EQ(filePtr->ParseRawDlpHeader(fileLen, dlpHeaderSize), DLP_PARSE_ERROR_FD_ERROR);
}

/**
 * @tc.name: HmacCheckTest
 * @tc.desc: test HmacCheck
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, HmacCheckTest, TestSize.Level0)
{
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    filePtr->version_ = SECOND;
    ASSERT_EQ(filePtr->HmacCheck(fileLen, dlpHeaderSize), DLP_OK);
}

/**
 * @tc.name: GetOfflineCertSizeTest
 * @tc.desc: test GetOfflineCertSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpRawFileTest, GetOfflineCertSizeTest, TestSize.Level0)
{
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
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
    std::shared_ptr<DlpFile> filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    ASSERT_EQ(filePtr->DoDlpHIAECryptOperation(message1, message2, offset, true), DLP_PARSE_ERROR_VALUE_INVALID);
}