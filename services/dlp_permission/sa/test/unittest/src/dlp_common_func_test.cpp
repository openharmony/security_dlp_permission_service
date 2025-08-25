/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_common_func_test.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_common_func.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "huks_apply_permission_test_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCommonFuncTest" };
static const size_t TEST_BLOB_SIZE = 3;
static const uint8_t TEST_BLOB[TEST_BLOB_SIZE] = { '1', '2', '3' };
}

void DlpCommonFuncTest::SetUpTestCase() {}

void DlpCommonFuncTest::TearDownTestCase() {}

void DlpCommonFuncTest::SetUp() {}

void DlpCommonFuncTest::TearDown() {}

/**
 * @tc.name: GetHMACValue001
 * @tc.desc: GetHMACValue001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, GetHMACValue001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "GetHMACValue001");

    HMACSrcParams params0 = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, nullptr };
    BlobData blob = { TEST_BLOB_SIZE, const_cast<uint8_t *>(TEST_BLOB) };
    HMACSrcParams params = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, &blob };

    int32_t ret = GetHMACValue(nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = GetHMACValue(&params0, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = GetHMACValue(&params, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    uint8_t *hmacValue = nullptr;
    ret = GetHMACValue(&params, &hmacValue, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    uint32_t hmacValueSize = 0;
    ret = GetHMACValue(&params, &hmacValue, &hmacValueSize, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: GetHMACValue002
 * @tc.desc: GetHMACValue002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, GetHMACValue002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "GetHMACValue002");

    BlobData blob = { TEST_BLOB_SIZE, const_cast<uint8_t *>(TEST_BLOB) };
    HMACSrcParams params = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, &blob };
    uint8_t *hmacValue = nullptr;
    uint32_t hmacValueSize = 0;
    int32_t ret = GetHMACValue(&params, &hmacValue, &hmacValueSize, &blob);
    EXPECT_EQ(ret, DLP_ERROR_GENERATE_KEY_FAILED);
}

/**
 * @tc.name: WriteHMACAndBufToFile001
 * @tc.desc: WriteHMACAndBufToFile001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, WriteHMACAndBufToFile001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "WriteHMACAndBufToFile001");

    int32_t ret = WriteHMACAndBufToFile(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    HMACSrcParams params0 = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, nullptr };
    ret = WriteHMACAndBufToFile(&params0, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    BlobData blob = { TEST_BLOB_SIZE, const_cast<uint8_t *>(TEST_BLOB) };
    HMACSrcParams params = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, &blob };
    ret = WriteHMACAndBufToFile(&params, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = WriteHMACAndBufToFile(&params, "0", nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = WriteHMACAndBufToFile(&params, "", "");
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: WriteHMACAndBufToFile002
 * @tc.desc: WriteHMACAndBufToFile002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, WriteHMACAndBufToFile002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "WriteHMACAndBufToFile002");

    BlobData blob = { TEST_BLOB_SIZE, const_cast<uint8_t *>(TEST_BLOB) };
    HMACSrcParams params = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, &blob };
    int32_t ret = WriteHMACAndBufToFile(&params, "testKeyAlias", "testFilePath");
    EXPECT_EQ(ret, DLP_ERROR_GENERATE_KEY_FAILED);
}

/**
 * @tc.name: ReadBufFromFile001
 * @tc.desc: ReadBufFromFile001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, ReadBufFromFile001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "ReadBufFromFile001");

    int32_t ret = ReadBufFromFile(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    uint8_t *fileBuffer = nullptr;
    ret = ReadBufFromFile(&fileBuffer, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    uint32_t fileSize = 0;
    ret = ReadBufFromFile(&fileBuffer, &fileSize, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: CompareHMACValue001
 * @tc.desc: CompareHMACValue001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCommonFuncTest, CompareHMACValue001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "CompareHMACValue001");

    HMACSrcParams params0 = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, nullptr };
    BlobData blob = { TEST_BLOB_SIZE, const_cast<uint8_t *>(TEST_BLOB) };
    HMACSrcParams params = { 1, DlpKeyProtectionLevel::PROTECT_LEVEL_DE, &blob };

    int32_t ret = CompareHMACValue(nullptr, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = CompareHMACValue(&params0, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = CompareHMACValue(&params, nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    uint8_t *buffer = nullptr;
    ret = CompareHMACValue(&params, &buffer, nullptr, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    uint32_t bufLen = 0;
    ret = CompareHMACValue(&params, &buffer, &bufLen, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}