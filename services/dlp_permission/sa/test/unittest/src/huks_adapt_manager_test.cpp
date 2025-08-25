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

#include "huks_adapt_manager_test.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "alg_common_type.h"
#include "alg_utils.h"
#include "huks_adapt_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AlgHuksTest" };
const uint32_t MAIN_OS_ACCOUNT_ID = 100;
static const char *const FILE_HMAC_KEY_ALIAS_TEST = "FILE_HMAC_KEY";
static const char *const HMAC_DATA_TEST = "TestDLP_HksHMAC_NormalHMACDataTest";
}

void AlgHuksTest::SetUpTestCase() {}

void AlgHuksTest::TearDownTestCase() {}

void AlgHuksTest::SetUp() {}

void AlgHuksTest::TearDown() {}

/**
 * @tc.name: HuksGenerateMacKey001
 * @tc.desc: HuksGenerateMacKey001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateMacKey001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateMacKey001");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateMacKey(&keyInfo);
    EXPECT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: HuksGenerateMacKey002
 * @tc.desc: HuksGenerateMacKey002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateMacKey002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateMacKey002");

    int32_t ret = HuksGenerateMacKey(nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: HuksGenerateMacKey003
 * @tc.desc: HuksGenerateMacKey003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateMacKey003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateMacKey003");

    BlobData keyAilas = { 0, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateMacKey(&keyInfo);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: IsHuksMgrKeyExist001
 * @tc.desc: IsHuksMgrKeyExist001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, IsHuksMgrKeyExist001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "IsHuksMgrKeyExist001");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    EXPECT_EQ(IsHuksMgrKeyExist(&keyInfo), true);
}

/**
 * @tc.name: IsHuksMgrKeyExist002
 * @tc.desc: IsHuksMgrKeyExist002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, IsHuksMgrKeyExist002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "IsHuksMgrKeyExist002");

    EXPECT_EQ(IsHuksMgrKeyExist(nullptr), false);
}

/**
 * @tc.name: IsHuksMgrKeyExist003
 * @tc.desc: IsHuksMgrKeyExist003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, IsHuksMgrKeyExist003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "IsHuksMgrKeyExist003");

    BlobData keyAilas = { 0, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    EXPECT_EQ(IsHuksMgrKeyExist(&keyInfo), false);
}

/**
 * @tc.name: HuksGenerateHmac001
 * @tc.desc: HuksGenerateHmac001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac001");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    BlobData data = { strlen(HMAC_DATA_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(HMAC_DATA_TEST)) };
    uint8_t outData[HASH_SIZE_SHA_256] = { 0 };
    BlobData outDataBlob = { HASH_SIZE_SHA_256, outData };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateHmac(&keyInfo, &data, &outDataBlob);
    EXPECT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: HuksGenerateHmac002
 * @tc.desc: HuksGenerateHmac002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac002");

    BlobData data = { strlen(HMAC_DATA_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(HMAC_DATA_TEST)) };
    uint8_t outData[HASH_SIZE_SHA_256] = { 0 };
    BlobData outDataBlob = { HASH_SIZE_SHA_256, outData };
    int32_t ret = HuksGenerateHmac(nullptr, &data, &outDataBlob);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: HuksGenerateHmac003
 * @tc.desc: HuksGenerateHmac003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac003");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST), nullptr };
    BlobData data = { strlen(HMAC_DATA_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(HMAC_DATA_TEST)) };
    uint8_t outData[HASH_SIZE_SHA_256] = { 0 };
    BlobData outDataBlob = { HASH_SIZE_SHA_256, outData };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateHmac(&keyInfo, &data, &outDataBlob);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: HuksGenerateHmac004
 * @tc.desc: HuksGenerateHmac004 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac004, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac004");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    uint8_t outData[HASH_SIZE_SHA_256] = { 0 };
    BlobData outDataBlob = { HASH_SIZE_SHA_256, outData };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateHmac(&keyInfo, nullptr, &outDataBlob);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: HuksGenerateHmac005
 * @tc.desc: HuksGenerateHmac005 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac005, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac005");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    BlobData data = { MAX_DATABASE_FILE_SIZE + 1,
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(HMAC_DATA_TEST)) };
    uint8_t outData[HASH_SIZE_SHA_256] = { 0 };
    BlobData outDataBlob = { HASH_SIZE_SHA_256, outData };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateHmac(&keyInfo, &data, &outDataBlob);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: HuksGenerateHmac006
 * @tc.desc: HuksGenerateHmac006 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgHuksTest, HuksGenerateHmac006, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL, "HuksGenerateHmac006");

    BlobData keyAilas = { strlen(FILE_HMAC_KEY_ALIAS_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(FILE_HMAC_KEY_ALIAS_TEST)) };
    BlobData data = { strlen(HMAC_DATA_TEST),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(HMAC_DATA_TEST)) };
    AlgKeyInfo keyInfo = {
        .protectionLevel = PROTECT_LEVEL_DE, .osAccountId = MAIN_OS_ACCOUNT_ID, .keyAlias = keyAilas
    };
    int32_t ret = HuksGenerateHmac(&keyInfo, &data, nullptr);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}