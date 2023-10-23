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

#include "dlp_crypt_test.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "accesstoken_kit.h"
#include "c_mock_common.h"
#include "dlp_crypt.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;
using namespace OHOS::Security::AccessToken;

extern "C" {
extern const EVP_MD* GetOpensslAlg(uint32_t alg);
}

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCryptTest"};
static const int32_t DEFAULT_USERID = 100;
static AccessTokenID g_selfTokenId = 0;
static long USEC_PER_SEC = 1000000L;
constexpr int THOUSAND = 1000;
constexpr int SIXTEEN = 16;
constexpr int TWENTYFOUR = 24;
constexpr int TWENTYFIVE = 25;
uint8_t g_key[32] = { 0xdc, 0x7c, 0x8d, 0xe, 0xeb, 0x41, 0x4b, 0xb0, 0x8e, 0x24, 0x8, 0x32, 0xc7, 0x88, 0x96, 0xb6,
    0x2, 0x69, 0x65, 0x49, 0xaf, 0x3c, 0xa7, 0x8f, 0x38, 0x3d, 0xe3, 0xf1, 0x23, 0xb6, 0x22, 0xfb };
uint8_t g_iv[16] = { 0x90, 0xd5, 0xe2, 0x45, 0xaa, 0xeb, 0xa0, 0x9, 0x61, 0x45, 0xd1, 0x48, 0x4a, 0xaf, 0xc9, 0xf9 };
static const int ENC_BUF_LEN = 10 * 1024 * 1024;

void Dumpptr(uint8_t *ptr, uint32_t len)
{
    uint8_t *abc = ptr;
    for (uint32_t i = 0; i < len; i++) {
        printf("%x ", *abc);
        abc++;
    }
    printf("\n");
}
}

void DlpCryptTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, "com.ohos.dlpmanager", 0);
    SetSelfTokenID(tokenId);
}

void DlpCryptTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
}

void DlpCryptTest::SetUp() {}

void DlpCryptTest::TearDown() {}

static void CheckParams(DlpUsageSpec* usage, DlpBlob* key, DlpBlob* mIn, DlpBlob* mEnc)
{
    DLP_LOG_INFO(LABEL, "CheckParams");
    usage->mode = THOUSAND;
    ASSERT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesEncrypt(key, usage, mIn, mEnc));
    usage->mode = DLP_MODE_CTR;
    // key len 16 when DlpOpensslAesEncrypt
    key->size = SIXTEEN;
    ASSERT_EQ(DLP_OK, DlpOpensslAesEncrypt(key, usage, mIn, mEnc));
    // key len 24 when DlpOpensslAesEncrypt
    key->size = TWENTYFOUR;
    ASSERT_EQ(DLP_OK, DlpOpensslAesEncrypt(key, usage, mIn, mEnc));
    // key len invalid when DlpOpensslAesEncrypt
    key->size = TWENTYFIVE;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesEncrypt(key, usage, mIn, mEnc));
}

/**
 * @tc.name: DlpOpensslAesEncrypt001
 * @tc.desc: Dlp encrypt test with invalid key.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt001");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // key = nullptr
    int32_t ret = DlpOpensslAesEncrypt(nullptr, &usageSpec, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt002
 * @tc.desc: Dlp encrypt test with invalid usageSpec.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt002");

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt003
 * @tc.desc: Dlp encrypt test with invalid message.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt003");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob cipherText = {15, enc};

    // message = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt004
 * @tc.desc: Dlp encrypt test with invalid cipherText.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt004");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    struct DlpBlob key = {32, g_key};

    // cipherText = nullptr
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt001
 * @tc.desc: Dlp encrypt test with invalid key.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt001");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // key = nullptr
    int32_t ret = DlpOpensslAesDecrypt(nullptr, &usageSpec, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt002
 * @tc.desc: Dlp encrypt test with invalid usageSpec.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt002");

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, nullptr, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt003
 * @tc.desc: Dlp encrypt test with invalid message.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt003");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob plainText = {15, enc};

    // message = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, nullptr, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt004
 * @tc.desc: Dlp encrypt test with invalid plainText.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt004");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    struct DlpBlob key = {32, g_key};

    // plainText = nullptr
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit001
 * @tc.desc: Dlp aes init test with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit001");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    // *cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(nullptr, &key, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit002
 * @tc.desc: Dlp aes init test with invalid key
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit002");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    void* ctx = nullptr;

    // key = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, nullptr, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit003
 * @tc.desc: Dlp aes init test with invalid usageSpec
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptInit003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit003");
    void* ctx = nullptr;
    struct DlpBlob key = {32, g_key};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptInit004
 * @tc.desc: Dlp aes init test with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptInit004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptInit004");
    void* ctx = nullptr;
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    // EVP_CIPHER_CTX_new failed when OpensslAesCipherCryptInit
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

    // EVP_aes_256_ctr failed when OpensslAesCipherCryptInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_aes_256_ctr", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

    // EVP_EncryptInit_ex failed when OpensslAesCipherCryptInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptInit_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

    // EVP_EncryptInit_ex first success second failed when OpensslAesCipherCryptInit
    condition.mockSequence = { false, true };
    SetMockConditions("EVP_EncryptInit_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

    // EVP_CIPHER_CTX_set_padding failed when OpensslAesCipherCryptInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_set_padding", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

     // usage.mode is not DLP_MODE_CTR when DlpOpensslAesDecrypt
    usageSpec.mode = 1000;
    ASSERT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec));
    usageSpec.mode = DLP_MODE_CTR;
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate001
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptUpdate(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate002
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t enc[16] = {0};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslAesEncryptUpdate(ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);

    struct DlpBlob message = {15, nullptr};

    // message len is not 0, but data is nullptr
    ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate003
 * @tc.desc: DlpOpensslAesEncryptUpdate with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptUpdate003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // cipherText = nullptr
    ret = DlpOpensslAesEncryptUpdate(ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptUpdate004
 * @tc.desc: DlpOpensslAesEncryptUpdate with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptUpdate004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptUpdate004");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    uint8_t enc[16] = {0};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    struct DlpOpensslAesCtx* contex = static_cast<struct DlpOpensslAesCtx*>(ctx);
    void *tmpCtx = contex->append;
    contex->append = nullptr;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText));
    contex->append = tmpCtx;

    // EVP_EncryptUpdate failed when OpensslAesCipherEncryptUpdate
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText));
    CleanMockConditions();

    contex->mode = 1000;
    ASSERT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText));
    contex->mode = DLP_MODE_CTR;
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal001
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesEncryptFinal(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);

    // cryptoCtx.append = nullptr
    DlpOpensslAesCtx* cryptoCtx = reinterpret_cast<DlpOpensslAesCtx*>(calloc(1, sizeof(DlpOpensslAesCtx)));
    ASSERT_NE(nullptr, cryptoCtx);
    cryptoCtx->mode = DLP_MODE_CTR;
    cryptoCtx->padding = OPENSSL_CTX_PADDING_ENABLE;
    cryptoCtx->append = nullptr;
    ret = DlpOpensslAesEncryptFinal(reinterpret_cast<void**>(&cryptoCtx), &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    free(cryptoCtx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal002
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslAesEncryptFinal(&ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal003
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // cipherText = nullptr
    ret = DlpOpensslAesEncryptFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal004
 * @tc.desc: DlpOpensslAesEncryptFinal with invalid mode
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // mode is invalid
    struct DlpOpensslAesCtx* contex = static_cast<struct DlpOpensslAesCtx*>(ctx);
    contex->mode = 1000;
    ret = DlpOpensslAesEncryptFinal(&ctx, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal005
 * @tc.desc: DlpOpensslAesEncryptFinal with openssl EVP_CIPHER_CTX_new branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal005");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // EVP_EncryptUpdate fail in OpensslAesCipherEncryptFinalThree
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptUpdate", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptFinal(&ctx, &message, &cipherText));
    CleanMockConditions();
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptFinal006
 * @tc.desc: DlpOpensslAesEncryptFinal with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptFinal006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptFinal006");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesEncryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesEncryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // EVP_EncryptFinal_ex fail in OpensslAesCipherEncryptFinalThree
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptFinal_ex", condition);
    EXPECT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncryptFinal(&ctx, &message, &cipherText));
    CleanMockConditions();
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit001
 * @tc.desc: Dlp aes init test with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit001");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    // *cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(nullptr, &key, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit002
 * @tc.desc: Dlp aes init test with invalid key
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit002");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    void* ctx = nullptr;

    // key = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, nullptr, &usageSpec);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit003
 * @tc.desc: Dlp aes init test with invalid usageSpec
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptInit003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit003");
    void* ctx = nullptr;
    struct DlpBlob key = {32, g_key};

    // usageSpec = nullptr
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptInit004
 * @tc.desc: Dlp aes init test with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptInit004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptInit004");

    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    void* ctx = nullptr;

    // EVP_CIPHER_CTX_new failed when OpensslAesCipherCryptInit
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec));
    CleanMockConditions();

     // usage.mode is not DLP_MODE_CTR when DlpOpensslAesDecrypt
    usageSpec.mode = 1000;
    ASSERT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec));
    usageSpec.mode = DLP_MODE_CTR;
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate001
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob plainText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptUpdate(nullptr, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate002
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    uint8_t dec[16] = {0};
    struct DlpBlob plainText = {15, dec};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslAesDecryptUpdate(ctx, nullptr, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate003
 * @tc.desc: DlpOpensslAesDecryptUpdate with invalid plainText
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptUpdate003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // plainText = nullptr
    ret = DlpOpensslAesDecryptUpdate(ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptUpdate004
 * @tc.desc: DlpOpensslAesDecryptUpdate with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptUpdate004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptUpdate004");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    uint8_t enc[16] = {0};
    struct DlpBlob cipherText = {15, enc};
    void* ctx = nullptr;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);

    // ctx append nullptr
    struct DlpOpensslAesCtx* aesCtx = static_cast<struct DlpOpensslAesCtx*>(ctx);
    void *backup = aesCtx->append;
    aesCtx->append = nullptr;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText));
    aesCtx->append = backup;

    // EVP_DecryptUpdate failed
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_DecryptUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText));
    CleanMockConditions();

    // mode invalid
    aesCtx->mode = 1000;
    EXPECT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText));
    aesCtx->mode = DLP_MODE_CTR;
    DlpOpensslAesHalFreeCtx(&ctx);
}


/**
 * @tc.name: DlpOpensslAesDecryptFinal001
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal001");
    struct DlpBlob message = {32, g_key};
    struct DlpBlob cipherText = {32, g_key};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslAesDecryptFinal(nullptr, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal002
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal002");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslAesDecryptFinal(&ctx, nullptr, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal003
 * @tc.desc: DlpOpensslAesDecryptFinal with invalid cipherText
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptFinal003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal003");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // cipherText = nullptr
    ret = DlpOpensslAesDecryptFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesDecryptFinal004
 * @tc.desc: DlpOpensslAesDecryptFinal with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecryptFinal004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecryptFinal004");
    struct DlpBlob key = {32, g_key};
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    void* ctx;
    int32_t ret = DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec);
    ASSERT_EQ(0, ret);
    message.size = 1;
    cipherText.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslAesDecryptUpdate(ctx, &message, &cipherText);
        ASSERT_EQ(0, ret);
        message.data = message.data + 1;
        cipherText.data = cipherText.data + 1;
        i++;
    }

    // ctx mode invalid
    struct DlpOpensslAesCtx* contex = static_cast<struct DlpOpensslAesCtx*>(ctx);
    contex->mode = 1000;
    EXPECT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesDecryptFinal(&ctx, &message, &cipherText));
    contex->mode = DLP_MODE_CTR;

    // ctx append null
    void *backup = contex->append;
    contex->append = nullptr;
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesDecryptFinal(&ctx, &message, &cipherText));
    contex->append = backup;

    // EVP_DecryptUpdate fail
    ASSERT_EQ(0, DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec));
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_DecryptUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecryptFinal(&ctx, &message, &cipherText));
    CleanMockConditions();

    // EVP_DecryptFinal_ex fail
    ASSERT_EQ(0, DlpOpensslAesDecryptInit(&ctx, &key, &usageSpec));
    condition.mockSequence = { true };
    SetMockConditions("EVP_DecryptFinal_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecryptFinal(&ctx, &message, &cipherText));
    CleanMockConditions();
    DlpOpensslAesHalFreeCtx(&ctx);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt001
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt001");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mEnc = {
        .data = nullptr,
        .size = 15
    };
    mEnc.data = enc;
    struct DlpBlob mDec = {
        .data = nullptr,
        .size = 15
    };
    mDec.data = dec;
    DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec);
    cout << "input hexdump:";
    Dumpptr(input, 16);
    cout << "enc hexdump:";
    Dumpptr(enc, 16);
    cout << "output hexdump:";
    Dumpptr(dec, 16);
    int32_t ret = strcmp(reinterpret_cast<char *>(input), reinterpret_cast<char *>(dec));
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt002
 * @tc.desc: Dlp encrypt && decrypt test for split interface
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt002");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = { .mode = DLP_MODE_CTR, .algParam = &tagIv};
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = { .data = input, .size = 15};
    struct DlpBlob mEnc = { .data = enc, .size = 15};
    struct DlpBlob mDec = { .data = dec, .size = 15};
    struct DlpBlob mNull = { .data = nullptr, .size = 0};
    void *ctx;
    int i = 0;
    DlpOpensslAesEncryptInit(&ctx, &key, &usage);
    mIn.size = mEnc.size = 1;
    while (i < 15) {
        DlpOpensslAesEncryptUpdate(ctx, &mIn, &mEnc);
        mIn.data = mIn.data + 1;
        mEnc.data = mEnc.data + 1;
        i++;
    }
    DlpOpensslAesEncryptFinal(&ctx, &mNull, &mEnc);
    DlpOpensslAesHalFreeCtx(&ctx);
    DlpOpensslAesDecryptInit(&ctx, &key, &usage);
    i = 0;
    mEnc.data = enc;
    mEnc.size = mDec.size = 1;
    while (i < 15) {
        DlpOpensslAesDecryptUpdate(ctx, &mEnc, &mDec);
        mEnc.data = mEnc.data + 1;
        mDec.data = mDec.data + 1;
        i++;
    }
    DlpOpensslAesDecryptFinal(&ctx, &mNull, &mDec);
    DlpOpensslAesHalFreeCtx(&ctx);
    ASSERT_EQ(0, strcmp(reinterpret_cast<char *>(input), reinterpret_cast<char *>(dec)));
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt003
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt003");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t *input = static_cast<uint8_t *>(malloc(ENC_BUF_LEN));
    uint8_t *enc = static_cast<uint8_t *>(malloc(ENC_BUF_LEN));
    uint8_t *dec = static_cast<uint8_t *>(malloc(ENC_BUF_LEN));

    struct DlpBlob mIn = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mIn.data = input;
    struct DlpBlob mEnc = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mEnc.data = enc;
    struct DlpBlob mDec = {
        .data = nullptr,
        .size = ENC_BUF_LEN
    };
    mDec.data = dec;

    struct timeval start, end, diff;
    gettimeofday(&start, nullptr);

    DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    int runtimeUs = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "10M date encrypt time use: " << runtimeUs << "(us) " << std::endl;

    gettimeofday(&start, nullptr);
    int32_t ret = DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec);
    gettimeofday(&end, nullptr);
    timersub(&end, &start, &diff);
    runtimeUs = diff.tv_sec * USEC_PER_SEC + diff.tv_usec;
    std::cout << "10M date decrypt time use: " << runtimeUs << "(us) " << std::endl;
    ASSERT_EQ(0, ret);
    free(input);
    free(enc);
    free(dec);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt004
 * @tc.desc: Dlp encrypt && decrypt test with invalid args.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt004");
    int32_t ret;

    ret = DlpOpensslAesEncrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    ret = DlpOpensslAesDecrypt(nullptr, nullptr, nullptr, nullptr);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt005
 * @tc.desc: Dlp encrypt && decrypt openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt005");

    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob mIn = {
        .data = input,
        .size = 15
    };
    struct DlpBlob mEnc = {
        .data = enc,
        .size = 15
    };

    // cipher ctx new failed when OpensslAesCipherInit
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();

    // EVP_aes_256_ctr return cipher failed when OpensslAesCipherInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_aes_256_ctr", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();

    // EVP_EncryptInit_ex return failed when OpensslAesCipherInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptInit_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt006
 * @tc.desc: Dlp encrypt && decrypt openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt006");

    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;

    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob mIn = {
        .data = input,
        .size = 15
    };
    struct DlpBlob mEnc = {
        .data = enc,
        .size = 15
    };

    // EVP_EncryptInit_ex first success and second failed when OpensslAesCipherInit
    DlpCMockCondition condition;
    condition.mockSequence = { false, true };
    SetMockConditions("EVP_EncryptInit_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();

    // EVP_CIPHER_CTX_set_padding failed when OpensslAesCipherInit
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_set_padding", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();

    // EVP_EncryptUpdate failed when OpensslAesCipherEncryptFinal
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();

    // EVP_EncryptFinal_ex failed when OpensslAesCipherEncryptFinal
    condition.mockSequence = { true };
    SetMockConditions("EVP_EncryptFinal_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc));
    CleanMockConditions();
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt007
 * @tc.desc: Dlp encrypt && decrypt openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt007, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt007");
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = {
        .data = input,
        .size = 15
    };
    struct DlpBlob mEnc = {
        .data = enc,
        .size = 15
    };
    struct DlpBlob mDec = {
        .data = dec,
        .size = 15
    };
    DlpCMockCondition condition;
    // usage.mode is not DLP_MODE_CTR when DlpOpensslAesEncrypt
    CheckParams(&usage, &key, &mIn, &mEnc);
    key.size = 24;
    // OpensslAesCipherInit failed when DlpOpensslAesDecrypt
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec));
    CleanMockConditions();
    // OpensslAesCipherEncryptFinal failed when DlpOpensslAesDecrypt
    condition.mockSequence = { true };
    SetMockConditions("EVP_DecryptUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec));
    CleanMockConditions();
    // EVP_DecryptFinal_ex failed when DlpOpensslAesDecrypt
    condition.mockSequence = { true };
    SetMockConditions("EVP_DecryptFinal_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec));
    CleanMockConditions();
    // usage.mode is not DLP_MODE_CTR when DlpOpensslAesDecrypt
    usage.mode = 1000;
    ASSERT_EQ(DLP_PARSE_ERROR_OPERATION_UNSUPPORTED, DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec));
}

/**
 * @tc.name: DlpOpensslAesHalFreeCtx001
 * @tc.desc: free crypt ctx test
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesHalFreeCtx001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesHalFreeCtx001");
    void *ctx;
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };
    ASSERT_EQ(DLP_OK, DlpOpensslAesEncryptInit(&ctx, &key, &usage));

    // mode invalid
    struct DlpOpensslAesCtx* opensslAesCtx = static_cast<struct DlpOpensslAesCtx*>(ctx);
    opensslAesCtx->mode = 1000;
    DlpOpensslAesHalFreeCtx(&ctx);
    ASSERT_EQ(ctx, nullptr);
}

/**
 * @tc.name: DlpOpensslAesHalFreeCtx002
 * @tc.desc: free crypt ctx test append null
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesHalFreeCtx002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesHalFreeCtx002");
    void *ctx;
    struct DlpBlob key = { 32, nullptr };
    key.data = g_key;
    struct DlpCipherParam tagIv = { .iv = { .data = nullptr, .size = 16}};
    tagIv.iv.data = g_iv;
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };
    ASSERT_EQ(DLP_OK, DlpOpensslAesEncryptInit(&ctx, &key, &usage));

    // append nullptr
    struct DlpOpensslAesCtx* opensslAesCtx = static_cast<struct DlpOpensslAesCtx*>(ctx);
    opensslAesCtx->append = nullptr;
    DlpOpensslAesHalFreeCtx(&ctx);
    ASSERT_EQ(ctx, nullptr);
}

/**
 * @tc.name: GetOpensslAlg001
 * @tc.desc: get openssl invalid alg
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, GetOpensslAlg001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpensslAlg001");
    ASSERT_EQ(GetOpensslAlg(1000), nullptr);
}

/**
 * @tc.name: DlpOpensslHash001
 * @tc.desc: HASH test
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mOut = {
        .data = nullptr,
        .size = 64
    };
    mOut.data = out;
    int ret;

    ret = DlpOpensslHash(DLP_DIGEST_SHA256, &mIn, &mOut);
    cout << "sha256:";
    Dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    mOut.size = 64;
    ret = DlpOpensslHash(DLP_DIGEST_SHA384, &mIn, &mOut);
    cout << "sha384:";
    Dumpptr(out, 16);
    ASSERT_EQ(0, ret);
    mOut.size = 64;
    ret = DlpOpensslHash(DLP_DIGEST_SHA512, &mIn, &mOut);
    cout << "sha512:";
    Dumpptr(out, 16);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslHash002
 * @tc.desc: DlpOpensslHash with invalid alg
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash002");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[32] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {32, out};

    // alg = 0
    int32_t ret = DlpOpensslHash(DLP_DIGEST_NONE, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);

    // alg != DLP_DIGEST_SHA256 | DLP_DIGEST_SHA384 | DLP_DIGEST_SHA512
    ret = DlpOpensslHash(100, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash003
 * @tc.desc: DlpOpensslHash with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash003");
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};

    // message = nullptr
    int32_t ret = DlpOpensslHash(DLP_DIGEST_SHA512, nullptr, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash004
 * @tc.desc: DlpOpensslHash with invalid hash
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash004");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};

    // hash = nullptr
    int32_t ret = DlpOpensslHash(DLP_DIGEST_SHA512, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHash005
 * @tc.desc: DlpOpensslHash with hash len < alg len
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash005");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    uint8_t output[16] = {};
    struct DlpBlob hash = {16, output};

    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslHash(DLP_DIGEST_SHA512, &message, &hash));
}

/**
 * @tc.name: DlpOpensslHash006
 * @tc.desc: DlpOpensslHash with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHash006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHash006");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    uint8_t output[16] = {};
    struct DlpBlob hash = {64, output};

    // EVP_sha512 failed
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_sha512", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHash(DLP_DIGEST_SHA512, &message, &hash));
    CleanMockConditions();

    // EVP_Digest failed
    condition.mockSequence = { true };
    SetMockConditions("EVP_Digest", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHash(DLP_DIGEST_SHA512, &message, &hash));
    CleanMockConditions();
}

/**
 * @tc.name: DlpOpensslHashInit001
 * @tc.desc: DlpOpensslHashInit with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashInit001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashInit001");

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashInit(nullptr, DLP_DIGEST_SHA256);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashInit002
 * @tc.desc: DlpOpensslHashInit with invalid alg
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashInit002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashInit002");

    // alg = DLP_DIGEST_NONE
    void* ctx = nullptr;
    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_NONE);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);

    // alg = 100
    ctx = nullptr;
    ret = DlpOpensslHashInit(&ctx, 100);
    EXPECT_EQ(DLP_PARSE_ERROR_DIGEST_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashInit003
 * @tc.desc: DlpOpensslHashInit with openssl abnormal branch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashInit003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashInit003");
    void* ctx = nullptr;

    // EVP_sha512 fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_sha512", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA512));
    CleanMockConditions();

    // EVP_MD_CTX_new fail
    condition.mockSequence = { true };
    SetMockConditions("EVP_MD_CTX_new", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA512));
    CleanMockConditions();

    // EVP_DigestInit_ex fail
    condition.mockSequence = { true };
    SetMockConditions("EVP_DigestInit_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA512));
    CleanMockConditions();
}

/**
 * @tc.name: DlpOpensslHashUpdate001
 * @tc.desc: DlpOpensslHashUpdate with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashUpdate001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashUpdate001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashUpdate(nullptr, &message);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashUpdate002
 * @tc.desc: DlpOpensslHashUpdate with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashUpdate002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashUpdate002");
    void* ctx = nullptr;
    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    ASSERT_EQ(0, ret);

    // message = nullptr
    ret = DlpOpensslHashUpdate(ctx, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashUpdate003
 * @tc.desc: DlpOpensslHashUpdate with openssl abnormal barnch
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashUpdate003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashUpdate003");
    void* ctx = nullptr;
    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    ASSERT_EQ(0, ret);

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob msg1 = {15, input};

    // EVP_DigestUpdate failed
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_DigestUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHashUpdate(ctx, &msg1));
    CleanMockConditions();
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal001
 * @tc.desc: DlpOpensslHashFinal with invalid cryptoCtx
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob message = {15, input};
    struct DlpBlob hash = {64, out};

    // cryptoCtx = nullptr
    int32_t ret = DlpOpensslHashFinal(nullptr, &message, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslHashFinal002
 * @tc.desc: DlpOpensslHashFinal with invalid message
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal002");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    // message = nullptr
    ret = DlpOpensslHashFinal(&ctx, nullptr, &hash);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal003
 * @tc.desc: DlpOpensslHashFinal ok
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal003");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    ret = DlpOpensslHashFinal(&ctx, &msg1, &hash);
    EXPECT_EQ(DLP_OK, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal004
 * @tc.desc: DlpOpensslHashFinal with invalid hash
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal004");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    struct DlpBlob message = {15, input};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    // hash = nullptr
    ret = DlpOpensslHashFinal(&ctx, &message, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal005
 * @tc.desc: DlpOpensslHashFinal with openssl EVP_DigestUpdate fail
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal005");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_DigestUpdate", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHashFinal(&ctx, &msg1, &hash));
    CleanMockConditions();

    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFinal006
 * @tc.desc: DlpOpensslHashFinal with openssl EVP_DigestFinal_ex fail
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFinal006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFinal006");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob hash = {64, out};
    struct DlpBlob msg1 = {15, input};
    void* ctx = nullptr;

    int32_t ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    EXPECT_EQ(0, ret);

    msg1.size = 1;
    int i = 0;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &msg1);
        EXPECT_EQ(0, ret);
        msg1.data = msg1.data + 1;
        i++;
    }

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("EVP_DigestFinal_ex", condition);
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, DlpOpensslHashFinal(&ctx, &msg1, &hash));
    CleanMockConditions();

    EVP_MD_CTX_free(reinterpret_cast<EVP_MD_CTX*>(ctx));
}

/**
 * @tc.name: DlpOpensslHashFreeCtx001
 * @tc.desc: DlpOpensslHashFreeCtx with null
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFreeCtx001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFreeCtx001");
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslHashFreeCtx(nullptr));

    void *ctx = nullptr;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpOpensslHashFreeCtx(&ctx));
}

/**
 * @tc.name: DlpOpensslHashFreeCtx002
 * @tc.desc: DlpOpensslHashFreeCtx with null
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashFreeCtx002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashFreeCtx002");
    void* ctx = nullptr;
    ASSERT_EQ(0, DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256));
    ASSERT_EQ(DLP_OK, DlpOpensslHashFreeCtx(&ctx));
}

/**
 * @tc.name: DlpOpensslHashTest001
 * @tc.desc: split hash test
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslHashTest001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslHashTest001");
    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t out[64] = {0};
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 15
    };
    mIn.data = input;
    struct DlpBlob mOut = {
        .data = nullptr,
        .size = 15
    };
    mOut.data = out;
    struct DlpBlob mNull = {
        .data = nullptr,
        .size = 0
    };
    int i = 0;
    int ret;
    void *ctx;

    ret = DlpOpensslHashInit(&ctx, DLP_DIGEST_SHA256);
    ASSERT_EQ(0, ret);

    mIn.size = 1;
    while (i < 15) {
        ret = DlpOpensslHashUpdate(ctx, &mIn);
        ASSERT_EQ(0, ret);
        mIn.data = mIn.data + 1;
        i++;
    }
    ret = DlpOpensslHashFinal(&ctx, &mNull, &mOut);
    ASSERT_EQ(0, ret);
    DlpOpensslHashFreeCtx(&ctx);

    cout << "sha256sum:";
    Dumpptr(out, 16);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey001
 * @tc.desc: random generate test
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey001");
    int ret = 0;
    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 32
    };

    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    Dumpptr(mIn.data, 16);
    free(mIn.data);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_192, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    Dumpptr(mIn.data, 16);
    free(mIn.data);
    ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_128, &mIn);
    ASSERT_EQ(0, ret);
    cout << "random key:";
    Dumpptr(mIn.data, 16);
    free(mIn.data);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey002
 * @tc.desc: random generate test with invalid keySize
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey002");
    struct DlpBlob key = {32, nullptr};
    int32_t ret = DlpOpensslGenerateRandomKey(1, &key);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey003
 * @tc.desc: random generate test with invalid key
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey003");

    // key = nullptr
    int32_t ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, nullptr);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey004
 * @tc.desc: random generate test when RAND_bytes return null
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslGenerateRandomKey004");

    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 32
    };

    DlpCMockCondition condition;
    condition.mockSequence = { true }; // first call return failed
    SetMockConditions("RAND_bytes", condition);
    int32_t ret = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &mIn);
    CleanMockConditions();
    ASSERT_EQ(DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR, ret);
}

/**
 * @tc.name: DlpCtrModeIncreaeIvCounter001
 * @tc.desc: random generate test when RAND_bytes return null
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpCtrModeIncreaeIvCounter001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpCtrModeIncreaeIvCounter001");

    struct DlpBlob mIn = {
        .data = nullptr,
        .size = 8
    };

    // data nullptr
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpCtrModeIncreaeIvCounter(mIn, 0));

    // size 0
    uint8_t ivData[8] = {0};
    mIn.data = ivData;
    mIn.size = 0;
    ASSERT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, DlpCtrModeIncreaeIvCounter(mIn, 0));

    // valid data
    mIn.data[7] = 0xff;
    mIn.size = 8;
    ASSERT_EQ(DLP_OK, DlpCtrModeIncreaeIvCounter(mIn, 1));
    ASSERT_EQ(mIn.data[7], 0);
    ASSERT_EQ(mIn.data[6], 1);
}

