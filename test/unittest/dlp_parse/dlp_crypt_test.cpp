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
#include <fcntl.h>
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
constexpr int HMAC_SIZE = 32;
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt001, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt002, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt003, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt004, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt001, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt002, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt003, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt004, TestSize.Level0)
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
 * @tc.name: DlpOpensslAesEncryptAndDecrypt001
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt001, TestSize.Level0)
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
 * @tc.name: DlpOpensslAesEncryptAndDecrypt003
 * @tc.desc: Dlp encrypt && decrypt test.
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt003, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt004, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt005, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt006, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt007, TestSize.Level0)
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
 * @tc.name: GetOpensslAlg001
 * @tc.desc: get openssl invalid alg
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, GetOpensslAlg001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetOpensslAlg001");
    ASSERT_EQ(GetOpensslAlg(1000), nullptr);
}

/**
 * @tc.name: DlpOpensslGenerateRandomKey001
 * @tc.desc: random generate test
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey001, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey002, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey003, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpOpensslGenerateRandomKey004, TestSize.Level0)
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
HWTEST_F(DlpCryptTest, DlpCtrModeIncreaeIvCounter001, TestSize.Level0)
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

/**
 * @tc.name: DlpHmacEncodeForRaw001
 * @tc.desc: test for DlpHmacEncodeForRaw with DLP_OK
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpHmacEncodeForRaw001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpHmacEncodeForRaw001");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[SIXTEEN] = {0};
    write(fd, buffer, SIXTEEN);
    lseek(fd, 0, SEEK_SET);

    uint8_t* hmacKeyData = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(hmacKeyData, nullptr);
    struct DlpBlob key = {
        .size = HMAC_SIZE,
        .data = hmacKeyData,
    };

    uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(outBuf, nullptr);
    struct DlpBlob out = {
        .size = HMAC_SIZE,
        .data = outBuf,
    };

    ASSERT_EQ(DLP_OK, DlpHmacEncodeForRaw(key, fd, SIXTEEN, out));
    delete[] key.data;
    key.data = nullptr;
    delete[] out.data;
    out.data = nullptr;

    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: DlpHmacEncodeForRaw002
 * @tc.desc: test for DlpHmacEncodeForRaw with DLP_OK
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpHmacEncodeForRaw002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpHmacEncodeForRaw002");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[SIXTEEN] = {0};
    write(fd, buffer, SIXTEEN);
    lseek(fd, 0, SEEK_SET);

    uint8_t* hmacKeyData = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(hmacKeyData, nullptr);
    struct DlpBlob key = {
        .size = HMAC_SIZE,
        .data = hmacKeyData,
    };

    uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(outBuf, nullptr);
    struct DlpBlob out = {
        .size = HMAC_SIZE,
        .data = outBuf,
    };

    ASSERT_EQ(DLP_OK, DlpHmacEncodeForRaw(key, fd, 0, out));
    delete[] key.data;
    key.data = nullptr;
    delete[] out.data;
    out.data = nullptr;

    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: DlpHmacEncodeForRaw003
 * @tc.desc: test for DlpHmacEncodeForRaw with DLP_OK
 * @tc.type: FUNC
 * @tc.require:SR000GVIG3
 */
HWTEST_F(DlpCryptTest, DlpHmacEncodeForRaw003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpHmacEncodeForRaw003");

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    ASSERT_NE(fd, -1);
    uint8_t buffer[SIXTEEN] = {0};
    write(fd, buffer, SIXTEEN);
    lseek(fd, 0, SEEK_SET);

    uint8_t* hmacKeyData = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(hmacKeyData, nullptr);
    struct DlpBlob key = {
        .size = HMAC_SIZE,
        .data = hmacKeyData,
    };

    uint8_t* outBuf = new (std::nothrow) uint8_t[HMAC_SIZE];
    ASSERT_NE(outBuf, nullptr);
    struct DlpBlob out = {
        .size = HMAC_SIZE,
        .data = outBuf,
    };

    ASSERT_EQ(DLP_OK, DlpHmacEncodeForRaw(key, fd, SIXTEEN - 1, out));
    delete[] key.data;
    key.data = nullptr;
    delete[] out.data;
    out.data = nullptr;

    close(fd);
    unlink("/data/fuse_test.txt");
}

/**
 * @tc.name: DlpHIAECryptTest
 * @tc.desc: test DlpHIAECrypt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpHIAECryptTest, TestSize.Level0)
{
    (void)InitDlpHIAEMgr();
    ASSERT_EQ(DlpHIAEEncrypt(nullptr, nullptr, 0, nullptr, nullptr), DLP_PARSE_ERROR_VALUE_INVALID);
    ASSERT_EQ(DlpHIAEDecrypt(nullptr, nullptr, 0, nullptr, nullptr), DLP_PARSE_ERROR_VALUE_INVALID);
    ClearDlpHIAEMgr();
}

/**
 * @tc.name: DlpOpensslAesEncrypt005
 * @tc.desc: Dlp encrypt test with invalid iv size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt005");
    struct DlpCipherParam tagIv = {{8, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // iv size != 16, AesParamCheck should return false
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt006
 * @tc.desc: Dlp encrypt test with cipherText size less than message size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt006");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[8] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {8, enc};

    // cipherText size < message size, AesParamCheck should return false
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, &message, &cipherText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt005
 * @tc.desc: Dlp decrypt test with invalid iv size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt005");
    struct DlpCipherParam tagIv = {{8, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // iv size != 16, AesParamCheck should return false
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt006
 * @tc.desc: Dlp decrypt test with plainText size less than message size.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt006");
    struct DlpCipherParam tagIv = {{16, g_iv}};
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, &tagIv};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[8] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {8, dec};

    // plainText size < message size, AesParamCheck should return false
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, &message, &plainText);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DlpOpensslAesEncrypt007
 * @tc.desc: Dlp encrypt test with algParam nullptr (ivData is null path in OpensslAesCipherInit).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncrypt007, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncrypt007");
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, nullptr};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob cipherText = {15, enc};

    // algParam is nullptr, ivData will be nullptr in OpensslAesCipherInit
    int32_t ret = DlpOpensslAesEncrypt(&key, &usageSpec, &message, &cipherText);
    EXPECT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DlpOpensslAesDecrypt007
 * @tc.desc: Dlp decrypt test with algParam nullptr (ivData is null path in OpensslAesCipherInit).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesDecrypt007, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesDecrypt007");
    struct DlpUsageSpec usageSpec = {DLP_MODE_CTR, nullptr};

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t dec[16] = {0};
    struct DlpBlob key = {32, g_key};
    struct DlpBlob message = {15, input};
    struct DlpBlob plainText = {15, dec};

    // algParam is nullptr, ivData will be nullptr in OpensslAesCipherInit
    int32_t ret = DlpOpensslAesDecrypt(&key, &usageSpec, &message, &plainText);
    EXPECT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt008
 * @tc.desc: Dlp encrypt && decrypt with algParam->iv.data is nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt008, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt008");
    struct DlpBlob key = {32, nullptr};
    key.data = g_key;

    struct DlpCipherParam tagIv = {.iv = {.data = nullptr, .size = 16}};
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};
    struct DlpBlob mIn = {15, input};
    struct DlpBlob mEnc = {15, enc};
    struct DlpBlob mDec = {15, dec};

    // algParam is not nullptr but iv.data is nullptr, IV size check short-circuits
    int32_t ret = DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    EXPECT_EQ(DLP_OK, ret);
    ret = DlpOpensslAesDecrypt(&key, &usage, &mEnc, &mDec);
    EXPECT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DlpOpensslAesEncryptAndDecrypt009
 * @tc.desc: Dlp encrypt && decrypt test with iv size 0 (invalid iv size check).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCryptTest, DlpOpensslAesEncryptAndDecrypt009, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "DlpOpensslAesEncryptAndDecrypt009");
    struct DlpBlob key = {32, nullptr};
    key.data = g_key;

    struct DlpCipherParam tagIv = {.iv = {.data = g_iv, .size = 0}};
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &tagIv
    };

    uint8_t input[16] = "aaaaaaaaaaaaaaa";
    uint8_t enc[16] = {0};
    struct DlpBlob mIn = {15, input};
    struct DlpBlob mEnc = {15, enc};

    // iv.size = 0, should fail AesParamCheck
    int32_t ret = DlpOpensslAesEncrypt(&key, &usage, &mIn, &mEnc);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
    ret = DlpOpensslAesDecrypt(&key, &usage, &mIn, &mEnc);
    EXPECT_EQ(DLP_PARSE_ERROR_VALUE_INVALID, ret);
}
