/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DLP_CRYPT_H
#define DLP_CRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum DlpKeyDigest {
    DLP_DIGEST_NONE = 0,
    DLP_DIGEST_SHA256 = 12,
    DLP_DIGEST_SHA384 = 13,
    DLP_DIGEST_SHA512 = 14,
};

struct DlpOpensslAesCtx {
    uint32_t mode;
    uint32_t padding;
    void* append;
};

enum DLP_DIGEST_LEN {
    SHA256_LEN = 32,
    SHA384_LEN = 48,
    SHA512_LEN = 64,
};

#define OPENSSL_CTX_PADDING_NONE (0)   /* set chipher padding none */
#define OPENSSL_CTX_PADDING_ENABLE (1) /* set chipher padding enable */

#define DLP_BITS_PER_BYTE (8)
#define DLP_KEY_BYTES(keySize) (((keySize) + DLP_BITS_PER_BYTE - 1) / DLP_BITS_PER_BYTE)

#define DLP_OPENSSL_ERROR_LEN 128

#define DLP_OPENSSL_SUCCESS 1 /* openssl return 1: success */

#define BIT_NUM_OF_UINT8 8

enum DlpKeySize {
    DLP_AES_KEY_SIZE_128 = 128,
    DLP_AES_KEY_SIZE_192 = 192,
    DLP_AES_KEY_SIZE_256 = 256,
};

struct DlpBlob {
    uint32_t size = 0;
    uint8_t* data = nullptr;
};

struct DlpCipherParam {
    struct DlpBlob iv;
};

struct DlpUsageSpec {
    uint32_t mode;
    struct DlpCipherParam* algParam;
};

enum DlpCipherMode {
    DLP_MODE_CTR = 1,
};

enum DlpKeyPadding {
    DLP_PADDING_NONE = 0,
    DLP_PADDING_OAEP = 1,
    DLP_PADDING_PSS = 2,
    DLP_PADDING_PKCS1_V1_5 = 3,
    DLP_PADDING_PKCS5 = 4,
    DLP_PADDING_PKCS7 = 5,
};

#define SELF_FREE_PTR(PTR, FREE_FUNC) \
    {                                 \
        if ((PTR) != NULL) {          \
            FREE_FUNC(PTR);           \
            (PTR) = NULL;             \
        }                             \
    }

#define DLP_FREE_PTR(p) SELF_FREE_PTR(p, free)

int32_t DlpOpensslGenerateRandomKey(uint32_t keySize, struct DlpBlob* key);

int32_t DlpOpensslAesEncrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* cipherText);

int32_t DlpOpensslAesDecrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* plainText);

int32_t DlpOpensslAesEncryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec);

int32_t DlpOpensslAesEncryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText);

int32_t DlpOpensslAesEncryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText);

int32_t DlpOpensslAesDecryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec);

int32_t DlpOpensslAesDecryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText);

int32_t DlpOpensslAesDecryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText);

void DlpOpensslAesHalFreeCtx(void** cryptoCtx);

int32_t DlpOpensslHash(uint32_t alg, const struct DlpBlob* msg, struct DlpBlob* hash);

int32_t DlpOpensslHashInit(void** cryptoCtx, uint32_t alg);

int32_t DlpOpensslHashUpdate(void* cryptoCtx, const struct DlpBlob* msg);

int32_t DlpOpensslHashFinal(void** cryptoCtx, const struct DlpBlob* msg, struct DlpBlob* hash);

int32_t DlpOpensslHashFreeCtx(void** cryptoCtx);

int32_t DlpCtrModeIncreaeIvCounter(struct DlpBlob& iv, uint32_t count);

int32_t DlpHmacEncode(const DlpBlob& key, int32_t fd, DlpBlob& out);
#ifdef __cplusplus
}
#endif

#endif
