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

#include "dlp_crypt.h"
#include <cstdio>
#include <cstdlib>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <securec.h>
#include <string>
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace OHOS::Security::DlpPermission;
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpParse"};
static const uint32_t BYTE_LEN = 8;
const uint32_t HMAC_SIZE = 32;
const uint32_t SHA256_KEY_LEN = 32;
const uint32_t BUFFER_SIZE = 1048576;

#ifdef __cplusplus
extern "C" {
#endif

inline bool DlpOpensslCheckBlob(const struct DlpBlob* blob)
{
    return (blob != nullptr) && (blob->data != nullptr);
}

inline bool DlpOpensslCheckBlobZero(const struct DlpBlob* blob)
{
    if (blob == nullptr) {
        return false;
    }

    if (blob->data == nullptr && blob->size == 0) {
        return true;
    }

    if (blob->data == nullptr) {
        return false;
    }

    return true;
}

static bool AesGenKeyCheckParam(uint32_t keySize)
{
    return (keySize == DLP_AES_KEY_SIZE_128) || (keySize == DLP_AES_KEY_SIZE_192) || (keySize == DLP_AES_KEY_SIZE_256);
}

int32_t DlpOpensslGenerateRandomKey(uint32_t keySize, struct DlpBlob* key)
{
    if (key == nullptr) {
        DLP_LOG_ERROR(LABEL, "Generate key fail, blob is nullptr");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!AesGenKeyCheckParam(keySize)) {
        DLP_LOG_ERROR(LABEL, "Generate key fail, key size %{public}u is invalid", keySize);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    uint32_t keySizeByte = keySize / BIT_NUM_OF_UINT8;

    uint8_t* tmpKey = new (std::nothrow) uint8_t[keySizeByte];
    if (tmpKey == nullptr) {
        DLP_LOG_ERROR(LABEL, "Generate key fail, alloc %{public}u buffer fail", keySizeByte);
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int res = RAND_bytes(tmpKey, keySizeByte);
    if (res <= 0) {
        DLP_LOG_ERROR(LABEL, "Generate key fail, generate rand bytes error, errno=%{public}d", res);
        (void)memset_s(tmpKey, keySizeByte, 0, keySizeByte);
        delete[] tmpKey;
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    } else {
        key->data = tmpKey;
        key->size = keySizeByte;
    }
    return DLP_OK;
}

static const EVP_CIPHER* GetCtrCipherType(uint32_t keySize)
{
    switch (keySize) {
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_128):
            return EVP_aes_128_ctr();
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_192):
            return EVP_aes_192_ctr();
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_256):
            return EVP_aes_256_ctr();
        default:
            return nullptr;
    }
}

inline void DlpLogOpensslError(void)
{
    char szErr[DLP_OPENSSL_ERROR_LEN] = {0};
    unsigned long errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, DLP_OPENSSL_ERROR_LEN);
    DLP_LOG_ERROR(LABEL, "Openssl engine error, errno=%{public}lu, errmsg=%{public}s", errCode, szErr);
}

static int32_t OpensslAesCipherInit(
    const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec, bool isEncrypt, EVP_CIPHER_CTX** ctx)
{
    int32_t ret;
    struct DlpCipherParam* cipherParam = usageSpec->algParam;

    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == nullptr) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const EVP_CIPHER* cipher = GetCtrCipherType(key->size);
    if (cipher == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes cipher init fail, get cipher type error");
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(*ctx, cipher, nullptr, nullptr, nullptr);
    } else {
        ret = EVP_DecryptInit_ex(*ctx, cipher, nullptr, nullptr, nullptr);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(
            *ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    } else {
        ret = EVP_DecryptInit_ex(
            *ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = EVP_CIPHER_CTX_set_padding(*ctx, OPENSSL_CTX_PADDING_ENABLE);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptFinal(
    EVP_CIPHER_CTX* ctx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    int32_t outLen = 0;

    if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = static_cast<uint32_t>(outLen);

    if (EVP_EncryptFinal_ex(ctx, cipherText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size += static_cast<uint32_t>(outLen);

    EVP_CIPHER_CTX_free(ctx);
    return DLP_OK;
}

static int32_t OpensslAesCipherCryptInitParams(const struct DlpBlob* key, EVP_CIPHER_CTX* ctx,
    const struct DlpCipherParam* cipherParam, bool isEncrypt)
{
    int32_t ret;
    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(
            ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    } else {
        ret = EVP_DecryptInit_ex(
            ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    ret = EVP_CIPHER_CTX_set_padding(ctx, OPENSSL_CTX_PADDING_ENABLE);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

static int32_t OpensslAesCipherCryptInit(
    const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec, bool isEncrypt, void** cryptoCtx)
{
    int32_t ret;
    struct DlpCipherParam* cipherParam = reinterpret_cast<struct DlpCipherParam*>(usageSpec->algParam);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const EVP_CIPHER* cipher = GetCtrCipherType(key->size);
    if (cipher == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes cipher crypt init fail, get cipher type error");
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    } else {
        ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = OpensslAesCipherCryptInitParams(key, ctx, cipherParam, isEncrypt);
    if (ret != DLP_OK) {
        EVP_CIPHER_CTX_free(ctx);
        DLP_LOG_ERROR(LABEL, "Aes cipher crypt init fail, init cipher params error, errno=%d", ret);
        return ret;
    }

    struct DlpOpensslAesCtx* outCtx = static_cast<struct DlpOpensslAesCtx*>(malloc(sizeof(DlpOpensslAesCtx)));
    if (outCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes cipher crypt init fail, alloc aes ctx fail");
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->append = static_cast<void*>(ctx);

    *cryptoCtx = static_cast<void*>(outCtx);

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    struct DlpOpensslAesCtx* aesCtx = static_cast<struct DlpOpensslAesCtx*>(cryptoCtx);
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(aesCtx->append);
    if (ctx == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t outLen = 0;
    if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = static_cast<uint32_t>(outLen);

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptFinalThree(
    void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(aesCtx->append);

    if (ctx == nullptr) {
        DLP_FREE_PTR(*cryptoCtx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = DLP_OK;
    do {
        int32_t outLen = 0;
        if (message->size != 0) {
            if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) !=
                DLP_OPENSSL_SUCCESS) {
                DlpLogOpensslError();
                ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
            cipherText->size = static_cast<uint32_t>(outLen);
        }

        if (EVP_EncryptFinal_ex(ctx, (cipherText->data + outLen), &outLen) != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size += static_cast<uint32_t>(outLen);
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    aesCtx->append = nullptr;
    DLP_FREE_PTR(*cryptoCtx);

    return ret;
}

static int32_t OpensslAesCipherDecryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    struct DlpOpensslAesCtx* aesCtx = static_cast<struct DlpOpensslAesCtx*>(cryptoCtx);
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(aesCtx->append);

    if (ctx == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t outLen = 0;
    if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size = static_cast<uint32_t>(outLen);

    return DLP_OK;
}

static int32_t OpensslAesCipherDecryptFinalThree(
    void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    EVP_CIPHER_CTX* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(aesCtx->append);
    if (ctx == nullptr) {
        DLP_FREE_PTR(*cryptoCtx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = DLP_OK;
    do {
        int32_t outLen = 0;
        if (message->size != 0) {
            if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
                DlpLogOpensslError();
                ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
            plainText->size = static_cast<uint32_t>(outLen);
        }

        if (EVP_DecryptFinal_ex(ctx, plainText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        plainText->size += static_cast<uint32_t>(outLen);
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    aesCtx->append = nullptr;
    DLP_FREE_PTR(*cryptoCtx);
    return ret;
}

static int32_t OpensslAesCipherDecryptFinal(
    EVP_CIPHER_CTX* ctx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    int32_t outLen = 0;

    if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size = static_cast<uint32_t>(outLen);

    if (EVP_DecryptFinal_ex(ctx, plainText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size += static_cast<uint32_t>(outLen);

    EVP_CIPHER_CTX_free(ctx);
    return DLP_OK;
}

int32_t DlpOpensslAesEncryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt init fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt init fail, usage spec is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(key)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt init fail, key is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherCryptInit(key, usageSpec, true, cryptoCtx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes encrypt init fail, errno=%{public}d", ret);
                return ret;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Aes encrypt init fail, aes mode 0x%{public}x unsupport", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesEncryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt update fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlobZero(message)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt update fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(cipherText)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt update fail, cipher text is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = static_cast<struct DlpOpensslAesCtx*>(cryptoCtx);
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherEncryptUpdate(cryptoCtx, message, cipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes encrypt update fail, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes encrypt update fail, aes mode 0x%{public}x unsupport", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesEncryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt final fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlobZero(message)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt final fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(cipherText)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt final fail, cipher text is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)*cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherEncryptFinalThree(cryptoCtx, message, cipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes encrypt final fail, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes encrypt final fail, aes mode 0x%{public}x unsupport", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesDecryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt init fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt init fail, usage spec is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(key)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt init fail, key is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherCryptInit(key, usageSpec, false, cryptoCtx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes decrypt init fail, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes decrypt init fail, aes mode 0x%{public}x unsupport", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return ret;
}

int32_t DlpOpensslAesDecryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt update fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlobZero(message)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt update fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(plainText)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt update fail, plain text is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = static_cast<struct DlpOpensslAesCtx*>(cryptoCtx);
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherDecryptUpdate(cryptoCtx, message, plainText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes decrypt update fail, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes decrypt update fail, aes mode 0x%{public}x unsupport", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return ret;
}

int32_t DlpOpensslAesDecryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt final fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlobZero(message)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt final fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(plainText)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt final fail, plain text is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)*cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherDecryptFinalThree(cryptoCtx, message, plainText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes decrypt final fail, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes decrypt final fail, aes mode 0x%{public}x unsupport", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

void DlpOpensslAesHalFreeCtx(void** cryptoCtx)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Aes free ctx fail, cxt is null");
        return;
    }

    struct DlpOpensslAesCtx* opensslAesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    switch (opensslAesCtx->mode) {
        case DLP_MODE_CTR:
            if (reinterpret_cast<EVP_CIPHER_CTX*>(opensslAesCtx->append) != nullptr) {
                EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX*>(opensslAesCtx->append));
                opensslAesCtx->append = nullptr;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Aes free ctx fail, aes mode 0x%{public}x unsupport", opensslAesCtx->mode);
            break;
    }

    DLP_FREE_PTR(*cryptoCtx);
}

static bool AesParamCheck(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Check aes params fail, usage spec is null");
        return false;
    }

    if (!DlpOpensslCheckBlob(key)) {
        DLP_LOG_ERROR(LABEL, "Check aes params fail, key is invalid");
        return false;
    }

    if (!DlpOpensslCheckBlob(message)) {
        DLP_LOG_ERROR(LABEL, "Check aes params fail, msg in invalid");
        return false;
    }

    if (!DlpOpensslCheckBlob(cipherText)) {
        DLP_LOG_ERROR(LABEL, "Check aes params fail, cipher text is invalid");
        return false;
    }

    return true;
}

int32_t DlpOpensslAesEncrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (!AesParamCheck(key, usageSpec, message, cipherText)) {
        DLP_LOG_ERROR(LABEL, "Aes encrypt fail, check aes params error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    EVP_CIPHER_CTX* ctx = nullptr;
    struct DlpBlob tmpCipherText = *cipherText;

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherInit(key, usageSpec, true, &ctx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes encrypt fail, encrypt init error, errno=%{public}d", ret);
                return ret;
            }

            ret = OpensslAesCipherEncryptFinal(ctx, message, &tmpCipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes encrypt fail, encrypt final error, errno=%{public}d", ret);
                return ret;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Aes encrypt fail, aes mode 0x%{public}x unsupport", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    cipherText->size = tmpCipherText.size;
    return DLP_OK;
}

int32_t DlpOpensslAesDecrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* plainText)
{
    if (!AesParamCheck(key, usageSpec, message, plainText)) {
        DLP_LOG_ERROR(LABEL, "Aes decrypt fail, check aes params error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    EVP_CIPHER_CTX* ctx = nullptr;
    struct DlpBlob tmpPlainText = *plainText;

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherInit(key, usageSpec, false, &ctx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes decrypt fail, decrypt init error, errno=%{public}d", ret);
                return ret;
            }

            ret = OpensslAesCipherDecryptFinal(ctx, message, &tmpPlainText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "Aes decrypt fail, decrypt final error, errno=%{public}d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Aes decrypt fail, aes mode 0x%{public}x unsupport", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    plainText->size = tmpPlainText.size;
    return ret;
}

static bool CheckDigestAlg(uint32_t alg)
{
    switch (alg) {
        case DLP_DIGEST_SHA256:
        case DLP_DIGEST_SHA384:
        case DLP_DIGEST_SHA512:
            return true;
        default:
            return false;
    }
}

const EVP_MD* GetOpensslAlg(uint32_t alg)
{
    switch (alg) {
        case DLP_DIGEST_SHA256:
            return EVP_sha256();
        case DLP_DIGEST_SHA384:
            return EVP_sha384();
        case DLP_DIGEST_SHA512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

static uint32_t GetHashLen(uint32_t alg)
{
    if (alg == DLP_DIGEST_SHA256) {
        return SHA256_LEN;
    } else if (alg == DLP_DIGEST_SHA384) {
        return SHA384_LEN;
    } else {
        return SHA512_LEN;
    }
}

static bool HashCheckParam(uint32_t alg, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    if (!CheckDigestAlg(alg)) {
        DLP_LOG_ERROR(LABEL, "Check hash param fail, alg type is unsupported");
        return false;
    }

    if (!DlpOpensslCheckBlob(hash)) {
        DLP_LOG_ERROR(LABEL, "Check hash param fail, hash is invalid");
        return false;
    }

    uint32_t hashLen = GetHashLen(alg);
    if (hash->size < hashLen) {
        DLP_LOG_ERROR(LABEL, "Check hash param fail, hash buff too short");
        return false;
    }

    if (!DlpOpensslCheckBlob(msg)) {
        DLP_LOG_ERROR(LABEL, "Check hash param fail, msg is invalid");
        return false;
    }

    return true;
}

int32_t DlpOpensslHash(uint32_t alg, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    if (!HashCheckParam(alg, msg, hash)) {
        DLP_LOG_ERROR(LABEL, "Openssl hash fail, param is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    const EVP_MD* opensslAlg = GetOpensslAlg(alg);
    if (opensslAlg == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash fail, get alg fail");
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    int32_t ret = EVP_Digest(msg->data, msg->size, hash->data, &hash->size, opensslAlg, nullptr);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

int32_t DlpOpensslHashInit(void** cryptoCtx, uint32_t alg)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash init fail, ctx is null");
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }
    if (!CheckDigestAlg(alg)) {
        DLP_LOG_ERROR(LABEL, "Openssl hash init fail, alg is invalid");
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }
    const EVP_MD* opensslAlg = GetOpensslAlg(alg);
    if (opensslAlg == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash init fail, get alg fail");
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    EVP_MD_CTX* tmpctx = EVP_MD_CTX_new();
    if (tmpctx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash init fail, alloc ctx fail");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    EVP_MD_CTX_set_flags(tmpctx, EVP_MD_CTX_FLAG_ONESHOT);
    int32_t ret = EVP_DigestInit_ex(tmpctx, opensslAlg, nullptr);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_MD_CTX_free(tmpctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    *cryptoCtx = static_cast<void*>(tmpctx);
    return DLP_OK;
}

int32_t DlpOpensslHashUpdate(void* cryptoCtx, const struct DlpBlob* msg)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash update fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(msg)) {
        DLP_LOG_ERROR(LABEL, "Openssl hash update fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = EVP_DigestUpdate(
        reinterpret_cast<EVP_MD_CTX*>(cryptoCtx), reinterpret_cast<void*>(msg->data), msg->size);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

int32_t DlpOpensslHashFinal(void** cryptoCtx, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash final fail, ctx is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlobZero(msg)) {
        DLP_LOG_ERROR(LABEL, "Openssl hash final fail, msg is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (!DlpOpensslCheckBlob(hash)) {
        DLP_LOG_ERROR(LABEL, "Openssl hash final fail, hash is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    if (msg->size != 0) {
        ret = EVP_DigestUpdate((EVP_MD_CTX*)*cryptoCtx, msg->data, msg->size);
        if (ret != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
            *cryptoCtx = nullptr;
            return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }

    ret = EVP_DigestFinal_ex((EVP_MD_CTX*)*cryptoCtx, hash->data, &hash->size);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
        *cryptoCtx = nullptr;
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
    *cryptoCtx = nullptr;
    return DLP_OK;
}

int32_t DlpOpensslHashFreeCtx(void** cryptoCtx)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl hash free ctx fail, param is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
    *cryptoCtx = nullptr;
    return DLP_OK;
}

static void IncIvCounterLitteEndian(struct DlpBlob& iv, uint32_t count)
{
    uint8_t* data = iv.data;
    int size = static_cast<int>(iv.size - 1);
    for (int i = size; i >= 0; i--) {
        count += data[i];
        data[i] = static_cast<uint8_t>(count);
        count >>= BYTE_LEN;
        if (count == 0) {
            break;
        }
    }
}

int32_t DlpCtrModeIncreaeIvCounter(struct DlpBlob& iv, uint32_t count)
{
    if (iv.data == nullptr || iv.size == 0) {
        DLP_LOG_ERROR(LABEL, "param error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    IncIvCounterLitteEndian(iv, count);
    return DLP_OK;
}

int32_t DlpHmacEncode(const DlpBlob& key, int32_t fd, DlpBlob& out)
{
    if ((key.data == nullptr) || (key.size != SHA256_KEY_LEN)) {
        DLP_LOG_ERROR(LABEL, "Key blob invalid, size %{public}u", key.size);
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }
    if ((out.data == nullptr) || (out.size < HMAC_SIZE)) {
        DLP_LOG_ERROR(LABEL, "Output blob invalid, size %{public}u", out.size);
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == nullptr) {
        DLP_LOG_ERROR(LABEL, "HMAC_CTX is null");
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    if (HMAC_Init_ex(ctx, key.data, key.size, EVP_sha256(), nullptr) != 1) {
        DLP_LOG_ERROR(LABEL, "HMAC_Init failed");
        HMAC_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    auto buf = std::make_unique<unsigned char[]>(BUFFER_SIZE);
    int32_t readSize;
    while ((readSize = read(fd, buf.get(), BUFFER_SIZE)) > 0) {
        if (HMAC_Update(ctx, buf.get(), readSize) != 1) {
            DLP_LOG_ERROR(LABEL, "HMAC_Update failed");
            HMAC_CTX_free(ctx);
            return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }
    if (HMAC_Final(ctx, out.data, &out.size) != 1) {
        DLP_LOG_ERROR(LABEL, "HMAC_Final failed");
        HMAC_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    HMAC_CTX_free(ctx);
    return DLP_OK;
}
#ifdef __cplusplus
}
#endif
