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
#include "c_mock_common.h"

#include <dlfcn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#ifdef __cplusplus
extern "C" {
#endif

static const std::string OPENSSL_LIB_PATH = "libcrypto_openssl.z.so";

typedef int (*RandBytesFunc)(unsigned char *buf, int num);
typedef const EVP_CIPHER *(*EvpAes128Ctr)(void);
typedef const EVP_CIPHER *(*EvpAes192Ctr)(void);
typedef const EVP_CIPHER *(*EvpAes256Ctr)(void);
typedef unsigned long (*ErrGetError)(void);
typedef void (*ErrErrorStringN)(unsigned long e, char *buf, size_t len);
typedef EVP_CIPHER_CTX *(*EvpCipherCtxNew)(void);
typedef int (*EvpEncryptInitEx)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key, const unsigned char *iv);
typedef int (*EvpDecryptInitEx)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key, const unsigned char *iv);
typedef void (*EvpCipherCtxFree)(EVP_CIPHER_CTX *c);
typedef int (*EvpCipherCtxSetPadding)(EVP_CIPHER_CTX *c, int pad);
typedef int (*EvpEncryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
typedef int (*EvpEncryptFinalEx)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
typedef int (*EvpDecryptUpdate)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
typedef int (*EvpDecryptFinalEx)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);
typedef const EVP_MD *(*EvpSha256)(void);
typedef const EVP_MD *(*EvpSha384)(void);
typedef const EVP_MD *(*EvpSha512)(void);
typedef int (*EvpDigest)(const void *data, size_t count, unsigned char *md, unsigned int *size,
    const EVP_MD *type, ENGINE *impl);
typedef EVP_MD_CTX *(*EvpMDCtxNew)(void);
typedef int (*EvpDigestInitEx)(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
typedef void (*EvpMdCtxSetFlags)(EVP_MD_CTX *ctx, int flags);
typedef void (*EvpMdCtxFree)(EVP_MD_CTX *ctx);
typedef int (*EvpDigestUpdate)(EVP_MD_CTX *ctx, const void *d, size_t cnt);
typedef int (*EvpDigestFinalEx)(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);

static void *g_opensslHandle = nullptr;

static void *GetOpensslLibFunc(const char *funcName)
{
    if (g_opensslHandle == nullptr) {
        g_opensslHandle = dlopen(OPENSSL_LIB_PATH.c_str(), RTLD_LAZY);
        if (g_opensslHandle == nullptr) {
            return nullptr;
        }
    }

    return dlsym(g_opensslHandle, funcName);
}

int RAND_bytes(unsigned char *buf, int num)
{
    if (IsFuncNeedMock("RAND_bytes")) {
        return -1;
    }

    RandBytesFunc func = reinterpret_cast<RandBytesFunc>(GetOpensslLibFunc("RAND_bytes"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(buf, num);
}

const EVP_CIPHER *EVP_aes_128_ctr(void)
{
    if (IsFuncNeedMock("EVP_aes_128_ctr")) {
        return nullptr;
    }

    EvpAes128Ctr func = reinterpret_cast<EvpAes128Ctr>(GetOpensslLibFunc("EVP_aes_128_ctr"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

const EVP_CIPHER *EVP_aes_192_ctr(void)
{
    if (IsFuncNeedMock("EVP_aes_192_ctr")) {
        return nullptr;
    }

    EvpAes192Ctr func = reinterpret_cast<EvpAes192Ctr>(GetOpensslLibFunc("EVP_aes_192_ctr"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

const EVP_CIPHER *EVP_aes_256_ctr(void)
{
    if (IsFuncNeedMock("EVP_aes_256_ctr")) {
        return nullptr;
    }

    EvpAes256Ctr func = reinterpret_cast<EvpAes256Ctr>(GetOpensslLibFunc("EVP_aes_256_ctr"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

unsigned long ERR_get_error(void)
{
    if (IsFuncNeedMock("ERR_get_error")) {
        return 0;
    }

    ErrGetError func = reinterpret_cast<ErrGetError>(GetOpensslLibFunc("ERR_get_error"));
    if (func == nullptr) {
        return 0;
    }
    return (*func)();
}

void ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
    if (IsFuncNeedMock("ERR_error_string_n")) {
        return;
    }

    ErrErrorStringN func = reinterpret_cast<ErrErrorStringN>(GetOpensslLibFunc("ERR_error_string_n"));
    if (func == nullptr) {
        return;
    }
    (*func)(e, buf, len);
}

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void)
{
    if (IsFuncNeedMock("EVP_CIPHER_CTX_new")) {
        return nullptr;
    }

    EvpCipherCtxNew func = reinterpret_cast<EvpCipherCtxNew>(GetOpensslLibFunc("EVP_CIPHER_CTX_new"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key, const unsigned char *iv)
{
    if (IsFuncNeedMock("EVP_EncryptInit_ex")) {
        return -1;
    }

    EvpEncryptInitEx func = reinterpret_cast<EvpEncryptInitEx>(GetOpensslLibFunc("EVP_EncryptInit_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, cipher, impl, key, iv);
}

int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl,
    const unsigned char *key, const unsigned char *iv)
{
    if (IsFuncNeedMock("EVP_DecryptInit_ex")) {
        return -1;
    }

    EvpDecryptInitEx func = reinterpret_cast<EvpDecryptInitEx>(GetOpensslLibFunc("EVP_DecryptInit_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, cipher, impl, key, iv);
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *c)
{
    if (IsFuncNeedMock("EVP_CIPHER_CTX_free")) {
        return;
    }

    EvpCipherCtxFree func = reinterpret_cast<EvpCipherCtxFree>(GetOpensslLibFunc("EVP_CIPHER_CTX_free"));
    if (func == nullptr) {
        return;
    }
    (*func)(c);
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad)
{
    if (IsFuncNeedMock("EVP_CIPHER_CTX_set_padding")) {
        return -1;
    }

    EvpCipherCtxSetPadding func =
        reinterpret_cast<EvpCipherCtxSetPadding>(GetOpensslLibFunc("EVP_CIPHER_CTX_set_padding"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(c, pad);
}

int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    if (IsFuncNeedMock("EVP_EncryptUpdate")) {
        return -1;
    }

    EvpEncryptUpdate func =
        reinterpret_cast<EvpEncryptUpdate>(GetOpensslLibFunc("EVP_EncryptUpdate"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, out, outl, in, inl);
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (IsFuncNeedMock("EVP_EncryptFinal_ex")) {
        return -1;
    }

    EvpEncryptFinalEx func =
        reinterpret_cast<EvpEncryptFinalEx>(GetOpensslLibFunc("EVP_EncryptFinal_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, out, outl);
}

int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    if (IsFuncNeedMock("EVP_DecryptUpdate")) {
        return -1;
    }

    EvpDecryptUpdate func =
        reinterpret_cast<EvpDecryptUpdate>(GetOpensslLibFunc("EVP_DecryptUpdate"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, out, outl, in, inl);
}

int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl)
{
    if (IsFuncNeedMock("EVP_DecryptFinal_ex")) {
        return -1;
    }

    EvpDecryptFinalEx func =
        reinterpret_cast<EvpDecryptFinalEx>(GetOpensslLibFunc("EVP_DecryptFinal_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, outm, outl);
}

const EVP_MD *EVP_sha256(void)
{
    if (IsFuncNeedMock("EVP_sha256")) {
        return nullptr;
    }

    EvpSha256 func =
        reinterpret_cast<EvpSha256>(GetOpensslLibFunc("EVP_sha256"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

const EVP_MD *EVP_sha384(void)
{
    if (IsFuncNeedMock("EVP_sha384")) {
        return nullptr;
    }

    EvpSha384 func =
        reinterpret_cast<EvpSha384>(GetOpensslLibFunc("EVP_sha384"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

const EVP_MD *EVP_sha512(void)
{
    if (IsFuncNeedMock("EVP_sha512")) {
        return nullptr;
    }

    EvpSha512 func =
        reinterpret_cast<EvpSha512>(GetOpensslLibFunc("EVP_sha512"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size,
    const EVP_MD *type, ENGINE *impl)
{
    if (IsFuncNeedMock("EVP_Digest")) {
        return -1;
    }

    EvpDigest func =
        reinterpret_cast<EvpDigest>(GetOpensslLibFunc("EVP_Digest"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(data, count, md, size, type, impl);
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
    if (IsFuncNeedMock("EVP_MD_CTX_new")) {
        return nullptr;
    }

    EvpMDCtxNew func =
        reinterpret_cast<EvpMDCtxNew>(GetOpensslLibFunc("EVP_MD_CTX_new"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)();
}

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    if (IsFuncNeedMock("EVP_DigestInit_ex")) {
        return -1;
    }

    EvpDigestInitEx func =
        reinterpret_cast<EvpDigestInitEx>(GetOpensslLibFunc("EVP_DigestInit_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, type, impl);
}

void EVP_MD_CTX_set_flags(EVP_MD_CTX *ctx, int flags)
{
    if (IsFuncNeedMock("EVP_MD_CTX_set_flags")) {
        return;
    }

    EvpMdCtxSetFlags func =
        reinterpret_cast<EvpMdCtxSetFlags>(GetOpensslLibFunc("EVP_MD_CTX_set_flags"));
    if (func == nullptr) {
        return;
    }
    (*func)(ctx, flags);
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
    if (IsFuncNeedMock("EVP_MD_CTX_free")) {
        return;
    }

    EvpMdCtxFree func =
        reinterpret_cast<EvpMdCtxFree>(GetOpensslLibFunc("EVP_MD_CTX_free"));
    if (func == nullptr) {
        return;
    }
    (*func)(ctx);
}

int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
    if (IsFuncNeedMock("EVP_DigestUpdate")) {
        return -1;
    }

    EvpDigestUpdate func =
        reinterpret_cast<EvpDigestUpdate>(GetOpensslLibFunc("EVP_DigestUpdate"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, d, cnt);
}

int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
{
    if (IsFuncNeedMock("EVP_DigestFinal_ex")) {
        return -1;
    }

    EvpDigestFinalEx func =
        reinterpret_cast<EvpDigestFinalEx>(GetOpensslLibFunc("EVP_DigestFinal_ex"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(ctx, md, s);
}
#ifdef __cplusplus
}
#endif
