/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dlp_format.h"
#include "dlp_utils.h"
#include <iostream>
#include <fstream>
#include <new>
#include <securec.h>
#include <string>
#include <vector>
#include <unistd.h>

namespace OHOS {
namespace Security {
namespace DlpFormat {
using namespace std;
#define DLP_BUFF_LEN (4096)
#define DLP_FILE_MAGIC (0x87f4922)
#define DLP_MAX_CERT_SIZE (1024 * 1024)

DlpFile::DlpFile()
{
    head_.magic = DLP_FILE_MAGIC;
    head_.version = 1;
    head_.txtOffset = 0xffffffff;
    head_.txtSize = 0xffffffff;
    cert_.certBuff = nullptr;
    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = 0;

    cipher_.tagIv.iv.data = nullptr;
    cipher_.tagIv.iv.size = 0;

    cipher_.encKey.data = nullptr;
    cipher_.encKey.size = 0;

    cipher_.usageSpec = { 0 };
}

DlpFile::~DlpFile()
{
    // clear key
    if (cipher_.encKey.data != nullptr) {
        (void)memset_s(cipher_.encKey.data, cipher_.encKey.size, 0, cipher_.encKey.size);
        delete[] cipher_.encKey.data;
        cipher_.encKey.data = nullptr;
    }

    // clear iv
    if (cipher_.tagIv.iv.data != nullptr) {
        (void)memset_s(cipher_.tagIv.iv.data, cipher_.tagIv.iv.size, 0, cipher_.tagIv.iv.size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
    }

    // clear encrypt cert
    if (cert_.certBuff != nullptr) {
        (void)memset_s(cert_.certBuff, head_.certSize, 0, head_.certSize);
        delete[] cert_.certBuff;
        cert_.certBuff = nullptr;
    }
}

static int32_t ValidateCipher(const struct DlpBlob &key, const struct DlpUsageSpec &spec)
{
    if (key.data == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (spec.mode != DLP_MODE_CTR || spec.algParam == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    struct DlpBlob *iv = &(spec.algParam->iv);

    if (iv->size != VALID_IV_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (key.size != DLP_KEY_LEN_128 && key.size != DLP_KEY_LEN_192 && key.size != DLP_KEY_LEN_256) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    return DLP_SUCCESS;
}

int32_t DlpFile::SetCipher(const struct DlpBlob &key, const struct DlpUsageSpec &spec)
{
    struct DlpBlob *iv = &(spec.algParam->iv);

    if (ValidateCipher(key, spec)) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    cipher_.tagIv.iv.data = new (std::nothrow) uint8_t[iv->size];
    if (cipher_.tagIv.iv.data == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    if (memcpy_s(cipher_.tagIv.iv.data, iv->size, iv->data, iv->size) != 0) {
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
        return DLP_ERROR_MEMCPY_FAIL;
    }
    cipher_.tagIv.iv.size = iv->size;

    cipher_.encKey.data = new (std::nothrow) uint8_t[key.size];
    if (cipher_.encKey.data == nullptr) {
        (void)memset_s(cipher_.tagIv.iv.data, iv->size, 0, iv->size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
        return DLP_ERROR_MALLOC_FAIL;
    }

    if (memcpy_s(cipher_.encKey.data, key.size, key.data, key.size) != 0) {
        (void)memset_s(cipher_.tagIv.iv.data, iv->size, 0, iv->size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
        delete[] cipher_.encKey.data;
        cipher_.encKey.data = nullptr;
        return DLP_ERROR_MEMCPY_FAIL;
    }
    cipher_.encKey.size = key.size;

    cipher_.usageSpec.mode = spec.mode;
    cipher_.usageSpec.algParam = &cipher_.tagIv;

    return DLP_SUCCESS;
}

int32_t DlpFile::SetEncryptCert(const struct DlpBlob &data)
{
    if (data.data == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (data.size == 0 || data.size > DLP_MAX_CERT_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    cert_.certBuff = new (nothrow)uint8_t[data.size];
    if (cert_.certBuff == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    if (memcpy_s(cert_.certBuff, data.size, data.data, data.size) != 0) {
        delete[] cert_.certBuff;
        cert_.certBuff = nullptr;
        return DLP_ERROR_MEMCPY_FAIL;
    }

    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = data.size;
    head_.txtOffset = sizeof(struct DlpHeader) + data.size;

    return DLP_SUCCESS;
}

static int32_t ValidateDlpHeader(struct DlpHeader &head)
{
    if (head.magic != DLP_FILE_MAGIC) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }
    return DLP_SUCCESS;
}

int32_t DlpFile::FileParse(const std::string &inputFileUri, struct DlpHeader &head, struct DlpEncryptCert &cert)
{
    ifstream in(inputFileUri, ios::in | ios::binary);
    if (!in.is_open()) {
        return DLP_ERROR_FILE_FAIL;
    }

    in.read((char *)&head, sizeof(struct DlpHeader));
    if (ValidateDlpHeader(head) != DLP_SUCCESS) {
        in.close();
        return DLP_ERROR_NOT_DLP_FILE;
    }

    // parse cert
    uint8_t *buf = new (nothrow)uint8_t[head.certSize];
    if (buf == nullptr) {
        in.close();
        return DLP_ERROR_MALLOC_FAIL;
    }
    in.read((char *)buf, head.certSize);
    cert.certBuff = buf;
    in.close();
    return DLP_SUCCESS;
}

int32_t DlpFile::FileParse(const std::string &inputFileUri)
{
    int32_t ret = FileParse(inputFileUri, head_, cert_);
    if (ret != DLP_SUCCESS) {
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
    }
    return ret;
}

int32_t DlpFile::FileParse(int32_t fd)
{
    int32_t ret = read(fd, (void *)&head_, sizeof(struct DlpHeader));
    if (ret < 0) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (ValidateDlpHeader(head_) != 0) {
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_ERROR_NOT_DLP_FILE;
    }

    // parse cert
    uint8_t *buf = new (nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }
    read(fd, (void *)buf, head_.certSize);
    cert_.certBuff = buf;

    return DLP_SUCCESS;
}

uint32_t DlpFile::GetTxtOffset()
{
    return head_.txtOffset;
}

static int32_t PrepareBuff(struct DlpBlob &message1, struct DlpBlob &message2)
{
    message1.size = DLP_BUFF_LEN;
    message1.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message1.data == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    message2.size = DLP_BUFF_LEN;
    message2.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message2.data == nullptr) {
        delete[] message1.data;
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memset_s(message1.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    (void)memset_s(message2.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    return DLP_SUCCESS;
}

static inline void ClearLocal(struct DlpBlob &message1, struct DlpBlob &message2, ifstream &in, ofstream &out)
{
    delete[] message1.data;
    delete[] message2.data;
    out.close();
    in.close();
}

static int32_t OpenFile(const std::string &inputFileUri, const std::string &outputFileUri, ifstream &in, ofstream &out)
{
    in.open(inputFileUri, ios::in | ios::binary);
    if (!in.is_open()) {
        return DLP_ERROR_FILE_FAIL;
    }

    out.open(outputFileUri, ios::ate | ios::out | ios::binary);
    if (!out.is_open()) {
        in.close();
        return DLP_ERROR_FILE_FAIL;
    }

    return DLP_SUCCESS;
}

static int32_t DlpCipherOper(const struct DlpBlob *key, const struct DlpUsageSpec *usageSpec,
    const struct DlpBlob *message1, struct DlpBlob *message2, uint32_t opFlag)
{
    if (opFlag == DLP_ENCRYPTION) {
        return DlpOpensslAesEncrypt(key, usageSpec, message1, message2);
    } else if (opFlag == DLP_DECRYPTION) {
        return DlpOpensslAesDecrypt(key, usageSpec, message1, message2);
    } else {
        return memcpy_s(message2->data, message2->size, message1->data, message1->size);
    }
}

int32_t DlpFile::GenFile(const std::string &inputFileUri, const std::string &outputFileUri, uint32_t opFlag)
{
    ifstream in;
    ofstream out;
    if (OpenFile(inputFileUri, outputFileUri, in, out) != DLP_SUCCESS) {
        return DLP_ERROR_FILE_FAIL;
    }

    in.seekg(0, ios::end);
    int32_t fileLen = in.tellg();
    in.seekg(0, ios::beg);

    if (opFlag != DLP_DECRYPTION) {
        head_.txtSize = static_cast<uint32_t>(fileLen);
        out.write((char *)&head_, sizeof(struct DlpHeader));
        out.write((char *)cert_.certBuff, head_.certSize);
    }
    struct DlpBlob message, cipherText;
    if (PrepareBuff(message, cipherText) != DLP_SUCCESS) {
        in.close();
        out.close();
        return DLP_ERROR_MALLOC_FAIL;
    }

    if (opFlag == DLP_DECRYPTION) {
        in.seekg(head_.txtOffset, ios::beg);
    }

    int32_t offset;
    int32_t ret = 0;
    offset = in.tellg();
    while (offset < fileLen) {
        int32_t readLen = ((fileLen - offset) < DLP_BUFF_LEN) ? (fileLen - offset) : DLP_BUFF_LEN;
        in.read((char *)message.data, readLen);

        offset = in.tellg();
        message.size = static_cast<uint32_t>(readLen);
        cipherText.size = static_cast<uint32_t>(readLen);
        ret = DlpCipherOper(&cipher_.encKey, &cipher_.usageSpec, &message, &cipherText, opFlag);
        if (ret != 0) {
            break;
        }

        out.write((char *)cipherText.data, readLen);
    }

    ClearLocal(message, cipherText, in, out);

    if (ret != 0) {
        DLP_LOG_E("crypt operation fail, remove file");
        remove(outputFileUri.c_str());
        return DLP_ERROR_CRYPT_FAIL;
    }

    return DLP_SUCCESS;
}

static int32_t CheckStatus(struct DlpHeader *head, struct DlpEncryptCert *cert, struct DlpCipher *cipher,
    uint32_t opFlag)
{
    if (opFlag > DLP_UPDATE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (ValidateDlpHeader(*head)) {
        return DLP_ERROR_INVALID_HEAD;
    }

    if ((opFlag == DLP_UPDATE) && (cert->certBuff == nullptr)) {
        return DLP_ERROR_INVALID_CERT;
    }

    if (opFlag == DLP_DECRYPTION) {
        if (cipher->encKey.data == nullptr || cipher->tagIv.iv.data == nullptr) {
            return DLP_ERROR_INVALID_CIPHER;
        }
    }

    if (opFlag == DLP_ENCRYPTION) {
        if (cipher->encKey.data == nullptr || cipher->tagIv.iv.data == nullptr) {
            return DLP_ERROR_INVALID_CIPHER;
        }

        if (cert->certBuff == nullptr) {
            return DLP_ERROR_INVALID_CERT;
        }
    }

    return DLP_SUCCESS;
}

int32_t DlpFile::Operation(const std::string &inputFileUri, const std::string &outputFileUri, uint32_t opFlag)
{
    if (CheckStatus(&head_, &cert_, &cipher_, opFlag) != DLP_SUCCESS) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }
    return GenFile(inputFileUri, outputFileUri, opFlag);
}
}  // namespace DlpFormat
}  // namespace Security
}  // namespace OHOS
