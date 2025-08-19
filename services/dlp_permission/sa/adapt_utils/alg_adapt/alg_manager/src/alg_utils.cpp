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

#include "alg_utils.h"

#include <unistd.h>
#include "securec.h"

#include "dlp_permission_log.h"

#define MAX_FOLDER_NAME_SIZE 128

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AlgUtils" };
const int PARCEL_DEFAULT_INCREASE_STEP = 16;
const uint32_t PARCEL_UINT_MAX = 0xffffffffU;
}

void *HcMalloc(uint32_t size, char val)
{
    if (size == 0 || size > MAX_MALLOC_SIZE) {
        DLP_LOG_ERROR(LABEL, "Malloc size is invalid.");
        return nullptr;
    }
    void *addr = malloc(size);
    if (addr != nullptr) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

void HcFree(void *addr)
{
    if (addr != nullptr) {
        free(addr);
    }
}

uint32_t HcStrlen(const char *str)
{
    if (str == nullptr) {
        return 0;
    }
    return strlen(str);
}

void *ClibMalloc(uint32_t size, char val)
{
    if (size == 0 || size > CLIB_MAX_MALLOC_SIZE) {
        return nullptr;
    }
    void *addr = malloc(size);
    if (addr != nullptr) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

bool IsBlobDataValid(const BlobData *blob)
{
    if (blob == nullptr) {
        DLP_LOG_ERROR(LABEL, "Blob is null!");
        return false;
    }
    if (blob->value == nullptr) {
        DLP_LOG_ERROR(LABEL, "The value of blob is null!");
        return false;
    }
    if (blob->dataSize == 0) {
        DLP_LOG_ERROR(LABEL, "The data size of blob is zero!");
        return false;
    }
    return true;
}

void FreeBlobData(BlobData *data)
{
    if (data == nullptr) {
        return;
    }
    HcFree(data->value);
    data->value = nullptr;
    data->dataSize = 0;
}

HcParcel CreateParcel(uint32_t size, uint32_t allocUnit)
{
    HcParcel parcel;
    (void)memset_s(&parcel, sizeof(parcel), 0, sizeof(parcel));
    parcel.allocUnit = allocUnit;
    if (parcel.allocUnit == 0) {
        parcel.allocUnit = PARCEL_DEFAULT_INCREASE_STEP;
    }
    if (size > 0) {
        parcel.data = static_cast<char *>(ClibMalloc(size, 0));
        if (parcel.data != nullptr) {
            parcel.length = size;
        }
    }
    return parcel;
}

void DeleteParcel(HcParcel *parcel)
{
    if (parcel == nullptr) {
        return;
    }

    if (parcel->data != nullptr) {
        HcFree(parcel->data);
        parcel->data = 0;
    }
    parcel->length = 0;
    parcel->beginPos = 0;
    parcel->endPos = 0;
}

uint32_t GetParcelDataSize(const HcParcel *parcel)
{
    if (parcel == nullptr) {
        return 0;
    }
    if (parcel->endPos >= parcel->beginPos) {
        return parcel->endPos - parcel->beginPos;
    }
    return 0;
}

const char *GetParcelData(const HcParcel *parcel)
{
    if (parcel == nullptr) {
        return nullptr;
    }
    return parcel->data + parcel->beginPos;
}

HcBool ParcelRead(HcParcel *parcel, void *dst, uint32_t dataSize)
{
    errno_t rc;
    if (parcel == nullptr || dst == nullptr || dataSize == 0) {
        return HC_FALSE;
    }
    if (parcel->beginPos > PARCEL_UINT_MAX - dataSize) {
        return HC_FALSE;
    }
    if (parcel->beginPos + dataSize > parcel->endPos) {
        return HC_FALSE;
    }
    rc = memmove_s(dst, dataSize, parcel->data + parcel->beginPos, dataSize);
    if (rc != EOK) {
        return HC_FALSE;
    }
    parcel->beginPos += dataSize;
    return HC_TRUE;
}

static HcBool ParcelRealloc(HcParcel *parcel, uint32_t size)
{
    if (parcel->length >= size) {
        return HC_FALSE;
    }
    char *newData = static_cast<char *>(ClibMalloc(size, 0));
    if (newData == nullptr) {
        return HC_FALSE;
    }
    if (memcpy_s(newData, size, parcel->data, parcel->length) != EOK) {
        HcFree(newData);
        return HC_FALSE;
    }
    HcFree(parcel->data);
    parcel->data = newData;
    parcel->length = size;
    return HC_TRUE;
}

static HcBool ParcelIncrease(HcParcel *parcel, uint32_t size)
{
    if (parcel == nullptr || size == 0) {
        return HC_FALSE;
    }
    if (parcel->data == nullptr) {
        if (parcel->length != 0) {
            return HC_FALSE;
        }
        *parcel = CreateParcel(size, parcel->allocUnit);
        if (parcel->data == nullptr) {
            return HC_FALSE;
        } else {
            return HC_TRUE;
        }
    } else {
        return ParcelRealloc(parcel, size);
    }
}

static void ParcelRecycle(HcParcel *parcel)
{
    if (parcel == nullptr) {
        return;
    }
    if (parcel->data == nullptr || parcel->beginPos < parcel->allocUnit) {
        return;
    }

    uint32_t contentSize = parcel->endPos - parcel->beginPos;
    if (contentSize > 0) {
        if (memmove_s(parcel->data, contentSize, parcel->data + parcel->beginPos, contentSize) != EOK) {
            return;
        }
    }
    parcel->beginPos = 0;
    parcel->endPos = contentSize;
}

static uint32_t GetParcelIncreaseSize(HcParcel *parcel, uint32_t newSize)
{
    if (parcel == nullptr || parcel->allocUnit == 0) {
        return 0;
    }
    if (newSize % parcel->allocUnit) {
        return (newSize / parcel->allocUnit + 1) * parcel->allocUnit;
    } else {
        return (newSize / parcel->allocUnit) * parcel->allocUnit;
    }
}

HcBool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize)
{
    errno_t rc;
    if (parcel == nullptr || src == nullptr || dataSize == 0) {
        return HC_FALSE;
    }
    if (parcel->endPos > PARCEL_UINT_MAX - dataSize) {
        return HC_FALSE;
    }
    if (parcel->endPos + dataSize > parcel->length) {
        ParcelRecycle(parcel);
        if (parcel->endPos + dataSize > parcel->length) {
            uint32_t newSize = GetParcelIncreaseSize(parcel, parcel->endPos + dataSize);
            if (!ParcelIncrease(parcel, newSize)) {
                return HC_FALSE;
            }
        }
    }
    rc = memmove_s(parcel->data + parcel->endPos, dataSize, src, dataSize);
    if (rc != EOK) {
        return HC_FALSE;
    }
    parcel->endPos += dataSize;
    return HC_TRUE;
}

static int32_t CreateDirectory(const char *filePath)
{
    int32_t ret;
    errno_t eno;
    const char *chPtr = nullptr;
    char dirCache[MAX_FOLDER_NAME_SIZE];

    chPtr = filePath;
    while ((chPtr = strchr(chPtr, '/')) != nullptr) {
        unsigned long len = (unsigned long)((uintptr_t)chPtr - (uintptr_t)filePath);
        if (len == 0uL) {
            chPtr++;
            continue;
        }
        if (len >= MAX_FOLDER_NAME_SIZE) {
            DLP_LOG_ERROR(LABEL, "the length of folder in filePath is too long.");
            return -1;
        }
        eno = memcpy_s(dirCache, sizeof(dirCache), filePath, len);
        if (eno != EOK) {
            DLP_LOG_ERROR(LABEL, "memory copy failed");
            return -1;
        }
        dirCache[len] = 0;
        if (access(dirCache, F_OK) != 0) {
            ret = mkdir(dirCache, S_IRWXU);
            if (ret != 0) {
                DLP_LOG_ERROR(LABEL, "make dir failed, err code %{public}d", ret);
                return -1;
            }
        }
        chPtr++;
    }
    return 0;
}

static FILE *HcFileOpenRead(const char *path)
{
    return fopen(path, "rb");
}

static FILE *HcFileOpenWrite(const char *path, mode_t permissionMode)
{
    if (access(path, F_OK) != 0) {
        int32_t ret = CreateDirectory(path);
        if (ret != 0) {
            return nullptr;
        }
    }

    mode_t oldMask = umask(permissionMode);
    FILE *fp = fopen(path, "w+");
    (void)umask(oldMask);
    return fp;
}

int HcFileOpen(const char *path, int mode, FileHandle *file, mode_t permissionMode)
{
    if (path == nullptr || file == nullptr) {
        return -1;
    }
    if (mode == MODE_FILE_READ) {
        file->pfd = HcFileOpenRead(path);
    } else {
        file->pfd = HcFileOpenWrite(path, permissionMode);
    }

    if (file->pfd == nullptr) {
        return -1;
    }
    return 0;
}

int HcFileSize(FileHandle file)
{
    FILE *fp = (FILE *)file.pfd;
    if (fp != nullptr) {
        if (fseek(fp, 0L, SEEK_END) != 0) {
            return -1;
        }
        int size = ftell(fp);
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            return -1;
        }
        return size;
    } else {
        return -1;
    }
}

int HcFileRead(FileHandle file, void *dst, int dstSize)
{
    FILE *fp = (FILE *)file.pfd;
    if (fp == nullptr || dstSize < 0 || dst == nullptr) {
        return -1;
    }

    char *dstBuffer = static_cast<char *>(dst);
    int total = 0;
    while (total < dstSize) {
        int readCount = (int)fread(dstBuffer + total, 1, dstSize - total, fp);
        if (ferror(fp) != 0) {
            DLP_LOG_ERROR(LABEL, "read file error!");
        }
        if (readCount == 0) {
            return total;
        }
        total += readCount;
    }

    return total;
}

int HcFileWrite(FileHandle file, const void *src, int srcSize)
{
    FILE *fp = (FILE *)file.pfd;
    if (fp == nullptr || srcSize < 0 || src == nullptr) {
        return -1;
    }

    const char *srcBuffer = static_cast<const char *>(src);
    int total = 0;
    while (total < srcSize) {
        int writeCount = (int)fwrite(srcBuffer + total, 1, srcSize - total, fp);
        if (ferror(fp) != 0) {
            DLP_LOG_ERROR(LABEL, "write file error!");
        }
        total += writeCount;
    }
    return total;
}

void HcFileClose(FileHandle file)
{
    FILE *fp = (FILE *)file.pfd;
    if (fp == nullptr) {
        return;
    }

    (void)fclose(fp);
}

bool HcIsFileExist(const char *path)
{
    if (path == nullptr) {
        DLP_LOG_ERROR(LABEL, "Input params is invalid");
        return false;
    }
    if (access(path, 0) != 0) {
        return false;
    }
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS