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

#ifndef ALG_UTILS_H
#define ALG_UTILS_H

#include <stdint.h>
#include <sys/stat.h>

#define MAX_MALLOC_SIZE (1024 * 500) /* 500K */
#define CLIB_MAX_MALLOC_SIZE 40960 /* 40K */
#define MAX_POLICY_DATA_LEN (100 * 1024)

typedef uint32_t HcBool;
#define HC_TRUE 1
#define HC_FALSE 0

namespace OHOS {
namespace Security {
namespace DlpPermission {

typedef struct {
    uint32_t dataSize;
    uint8_t *value;
} BlobData;

typedef struct {
    char *data;
    unsigned int beginPos;
    unsigned int endPos;
    unsigned int length;
    unsigned int allocUnit;
} HcParcel;

typedef union {
    void *pfd;
    int fd;
} FileHandle;

#define MODE_FILE_READ 0
#define MODE_FILE_WRITE 1
#define USER_R_W_FILE_PERMISSION 066

#define DLP_FREE_PTR(ptr) \
{ \
    HcFree(ptr); \
    (ptr) = NULL; \
}

void* HcMalloc(uint32_t size, char val);
void HcFree(void* addr);
uint32_t HcStrlen(const char *str);
void* ClibMalloc(uint32_t size, char val);

bool IsBlobDataValid(const BlobData *blob);
void FreeBlobData(BlobData *data);

HcParcel CreateParcel(uint32_t size, uint32_t allocUnit);
void DeleteParcel(HcParcel *parcel);
uint32_t GetParcelDataSize(const HcParcel *parcel);
const char *GetParcelData(const HcParcel *parcel);
HcBool ParcelRead(HcParcel *parcel, void *dst, uint32_t dataSize);
HcBool ParcelWrite(HcParcel *parcel, const void *src, uint32_t dataSize);

int HcFileOpen(const char *path, int mode, FileHandle *file, mode_t permissionMode);
int HcFileSize(FileHandle file);
int HcFileRead(FileHandle file, void *dst, int dstSize);
int HcFileWrite(FileHandle file, const void *src, int srcSize);
void HcFileClose(FileHandle file);
bool HcIsFileExist(const char *path);

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // ALG_UTILS_H