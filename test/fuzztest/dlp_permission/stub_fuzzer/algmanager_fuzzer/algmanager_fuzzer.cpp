/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "algmanager_fuzzer.h"


#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include "account_adapt.h"
#include "cert_parcel.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_async_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_parcel.h"
#include "dlp_credential.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "accesstoken_kit.h"
#include "idlp_permission_service.h"
#include "securec.h"
#include "token_setproc.h"
#include "alg_utils.cpp"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using unordered_json = nlohmann::ordered_json;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
static const uint32_t PARCEL_NORMAL_SIZE = 16;
static const uint32_t PARCEL_LARGE_SIZE = 32;
static const uint32_t PARCEL_NORMAL_DATA_SIZE = sizeof(int64_t) + 1;
static const uint32_t PARCEL_NORMAL_ALLOC_UNIT = 0;
static const uint32_t PARCEL_NORMAL_BEGIN = 0;
static const uint32_t PARCEL_NORMAL_END = 12;
static const uint32_t PARCEL_OVERSIZE_DATA_SIZE = 16;
static const uint32_t PARCEL_LARGE_BEGIN = 10;
static const uint32_t PARCEL_SMALL_END = 1;
static const uint32_t PARCEL_MAX_BEGIN = PARCEL_UINT_MAX - PARCEL_NORMAL_DATA_SIZE + 1;
} // namespace

namespace OHOS {

void MemoryFuzzTest(const uint8_t* data, size_t size)
{
    (void)HcMalloc(0, '0');
    uint8_t *data1 = static_cast<uint8_t *>(HcMalloc(size, 0));
    if (data1 == nullptr) {
        return;
    }
    HcFree(data1);
    (void)ClibMalloc(0, '0');
    uint8_t *data2 = static_cast<uint8_t *>(ClibMalloc(size, 0));
    if (data2 == nullptr) {
        return;
    }
    HcFree(data2);
    char *newdata = static_cast<char *>(HcMalloc(size + 1, 0));
    int ret2 = memcpy_s(newdata, size, data, size);
    if (ret2 == -1) {
        HcFree(newdata);
        return;
    }
    uint32_t len = HcStrlen(newdata);
    HcFree(newdata);
    if (len != size) {
        return;
    }
    (void)HcStrlen(nullptr);
    return;
}

void BlobFuzzTest(const uint8_t* data, size_t size)
{
    BlobData *blob = nullptr;
    bool ret = IsBlobDataValid(blob);
    BlobData blob2 = {size, nullptr};
    ret = IsBlobDataValid(&blob2);
    FreeBlobData(&blob2);
    BlobData blob3 = {0, nullptr};
    FreeBlobData(&blob3);
    FreeBlobData(nullptr);
    unsigned char *newdata = static_cast<unsigned char *>(HcMalloc(size, 0));
    int ret2 = memcpy_s(newdata, size, data, size);
    if (ret2 == -1) {
        HcFree(newdata);
        return;
    }
    BlobData blob4 = {size, newdata};
    ret = IsBlobDataValid(&blob4);
    FreeBlobData(&blob4);
    uint8_t value = 0;
    uint8_t* valuePtr = &value;
    BlobData blob5 = {0, valuePtr};
    ret = IsBlobDataValid(&blob5);
}

void DeleteParcelTest1()
{
    HcBool ret = HC_TRUE;
    HcParcel testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            ret = HC_FALSE;
            break;
        }
        testData.beginPos = PARCEL_MAX_BEGIN;
        testData.endPos = PARCEL_UINT_MAX;
        uint32_t dataSize = PARCEL_NORMAL_DATA_SIZE;
        char dst = 0;
        ret = ParcelRead(&testData, &dst, dataSize);
    } while (0);
    DeleteParcel(&testData);
}

void DeleteParcelTest2()
{
    HcBool ret = HC_TRUE;
    HcParcel testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            ret = HC_FALSE;
            break;
        }
        testData.beginPos = PARCEL_NORMAL_BEGIN;
        testData.endPos = PARCEL_NORMAL_END;
        uint32_t dataSize = PARCEL_OVERSIZE_DATA_SIZE;
        char dst = 0;
        ret = ParcelRead(&testData, &dst, dataSize);
    } while (0);
    DeleteParcel(&testData);
}

void ParcelFileFuzzTest()
{
    HcParcel testData;
    testData.data = nullptr;
    testData.length = 1;
    (void)ParcelIncrease(&testData, 0);

    ParcelRecycle(nullptr);

    testData = CreateParcel(PARCEL_LARGE_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    testData.beginPos = PARCEL_SMALL_END;
    testData.endPos = PARCEL_LARGE_BEGIN;
    ParcelRecycle(&testData);
    DeleteParcel(&testData);

    (void)GetParcelIncreaseSize(nullptr, 0);

    (void)CreateDirectory("");

    (void)HcFileOpenWrite("", 0);

    FileHandle file;
    file.pfd = nullptr;
    HcFileClose(file);
}

void ParcelFuzzTest(const uint8_t* data, size_t size)
{
    uint32_t ret = 0;
    HcParcel testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            break;
        }
        testData.beginPos = PARCEL_LARGE_BEGIN;
        testData.endPos = PARCEL_SMALL_END;
        ret = GetParcelDataSize(&testData);
    } while (0);
    DeleteParcel(&testData);

    testData = CreateParcel(0, 0);
    ret = GetParcelDataSize(nullptr);
    ret = ParcelRead(nullptr, nullptr, 0);
    ret = ParcelRead(&testData, nullptr, 0);
    ret = ParcelRead(&testData, &testData, 0);
    ret = ParcelWrite(nullptr, nullptr, 0);
    ret = ParcelWrite(&testData, nullptr, 0);
    ret = ParcelWrite(&testData, data, size);
    DeleteParcel(&testData);

    testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            break;
        }
        testData.beginPos = PARCEL_SMALL_END;
        testData.endPos = PARCEL_LARGE_BEGIN;
        ret = GetParcelDataSize(&testData);
    } while (0);
    uint8_t* mData = nullptr;
    ret = ParcelWrite(&testData, mData, size);
    if (ret == HC_TRUE) {
        free(mData);
    }
    DeleteParcel(&testData);
    DeleteParcel(nullptr);

    (void)GetParcelData(nullptr);
    (void)GetParcelData(&testData);
    DeleteParcelTest1();
    DeleteParcelTest2();

    testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    (void)ParcelRealloc(&testData, 0);
    (void)ParcelIncrease(&testData, 0);
    DeleteParcel(&testData);

    (void)ParcelIncrease(nullptr, 0);

    ParcelFileFuzzTest();
}

void FileFuzzTest(const uint8_t* data, size_t size)
{
    int ret = HcFileOpen(nullptr, 0, nullptr, 0);
    ret = HcFileOpen("", 0, nullptr, 0);
    char *newdata = static_cast<char *>(HcMalloc(size, 0));
    ret = memcpy_s(newdata, size, data, size);
    if (ret == -1) {
        return;
    }
    ret = HcFileOpen(newdata, 0, nullptr, 0);
    HcFree(newdata);
    FileHandle file;
    ret = HcFileOpen("", 0, &file, 0);
    ret = HcFileSize(file);
    ret = HcFileRead(file, nullptr, -1);
    ret = HcFileWrite(file, nullptr, -1);
    int fd;
    file.pfd = static_cast<void *>(&fd);
    ret = HcFileRead(file, nullptr, -1);
    ret = HcFileRead(file, nullptr, 0);
    ret = HcFileWrite(file, nullptr, -1);
    ret = HcFileWrite(file, nullptr, 0);
    ret = HcIsFileExist(nullptr);
}

bool AlgManagerFuzzTest(const uint8_t* data, size_t size)
{
    MemoryFuzzTest(data, size);
    BlobFuzzTest(data, size);
    ParcelFuzzTest(data, size);
    FileFuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::AlgManagerFuzzTest(data, size);
    return 0;
}
