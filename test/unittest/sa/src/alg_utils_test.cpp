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

#include "alg_utils_test.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "alg_utils.cpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AlgUtilsTest" };
static const uint32_t HC_OVERSIZE_MALLOC_SIZE = MAX_MALLOC_SIZE + 1;
static const uint32_t CLIB_OVERSIZE_MALLOC_SIZE = CLIB_MAX_MALLOC_SIZE + 1;
static const uint32_t PARCEL_ZERO_DATA_SIZE = 0;
static const uint32_t PARCEL_NORMAL_SIZE = 16;
static const uint32_t PARCEL_NORMAL_ALLOC_UNIT = 0;
static const uint32_t PARCEL_LARGE_BEGIN = 10;
static const uint32_t PARCEL_SMALL_END = 1;
static const uint32_t PARCEL_NORMAL_BEGIN = 0;
static const uint32_t PARCEL_NORMAL_END = 12;
static const uint32_t PARCEL_NORMAL_DATA_SIZE = sizeof(int64_t) + 1;
static const uint32_t PARCEL_MAX_BEGIN = PARCEL_UINT_MAX - PARCEL_NORMAL_DATA_SIZE + 1;
static const uint32_t PARCEL_OVERSIZE_DATA_SIZE = 16;
static const uint32_t PARCEL_WRITE_SIZE = 7;
static const char *const PARCEL_WRITE_STR = "PARCEL";
static const uint32_t PARCEL_LARGE_ALLOC_UNIT = 7;
}

void AlgUtilsTest::SetUpTestCase() {}

void AlgUtilsTest::TearDownTestCase() {}

void AlgUtilsTest::SetUp() {}

void AlgUtilsTest::TearDown() {}

/**
 * @tc.name: HcMalloc001
 * @tc.desc: HcMalloc001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, HcMalloc001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "HcMalloc001");

    uint32_t size = 0;
    char val = '0';
    void *ret = HcMalloc(size, val);
    EXPECT_EQ(ret, nullptr);
    HcFree(nullptr);
}

/**
 * @tc.name: HcMalloc002
 * @tc.desc: HcMalloc002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, HcMalloc002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "HcMalloc002");

    uint32_t size = HC_OVERSIZE_MALLOC_SIZE;
    char val = '0';
    void *ret = HcMalloc(size, val);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: HcStrlen001
 * @tc.desc: HcStrlen001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, HcStrlen001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "HcStrlen001");

    const char *str = nullptr;
    int ret = HcStrlen(str);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ClibMalloc001
 * @tc.desc: ClibMalloc001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ClibMalloc001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ClibMalloc001");

    uint32_t size = 0;
    char val = '0';
    void *ret = ClibMalloc(size, val);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: ClibMalloc002
 * @tc.desc: ClibMalloc002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ClibMalloc002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ClibMalloc002");

    uint32_t size = CLIB_OVERSIZE_MALLOC_SIZE;
    char val = '0';
    void *ret = ClibMalloc(size, val);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: IsBlobDataValid001
 * @tc.desc: IsBlobDataValid001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, IsBlobDataValid001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "IsBlobDataValid001");

    bool ret = IsBlobDataValid(nullptr);
    EXPECT_EQ(ret, false);
    FreeBlobData(nullptr);
}

/**
 * @tc.name: IsBlobDataValid002
 * @tc.desc: IsBlobDataValid002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, IsBlobDataValid002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "IsBlobDataValid002");

    const uint32_t dataSize = 10;
    BlobData blob = { dataSize, nullptr };
    bool ret = IsBlobDataValid(&blob);
    EXPECT_EQ(ret, false);
    FreeBlobData(&blob);
}

/**
 * @tc.name: IsBlobDataValid003
 * @tc.desc: IsBlobDataValid003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, IsBlobDataValid003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "IsBlobDataValid003");

    const uint32_t dataSize = 10;
    BlobData blob = { 0, static_cast<uint8_t *>(HcMalloc(dataSize, 0)) };
    bool ret = IsBlobDataValid(&blob);
    EXPECT_EQ(ret, false);
    FreeBlobData(&blob);
}

/**
 * @tc.name: IsBlobDataValid004
 * @tc.desc: IsBlobDataValid004 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, IsBlobDataValid004, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "IsBlobDataValid004");

    const uint32_t dataSize = 10;
    BlobData blob = { dataSize, static_cast<uint8_t *>(HcMalloc(dataSize, 0)) };
    bool ret = IsBlobDataValid(&blob);
    EXPECT_EQ(ret, true);
    FreeBlobData(&blob);
}

/**
 * @tc.name: CreateParcel001
 * @tc.desc: CreateParcel001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, CreateParcel001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "CreateParcel001");

    HcParcel testData = CreateParcel(PARCEL_ZERO_DATA_SIZE, PARCEL_ZERO_DATA_SIZE);
    DeleteParcel(&testData);
    EXPECT_EQ(testData.data, nullptr);
    DeleteParcel(nullptr);
}

/**
 * @tc.name: GetParcelDataSize001
 * @tc.desc: GetParcelDataSize001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, GetParcelDataSize001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "GetParcelDataSize001");

    uint32_t ret = GetParcelDataSize(nullptr);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetParcelDataSize002
 * @tc.desc: GetParcelDataSize002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, GetParcelDataSize002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "GetParcelDataSize002");

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
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: GetParcelData001
 * @tc.desc: GetParcelData001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, GetParcelData001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "GetParcelData001");

    const char *ret = GetParcelData(nullptr);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: ParcelRead001
 * @tc.desc: ParcelRead001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelRead001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelRead001");

    HcParcel *testData = nullptr;
    void *dst = nullptr;
    uint32_t dataSize = PARCEL_ZERO_DATA_SIZE;
    HcBool ret = ParcelRead(testData, dst, dataSize);
    EXPECT_EQ(ret, HC_FALSE);
}

/**
 * @tc.name: ParcelRead002
 * @tc.desc: ParcelRead002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelRead002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelRead002");

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
    EXPECT_EQ(ret, HC_FALSE);
}

/**
 * @tc.name: ParcelRead003
 * @tc.desc: ParcelRead003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelRead003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelRead003");

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
    EXPECT_EQ(ret, HC_FALSE);
}

/**
 * @tc.name: ParcelTest
 * @tc.desc: ParcelTest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelTest, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelTest");

    EXPECT_EQ(ParcelRead(nullptr, nullptr, 0), HC_FALSE);
    HcParcel parcel;
    EXPECT_EQ(ParcelRead(&parcel, nullptr, 0), HC_FALSE);
    EXPECT_EQ(ParcelRead(&parcel, &parcel, 0), HC_FALSE);

    EXPECT_EQ(ParcelWrite(nullptr, nullptr, 0), HC_FALSE);
    EXPECT_EQ(ParcelWrite(&parcel, nullptr, 0), HC_FALSE);
    EXPECT_EQ(ParcelWrite(&parcel, &parcel, 0), HC_FALSE);
}

/**
 * @tc.name: ParcelWrite001
 * @tc.desc: ParcelWrite001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelWrite001, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelWrite001");

    HcParcel *testData = nullptr;
    void *src = nullptr;
    uint32_t dataSize = PARCEL_ZERO_DATA_SIZE;
    HcBool ret = ParcelWrite(testData, src, dataSize);
    EXPECT_EQ(ret, HC_FALSE);
}

/**
 * @tc.name: ParcelWrite002
 * @tc.desc: ParcelWrite002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelWrite002, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelWrite002");

    HcBool ret = HC_TRUE;
    HcParcel testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            ret = HC_FALSE;
            break;
        }
        testData.beginPos = PARCEL_NORMAL_BEGIN;
        testData.endPos = PARCEL_UINT_MAX;
        uint32_t dataSize = PARCEL_WRITE_SIZE;
        ret = ParcelWrite(&testData, PARCEL_WRITE_STR, dataSize);
    } while (0);
    DeleteParcel(&testData);
    EXPECT_EQ(ret, HC_FALSE);
}

/**
 * @tc.name: ParcelWrite003
 * @tc.desc: ParcelWrite003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, ParcelWrite003, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "ParcelWrite003");

    HcBool ret = HC_FALSE;
    HcParcel testData = CreateParcel(PARCEL_NORMAL_SIZE, PARCEL_NORMAL_ALLOC_UNIT);
    do {
        if (testData.data == nullptr) {
            ret = HC_TRUE;
            break;
        }
        testData.beginPos = PARCEL_NORMAL_BEGIN;
        testData.endPos = PARCEL_NORMAL_SIZE;
        uint32_t dataSize = PARCEL_WRITE_SIZE;
        ret = ParcelWrite(&testData, PARCEL_WRITE_STR, dataSize);
    } while (0);
    DeleteParcel(&testData);
    EXPECT_EQ(ret, HC_TRUE);
}

/**
 * @tc.name: HcFileTest
 * @tc.desc: HcFileTest test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, HcFileTest, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "HcFileTest");

    EXPECT_EQ(HcFileOpen(nullptr, 0, nullptr, 0), -1);
    EXPECT_EQ(HcFileOpen("", 0, nullptr, 0), -1);

    FileHandle file;
    EXPECT_EQ(HcFileOpen("", 0, &file, 0), -1);
    EXPECT_EQ(HcFileSize(file), -1);
    EXPECT_EQ(HcFileRead(file, nullptr, -1), -1);
    EXPECT_EQ(HcFileWrite(file, nullptr, -1), -1);

    int fd;
    file.pfd = (void *)(&fd);
    EXPECT_EQ(HcFileRead(file, nullptr, -1), -1);
    EXPECT_EQ(HcFileRead(file, nullptr, 0), -1);
    EXPECT_EQ(HcFileWrite(file, nullptr, -1), -1);
    EXPECT_EQ(HcFileWrite(file, nullptr, 0), -1);

    EXPECT_EQ(HcIsFileExist(nullptr), false);
}

/**
 * @tc.name: HcFileSubTest
 * @tc.desc: HcFileSub test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AlgUtilsTest, HcFileSubTest, TestSize.Level3)
{
    DLP_LOG_INFO(LABEL_TEST, "HcFileSubTest");
    HcParcel testData;
    testData.length = 0;
    EXPECT_EQ(ParcelRealloc(&testData, testData.length), HC_FALSE);

    EXPECT_EQ(ParcelIncrease(nullptr, 0), HC_FALSE);

    testData.data = nullptr;
    testData.length = 1;
    EXPECT_EQ(ParcelIncrease(&testData, 0), HC_FALSE);

    ParcelRecycle(nullptr);

    char charData;
    testData.data = &charData;
    testData.beginPos = 0;
    testData.allocUnit = 0;
    testData.beginPos = 0;
    ParcelRecycle(&testData);
    EXPECT_EQ(testData.endPos, 0);

    GetParcelIncreaseSize(nullptr, 0);

    testData.allocUnit = PARCEL_LARGE_ALLOC_UNIT;
    EXPECT_EQ(GetParcelIncreaseSize(&testData, PARCEL_LARGE_ALLOC_UNIT), PARCEL_LARGE_ALLOC_UNIT);
}
