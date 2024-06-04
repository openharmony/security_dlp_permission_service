/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "hex_string_test.h"

#include <string>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "HexStringTest"};
}

void HexStringTest::SetUpTestCase() {}

void HexStringTest::TearDownTestCase() {}

void HexStringTest::SetUp() {}

void HexStringTest::TearDown() {}

/**
 * @tc.name: ByteToHexString001
 * @tc.desc: ByteToHexString test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HexStringTest, ByteToHexString001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ByteToHexString001");
    char hexStrBuffer[64] = {0};
    uint8_t byteBuffer[30] = {0x1, 0x9, 0xf};

    // byte is nullptr
    EXPECT_EQ(ByteToHexString(nullptr, 0, hexStrBuffer, sizeof(hexStrBuffer)), DLP_SERVICE_ERROR_VALUE_INVALID);

    // hexStr is nullptr
    EXPECT_EQ(ByteToHexString(byteBuffer, sizeof(byteBuffer), nullptr, 1), DLP_SERVICE_ERROR_VALUE_INVALID);

    // hexStrBuffer len too short
    EXPECT_EQ(ByteToHexString(byteBuffer, sizeof(byteBuffer), hexStrBuffer, 1), DLP_SERVICE_ERROR_VALUE_INVALID);

    // normal branch
    EXPECT_EQ(ByteToHexString(byteBuffer, sizeof(byteBuffer), hexStrBuffer, sizeof(hexStrBuffer)), DLP_OK);
}

/**
 * @tc.name: HexStringToByte001
 * @tc.desc: HexStringToByte test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HexStringTest, HexStringToByte001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ByteToHexString001");
    uint8_t byteBuffer[30] = {0};

    // hexStr is nullptr
    EXPECT_EQ(HexStringToByte(nullptr, 0, byteBuffer, sizeof(byteBuffer)), DLP_SERVICE_ERROR_VALUE_INVALID);
    std::string test = "1d2c4F";
    // byte is nullptr
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), nullptr, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "1d2c4F1";
    // hexStr is not 2 aligned
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), nullptr, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);

    // byte len is short
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), nullptr, 1), DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "1d2c4Fq";
    // not hex number
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), nullptr, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "1d2c4F";
    // normal branch
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), byteBuffer, sizeof(byteBuffer)), DLP_OK);
}

/**
 * @tc.name: HexStringToByte002
 * @tc.desc: HexStringToByte test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HexStringTest, HexStringToByte002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ByteToHexString001");
    uint8_t byteBuffer[30] = {0};
    // normal branch
    std::string test = "1d2c4";
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), byteBuffer, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "1d2c4f";
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), byteBuffer, 1), DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "gd2c4f";
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), byteBuffer, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);
    test = "1g2c4f";
    EXPECT_EQ(HexStringToByte(test.c_str(), test.length(), byteBuffer, sizeof(byteBuffer)),
        DLP_SERVICE_ERROR_VALUE_INVALID);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS