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

#include "hex_string.h"
#include <cstdio>
#include <cstring>
#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static char HexToChar(uint8_t hex)
{
    return (hex > 9) ? (hex + 0x37) : (hex + 0x30);  // numbers greater than 9 are represented by letters in hex.
}

int32_t ByteToHexString(const uint8_t *byte, uint32_t byteLen, char *hexStr, uint32_t hexLen)
{
    if (byte == nullptr || hexStr == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (byteLen > (UINT32_MAX / BYTE_TO_HEX_OPER_LENGTH)) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    /* The terminator('\0') needs 1 bit */
    if (hexLen < byteLen * BYTE_TO_HEX_OPER_LENGTH + 1) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    for (uint32_t i = 0; i < byteLen; i++) {
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH] = HexToChar((byte[i] & 0xF0) >> 4);  // 4: shift right for filling
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1] = HexToChar(byte[i] & 0x0F);     // get low four bits
    }
    hexStr[byteLen * BYTE_TO_HEX_OPER_LENGTH] = '\0';

    return DLP_OK;
}

static uint8_t CharToHex(char c)
{
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A' + 10);  // hex trans to dec with base 10
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a' + 10);  // hex trans to dec with base 10
    }
    if ((c >= '0') && (c <= '9')) {
        return (c - '0');
    }
    return 16;  // max hex must < 16
}

int32_t HexStringToByte(const char *hexStr, uint8_t *byte, uint32_t byteLen)
{
    if (byte == nullptr || hexStr == nullptr) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint32_t realHexLen = strlen(hexStr);
    /* even number or not */
    if (realHexLen % BYTE_TO_HEX_OPER_LENGTH != 0 || byteLen < realHexLen / BYTE_TO_HEX_OPER_LENGTH) {
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }

    for (uint32_t i = 0; i < realHexLen / BYTE_TO_HEX_OPER_LENGTH; i++) {
        uint8_t high = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH]);
        uint8_t low = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1]);
        if (high == 16 || low == 16) {  // max hex must < 16
            return DLP_SERVICE_ERROR_VALUE_INVALID;
        }
        byte[i] = high << 4;  // 4: Set the high nibble
        byte[i] |= low;       // Set the low nibble
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS