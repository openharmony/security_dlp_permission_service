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

#ifndef DLP_PERMISSION_SERIALIZER_TEST_H
#define DLP_PERMISSION_SERIALIZER_TEST_H

#include <gtest/gtest.h>
#include "dlp_permission_serializer.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

#define ONLINE_POLICY_CONTENT "plaintextPolicy"
#define POLICY_INDEX "policy"
#define FILE_INDEX "file"
constexpr int32_t IVKEY_LEN = 16;
constexpr int32_t AESKEY_LEN = 32;
constexpr int32_t IVKEY_STR_LEN = 36;
constexpr int32_t AESKEY_STR_LEN = 72;

class DlpPermissionSerializerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_PERMISSION_SERIALIZER_TEST_H
