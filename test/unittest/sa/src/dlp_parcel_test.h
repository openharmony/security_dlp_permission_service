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

#ifndef DLP_PARCEL_TEST_H
#define DLP_PARCEL_TEST_H

#include <gtest/gtest.h>
#include "auth_user_info_parcel.h"
#include "dlp_policy_parcel.h"
#include "dlp_sandbox_callback_info_parcel.h"
#include "open_dlp_file_callback_info_parcel.h"
#include "retention_sandbox_info.h"
#include "visited_dlp_file_info.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpParcelTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PARCEL_TEST_H
