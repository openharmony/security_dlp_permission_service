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

#include "dlp_permission_load_callback_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionLoadCallbackTest"};
constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
}

void DlpPermissionLoadCallbackTest::SetUpTestCase() {}

void DlpPermissionLoadCallbackTest::TearDownTestCase() {}

void DlpPermissionLoadCallbackTest::SetUp() {}

void DlpPermissionLoadCallbackTest::TearDown() {}

/**
 * @tc.name: OnLoadSystemAbilityFail001
 * @tc.desc: OnLoadSystemAbilityFail test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionLoadCallbackTest, OnLoadSystemAbilityFail001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnLoadSystemAbilityFail001");

    DlpPermissionLoadCallback callback_;
    int32_t systemAbilityId = 0;

    callback_.OnLoadSystemAbilityFail(systemAbilityId);
    ASSERT_NE(SA_ID_DLP_PERMISSION_SERVICE, systemAbilityId);

    systemAbilityId = SA_ID_DLP_PERMISSION_SERVICE;
    ASSERT_EQ(SA_ID_DLP_PERMISSION_SERVICE, systemAbilityId);
}

/**
 * @tc.name: OnLoadSystemAbilitySuccess001
 * @tc.desc: OnLoadSystemAbilitySuccess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionLoadCallbackTest, OnLoadSystemAbilitySuccess001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnLoadSystemAbilitySuccess001");

    DlpPermissionLoadCallback callback_;
    int32_t systemAbilityId = 0;
    sptr<IRemoteObject> remoteObject = nullptr;

    callback_.OnLoadSystemAbilitySuccess(systemAbilityId, remoteObject);
    ASSERT_NE(SA_ID_DLP_PERMISSION_SERVICE, systemAbilityId);

    systemAbilityId = SA_ID_DLP_PERMISSION_SERVICE;
    ASSERT_EQ(nullptr, remoteObject);
}

