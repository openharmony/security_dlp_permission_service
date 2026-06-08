/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "dlp_transparent_enc_manager_test.h"
#include <vector>
#include "gtest/gtest.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                      "DlpTransparentEncManagerTest"};
static constexpr int32_t DEFAULT_USER_ID = 100;
}  // namespace

void DlpTransparentEncManagerTest::SetUpTestCase()
{
    DLP_LOG_INFO(LABEL, "SetUpTestCase.");
}

void DlpTransparentEncManagerTest::TearDownTestCase()
{
    DLP_LOG_INFO(LABEL, "TearDownTestCase.");
}

void DlpTransparentEncManagerTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "SetUp ok.");
}

void DlpTransparentEncManagerTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown.");
}

/**
 * @tc.name: GetInstance001
 * @tc.desc: GetInstance test - singleton pattern verification.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpTransparentEncManagerTest, GetInstance001, TestSize.Level0)
{
    auto& instance1 = DlpTransparentEncManager::GetInstance();
    auto& instance2 = DlpTransparentEncManager::GetInstance();
    ASSERT_EQ(&instance1, &instance2);
}

/**
 * @tc.name: SetControlledAppLists001
 * @tc.desc: SetControlledAppLists with multiple apps, should fail due to dlopen.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists001, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    appLists.push_back("com.test.app2");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: SetControlledAppLists002
 * @tc.desc: SetControlledAppLists with userId=0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists002, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, 0, true);
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: SetControlledAppLists003
 * @tc.desc: SetControlledAppLists with userIdSet=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists003, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, 0, false);
    ASSERT_NE(ret, DLP_OK);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS