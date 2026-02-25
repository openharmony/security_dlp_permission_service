/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dlp_permission_serializer_sub_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_os_account_sub_mock.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "permission_manager_adapter.cpp"
#include "bundle_manager_adapter.h"
#include "bundle_mgr_client.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#define  private public
#include "dlp_permission_serializer.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::DlpPermissionUnitTest;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL_TEST = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionSerializerSubTest"};
static const int32_t ERROR_USERID1 = 777;
}

void DlpPermissionSerializerSubTest::SetUpTestCase() {}

void DlpPermissionSerializerSubTest::TearDownTestCase() {}

void DlpPermissionSerializerSubTest::SetUp() {}

void DlpPermissionSerializerSubTest::TearDown() {}

/**
 * @tc.name: GetOsAccountId001
 * @tc.desc: GetOsAccountId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, GetOsAccountId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "GetOsAccountId001");

    int32_t osAccountId = ERROR_USERID1;
    int32_t ret = GetOsAccountId(osAccountId);
    ASSERT_NE(ret, OHOS::ERR_OK);
}

/**
 * @tc.name: GetBundleMgrsa001
 * @tc.desc: GetBundleMgrsa test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, GetBundleMgrsa001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "GetBundleMgrsa001");

    auto ret = GetBundleMgrsa();
    ASSERT_NE(ret, nullptr);
}

/**
 * @tc.name: GetAppIdentifier001
 * @tc.desc: GetAppIdentifier test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, GetAppIdentifier001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "GetAppIdentifier001");

    std::string bundleName = "";
    std::string appIdentifier = "";
    int32_t userId = 0;
    auto ret = GetAppIdentifier(bundleName, appIdentifier, userId);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: GetAppIdentifierForCalling001
 * @tc.desc: GetAppIdentifierForCalling test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, GetAppIdentifierForCalling001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "GetAppIdentifierForCalling001");

    std::string appIdentifier = "";
    auto ret = PermissionManagerAdapter::GetAppIdentifierForCalling(appIdentifier);
    ASSERT_NE(ret, true);
}

/**
 * @tc.name: CheckPermissionForConnect001
 * @tc.desc: CheckPermissionForConnect test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, CheckPermissionForConnect001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "CheckPermissionForConnect001");

    uint32_t callerTokenId = 0;
    auto ret = CheckPermissionForConnect(callerTokenId);
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: CheckPermissionAndGetAppId001
 * @tc.desc: CheckPermissionAndGetAppId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, CheckPermissionAndGetAppId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "CheckPermissionAndGetAppId001");

    std::string permission = "";
    auto ret = PermissionManagerAdapter::CheckPermissionAndGetAppId(permission);
    ASSERT_NE(ret, true);
}

/**
 * @tc.name: CheckSandboxFlagWithService001
 * @tc.desc: CheckSandboxFlagWithService test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerSubTest, CheckSandboxFlagWithService001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL_TEST, "CheckSandboxFlagWithService001");

    bool sandboxFlag;
    (void)PermissionManagerAdapter::CheckSandboxFlagWithService(0, sandboxFlag);
    ASSERT_NE(sandboxFlag, true);
}
