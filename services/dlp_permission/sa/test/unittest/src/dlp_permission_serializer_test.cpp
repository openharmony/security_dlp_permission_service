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

#include "dlp_permission_serializer_test.h"
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
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionSerializerTest"};
}

void DlpPermissionSerializerTest::SetUpTestCase() {}

void DlpPermissionSerializerTest::TearDownTestCase() {}

void DlpPermissionSerializerTest::SetUp() {}

void DlpPermissionSerializerTest::TearDown() {}

/**
 * @tc.name: SerializeDlpPermission001
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission001");
 
    std::vector<AuthUserInfo> authUsers;
    AuthUserInfo info;
    info.authPerm = CONTENT_EDIT;
    authUsers.push_back(info);
    AuthUserInfo info1;
    info1.authPerm = FULL_CONTROL;
    authUsers.push_back(info1);
    AuthUserInfo info2;
    info2.authPerm = NO_PERMISSION;
    authUsers.push_back(info2);

    PermissionPolicy policy;
    policy.authUsers_ = authUsers;
    unordered_json permInfoJson;

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}