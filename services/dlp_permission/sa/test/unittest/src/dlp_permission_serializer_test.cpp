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

/**
 * @tc.name: SerializeDlpPermission002
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission002");
    char aeskey[AESKEY_STR_LEN] = "1234567890123456789012345678901234567890123456789012345678901234";

    PermissionPolicy policy;
    policy.SetAeskey(reinterpret_cast<uint8_t*>(aeskey), AESKEY_LEN);
    unordered_json permInfoJson;

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: SerializeDlpPermission003
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission003");
    char aeskey[AESKEY_STR_LEN] = "1234567890123456789012345678901234567890123456789012345678901234";
    char ivkey[IVKEY_STR_LEN] = "12345678901234567890123456789012";

    PermissionPolicy policy1;
    policy1.supportEveryone_ = true;
    policy1.everyonePerm_ = CONTENT_EDIT;
    policy1.SetAeskey(reinterpret_cast<uint8_t*>(aeskey), AESKEY_LEN);
    policy1.SetIv(reinterpret_cast<uint8_t*>(ivkey), IVKEY_LEN);

    PermissionPolicy policy2;
    policy2.supportEveryone_ = true;
    policy2.everyonePerm_ = FULL_CONTROL;
    policy2.SetAeskey(reinterpret_cast<uint8_t*>(aeskey), AESKEY_LEN);
    policy2.SetIv(reinterpret_cast<uint8_t*>(ivkey), IVKEY_LEN);

    PermissionPolicy policy3;
    policy3.supportEveryone_ = true;
    policy3.everyonePerm_ = NO_PERMISSION;
    policy3.SetAeskey(reinterpret_cast<uint8_t*>(aeskey), AESKEY_LEN);
    policy3.SetIv(reinterpret_cast<uint8_t*>(ivkey), IVKEY_LEN);

    unordered_json permInfoJson;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy1, permInfoJson);
    ASSERT_EQ(DLP_OK, ret);

    ret = serialize.SerializeDlpPermission(policy2, permInfoJson);
    ASSERT_EQ(DLP_OK, ret);

    ret = serialize.SerializeDlpPermission(policy3, permInfoJson);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DeserializeDlpPermission001
 * @tc.desc: DeserializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeDlpPermission001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeDlpPermission001");
 
    unordered_json permJson;
    PermissionPolicy policy;
    permJson["plaintextPolicy"] = "7b7d";

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeDlpPermission(permJson, policy);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DeserializeDlpPermission002
 * @tc.desc: DeserializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeDlpPermission002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeDlpPermission002");
 
    unordered_json permJson;
    PermissionPolicy policy;
    permJson["file"] = {{"filekey", "ttttt"}, {"filekeyLen", AESKEY_LEN}};

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeDlpPermission(permJson, policy);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DeserializeDlpPermission003
 * @tc.desc: DeserializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeDlpPermission003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeDlpPermission003");
 
    unordered_json permJson;
    PermissionPolicy policy;
    permJson["file"] = {{"iv", "ttttt"}, {"ivLen", AESKEY_LEN}};

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeDlpPermission(permJson, policy);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DeserializeDlpPermission004
 * @tc.desc: DeserializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeDlpPermission004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeDlpPermission004");
 
    unordered_json permJson1;
    permJson1["policy"] = {{"account", {"right", {"edit", true}}}};

    unordered_json permJson2;
    permJson1["policy"] = {{"account", {"right", {"fullCtrl", true}}}};

    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeDlpPermission(permJson1, policy);
    ASSERT_EQ(DLP_OK, ret);

    ret = serialize.DeserializeDlpPermission(permJson2, policy);
    ASSERT_EQ(DLP_OK, ret);
}