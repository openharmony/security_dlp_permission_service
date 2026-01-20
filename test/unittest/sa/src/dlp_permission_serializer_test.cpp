/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "dlp_os_account_mock.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "permission_manager_adapter.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionSerializerTest"};
static const int32_t DEFAULT_USERID = 100;
}

void DlpPermissionSerializerTest::SetUpTestCase() {}

void DlpPermissionSerializerTest::TearDownTestCase() {}

void DlpPermissionSerializerTest::SetUp() {}

void DlpPermissionSerializerTest::TearDown() {}

static sptr<AppExecFwk::IBundleMgr> GetBundleMgr(void)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        return nullptr;
    }

    sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        return nullptr;
    }

    return iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
}

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
    info.authPerm = DLPFileAccess::CONTENT_EDIT;
    authUsers.push_back(info);
    AuthUserInfo info1;
    info1.authPerm = DLPFileAccess::FULL_CONTROL;
    authUsers.push_back(info1);
    AuthUserInfo info2;
    info2.authPerm = DLPFileAccess::NO_PERMISSION;
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
    char aesKey[AESKEY_STR_LEN] = "1234567890123456789012345678901234567890123456789012345678901234";
    char ivKey[IVKEY_STR_LEN] = "12345678901234567890123456789012";
    char hmacKey[HMACKEY_STR_LEN] = "1234567890123456789012345678901234567890123456789012345678901234";

    PermissionPolicy policy1;
    policy1.supportEveryone_ = true;
    policy1.everyonePerm_ = DLPFileAccess::CONTENT_EDIT;
    policy1.SetAeskey(reinterpret_cast<uint8_t*>(aesKey), AESKEY_LEN);
    policy1.SetIv(reinterpret_cast<uint8_t*>(ivKey), IVKEY_LEN);
    policy1.SetHmacKey(reinterpret_cast<uint8_t*>(hmacKey), HMACKEY_LEN);

    PermissionPolicy policy2;
    policy2.supportEveryone_ = true;
    policy2.everyonePerm_ = DLPFileAccess::FULL_CONTROL;
    policy2.SetAeskey(reinterpret_cast<uint8_t*>(aesKey), AESKEY_LEN);
    policy2.SetIv(reinterpret_cast<uint8_t*>(ivKey), IVKEY_LEN);
    policy2.SetHmacKey(reinterpret_cast<uint8_t*>(hmacKey), HMACKEY_LEN);

    PermissionPolicy policy3;
    policy3.supportEveryone_ = true;
    policy3.everyonePerm_ = DLPFileAccess::NO_PERMISSION;
    policy3.SetAeskey(reinterpret_cast<uint8_t*>(aesKey), AESKEY_LEN);
    policy3.SetIv(reinterpret_cast<uint8_t*>(ivKey), IVKEY_LEN);
    policy3.SetHmacKey(reinterpret_cast<uint8_t*>(hmacKey), HMACKEY_LEN);

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
 * @tc.name: SerializeDlpPermission004
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission004");
    PermissionPolicy policy;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::DOMAIN_ACCOUNT;
    unordered_json permInfoJson;

    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: SerializeDlpPermission005
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission005");
    PermissionPolicy policy;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::DOMAIN_ACCOUNT;
    unordered_json permInfoJson;
    std::string paramJson = R"({"parameters":{"adConfig":{"adDomain":"test"}}})";
    SetAccountServerConfigParameters(paramJson);
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, ret);

    paramJson = R"({"adConfig":{"adDomain":"test"},"type":"AD"})";
    SetAccountServerConfigParameters(paramJson);
    ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, ret);

    paramJson = R"({[]})";
    SetAccountServerConfigParameters(paramJson);
    ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_JSON_OPERATE_FAIL, ret);
}

/**
 * @tc.name: SerializeDlpPermission006
 * @tc.desc: SerializeDlpPermission test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, SerializeDlpPermission006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeDlpPermission006");
    PermissionPolicy policy;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    policy.waterMarkConfig_ = true;
    policy.countdown_ = 100;
    unordered_json permInfoJson;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.SerializeDlpPermission(policy, permInfoJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
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
    permJson["plaintextPolicy"] = "7b2266696c65223a7b226976223a223132222c2269764c656e223a31367d7d";

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
    permJson2["policy"] = {{"account", {"right", {"fullCtrl", true}}}};

    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeDlpPermission(permJson1, policy);
    ASSERT_EQ(DLP_OK, ret);

    ret = serialize.DeserializeDlpPermission(permJson2, policy);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DeserializeEncPolicyData001
 * @tc.desc: DeserializeEncPolicyData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeEncPolicyData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeEncPolicyData001");

    unordered_json permJson1;
    DLP_EncPolicyData encData;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeEncPolicyData(permJson1, encData, true);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: DeserializeEncPolicyData002
 * @tc.desc: DeserializeEncPolicyData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeEncPolicyData002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeEncPolicyData002");

    unordered_json permJson1;
    permJson1["encData"] = "X";
    permJson1["encDataLen"] = 11;
    DLP_EncPolicyData encData;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeEncPolicyData(permJson1, encData, false);
    ASSERT_NE(DLP_OK, ret);
}

/**
 * @tc.name: DeserializeEveryoneInfo001
 * @tc.desc: DeserializeEveryoneInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeEveryoneInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeEveryoneInfo001");

    unordered_json permJson1;
    unordered_json rightInfoJson;
    unordered_json everyoneJson;
    rightInfoJson["read"] = true;
    everyoneJson["right1"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    bool ret = serialize.DeserializeEveryoneInfo(permJson1, policy);
    ASSERT_EQ(false, ret);
    everyoneJson["right"] = 1;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeEveryoneInfo(permJson1, policy);
    ASSERT_EQ(false, ret);
    rightInfoJson["edit"] = "true";
    rightInfoJson["fullCtrl"] = "true";
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeEveryoneInfo(permJson1, policy);
    ASSERT_EQ(true, ret);
    rightInfoJson["edit"] = true;
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeEveryoneInfo(permJson1, policy);
    ASSERT_EQ(true, ret);
    rightInfoJson["fullCtrl"] = true;
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeEveryoneInfo(permJson1, policy);
    ASSERT_EQ(true, ret);
}

/**
 * @tc.name: DeserializeProperty001
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty001");

    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["waterMarkConfig"] = true;
    permJson1["everyone"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.waterMarkConfig_, true);
}

/**
 * @tc.name: DeserializeProperty002
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty002");
    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["waterMarkConfig"] = false;
    permJson1["everyone"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.waterMarkConfig_, false);
}

/**
 * @tc.name: DeserializeProperty003
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty003");
    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["waterMarkConfig111"] = false;
    permJson1["everyone"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.waterMarkConfig_, false);
}

/**
 * @tc.name: DeserializeProperty004
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty004");
    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["waterMarkConfig111"] = false;
    permJson1["everyone111"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.waterMarkConfig_, false);
}

/**
 * @tc.name: DeserializeProperty005
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty005");
    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["waterMarkConfig111"] = false;
    permJson1["everyone111"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::INVALID_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.waterMarkConfig_, false);
}

/**
 * @tc.name: DeserializeProperty006
 * @tc.desc: DeserializeProperty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeProperty006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeProperty006");
    unordered_json permJson1;
    unordered_json everyoneJson;
    everyoneJson["countdown"] = false;
    permJson1["everyone"] = everyoneJson;
    PermissionPolicy policy;
    DlpPermissionSerializer serialize;
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::CLOUD_ACCOUNT;
    serialize.DeserializeProperty(permJson1, policy);
    ASSERT_EQ(policy.countdown_, false);
}

/**
 * @tc.name: DeserializeAuthUserInfo001
 * @tc.desc: DeserializeAuthUserInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, DeserializeAuthUserInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeAuthUserInfo001");

    unordered_json permJson1;
    unordered_json rightInfoJson;
    unordered_json everyoneJson;
    rightInfoJson["read"] = true;
    everyoneJson["right1"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    AuthUserInfo userInfo;
    DlpPermissionSerializer serialize;
    int32_t ret = serialize.DeserializeAuthUserInfo(permJson1, userInfo);
    ASSERT_EQ(DLP_OK, ret);
    everyoneJson["right"] = 1;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeAuthUserInfo(permJson1, userInfo);
    ASSERT_EQ(DLP_OK, ret);
    rightInfoJson["edit"] = "true";
    rightInfoJson["fullCtrl"] = "true";
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeAuthUserInfo(permJson1, userInfo);
    ASSERT_EQ(DLP_OK, ret);
    rightInfoJson["edit"] = true;
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeAuthUserInfo(permJson1, userInfo);
    ASSERT_EQ(DLP_OK, ret);
    rightInfoJson["fullCtrl"] = true;
    everyoneJson["right"] = rightInfoJson;
    permJson1["everyone"] = everyoneJson;
    ret = serialize.DeserializeAuthUserInfo(permJson1, userInfo);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: CheckAuthPolicy001
 * @tc.desc: CheckAuthPolicy001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionSerializerTest, CheckAuthPolicy001, TestSize.Level1)
{
    int32_t ret = PermissionManagerAdapter::CheckAuthPolicy("test_appId", "test_type", 0);
    ASSERT_NE(DLP_OK, ret);
    ret = PermissionManagerAdapter::CheckAuthPolicy("test_appId", "test_type", 1);
    ASSERT_NE(DLP_OK, ret);
    (void)PermissionManagerAdapter::CheckAuthPolicy("test_appId", "txt", 0);

    auto bundleMgr = GetBundleMgr();
    ASSERT_NE(bundleMgr, nullptr);
    AppExecFwk::BundleInfo bundleInfo;
    ret = bundleMgr->GetBundleInfoV9("com.ohos.dlpmanager",
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO),
        bundleInfo, DEFAULT_USERID);
    ASSERT_EQ(ret, 0);
    (void)PermissionManagerAdapter::CheckAuthPolicy(bundleInfo.appId, "txt", 1);

    AppExecFwk::BundleInfo bundleInfo1;
    ret = bundleMgr->GetBundleInfoV9("com.ohos.permissionmanager",
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO),
        bundleInfo1, DEFAULT_USERID);
    ASSERT_EQ(ret, 0);
    (void)PermissionManagerAdapter::CheckAuthPolicy(bundleInfo1.appId, "txt", 0);
}
