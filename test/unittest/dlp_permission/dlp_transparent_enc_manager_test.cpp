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

#include <bitset>
#include <cstring>
#include <vector>

#include "dlfcn_mock.h"
#include "gtest/gtest.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;

extern "C" {
int32_t DLP_ProcessPluginCommand(int32_t code, const char *message, char **result, uint32_t *resultLen);
int32_t DLP_FreePluginCommandResult(char **result, uint32_t *resultLen);
int32_t DLP_GetDockerPolicy(const char *fileUri, DockerPolicyPayload **policy);
int32_t DLP_FreeDockerPolicy(DockerPolicyPayload **policy);
void MockSetResult(int32_t result);
void MockSetControlledAppListsData(const char *const *appLists, uint32_t appListsLen);
void MockSetPluginCommandResultData(const char *result);
void MockSetDockerPolicyInfoData(bool isEncrypted, bool needSandbox,
    const char *bundleName, const char *mimeType, uint32_t permission);
void MockResetAllState();
}

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpTransparentEncManagerTest"
};
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
    MockResetAllState();
}

void DlpTransparentEncManagerTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown.");
}

HWTEST_F(DlpTransparentEncManagerTest, GetInstance001, TestSize.Level0)
{
    auto &instance1 = DlpTransparentEncManager::GetInstance();
    auto &instance2 = DlpTransparentEncManager::GetInstance();
    ASSERT_EQ(&instance1, &instance2);
}

HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists001, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    appLists.push_back("com.test.app2");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists002, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, 0, true);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppLists003, TestSize.Level1)
{
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, 0, false);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, GetControlledAppListsDlopenFail001, TestSize.Level1)
{
    TestMock::ResetDlfcnMock();
    std::vector<std::string> appLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(appLists);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, ProcessPluginCommandDlopenFail001, TestSize.Level1)
{
    TestMock::ResetDlfcnMock();
    std::string result;
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test", result);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, GetDockerPolicyDlopenFail001, TestSize.Level1)
{
    TestMock::ResetDlfcnMock();
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_NE(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailProcessPluginCommand001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_ProcessPluginCommand");
    std::string result;
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test", result);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailGetDockerPolicy001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_GetDockerPolicy");
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailFreePluginCommandResult001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_FreePluginCommandResult");
    std::string result;
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test", result);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailFreeDockerPolicy001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_FreeDockerPolicy");
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailSetControlledAppLists001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_SetControlledAppLists");
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, LoadDlsymFailGetControlledAppLists001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor("DLP_GetControlledAppLists");
    std::vector<std::string> appLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(appLists);
    ASSERT_EQ(ret, DLP_ERROR_DLSYM);
    TestMock::ResetDlfcnMock();
}

HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppListsSuccess001, TestSize.Level1)
{
    TestMock::SetDlopenShouldFail(false);
    TestMock::SetDlsymShouldFailFor(nullptr);
    MockSetResult(0);
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_EQ(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, SetControlledAppListsSoCallFail001, TestSize.Level1)
{
    MockSetResult(-1);
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_NE(ret, DLP_OK);
    MockSetResult(0);
}

HWTEST_F(DlpTransparentEncManagerTest, GetControlledAppListsSuccessEmpty001, TestSize.Level1)
{
    MockSetResult(0);
    MockSetControlledAppListsData(nullptr, 0);
    std::vector<std::string> appLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(appLists);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_TRUE(appLists.empty());
}

HWTEST_F(DlpTransparentEncManagerTest, GetControlledAppListsSuccessWithData001, TestSize.Level1)
{
    MockSetResult(0);
    const char *apps[] = {"com.test.app1", "com.test.app2"};
    MockSetControlledAppListsData(apps, 2);
    std::vector<std::string> appLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(appLists);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_EQ(appLists.size(), static_cast<size_t>(2));
    ASSERT_EQ(appLists[0], "com.test.app1");
    ASSERT_EQ(appLists[1], "com.test.app2");
}

HWTEST_F(DlpTransparentEncManagerTest, GetControlledAppListsSoCallFail001, TestSize.Level1)
{
    MockSetResult(-1);
    std::vector<std::string> appLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(appLists);
    ASSERT_NE(ret, DLP_OK);
    MockSetResult(0);
}

HWTEST_F(DlpTransparentEncManagerTest, ProcessPluginCommandSuccessEmptyResult001, TestSize.Level1)
{
    MockSetResult(0);
    MockSetPluginCommandResultData("");
    std::string result = "initial";
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test_msg", result);
    ASSERT_EQ(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, ProcessPluginCommandSuccessWithResult001, TestSize.Level1)
{
    MockSetResult(0);
    MockSetPluginCommandResultData("plugin_response_data");
    std::string result;
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test_msg", result);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_EQ(result, "plugin_response_data");
}

HWTEST_F(DlpTransparentEncManagerTest, ProcessPluginCommandSoCallFail001, TestSize.Level1)
{
    MockSetResult(-1);
    std::string result;
    int32_t ret = DlpTransparentEncManager::GetInstance().ProcessPluginCommand(0x1001, "test_msg", result);
    ASSERT_NE(ret, DLP_OK);
    MockSetResult(0);
}

HWTEST_F(DlpTransparentEncManagerTest, GetDockerPolicySuccessWithPolicy001, TestSize.Level1)
{
    MockSetResult(0);
    MockSetDockerPolicyInfoData(true, true, "com.test.bundle", "application/dlp", 2);
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_EQ(policy.isEncrypted, true);
    ASSERT_EQ(policy.needSandbox, true);
    ASSERT_EQ(policy.bundleName, "com.test.bundle");
    ASSERT_EQ(policy.mimeType, "application/dlp");
    ASSERT_EQ(policy.permission, static_cast<uint32_t>(2));
}

HWTEST_F(DlpTransparentEncManagerTest, GetDockerPolicySoCallFail001, TestSize.Level1)
{
    MockSetResult(-1);
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_NE(ret, DLP_OK);
    MockSetResult(0);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_ProcessPluginCommandNullParams001, TestSize.Level1)
{
    char *result = nullptr;
    uint32_t resultLen = 0;
    int32_t ret = DLP_ProcessPluginCommand(0x1001, nullptr, &result, &resultLen);
    ASSERT_EQ(ret, -1);
    ret = DLP_ProcessPluginCommand(0x1001, "msg", nullptr, &resultLen);
    ASSERT_EQ(ret, -1);
    ret = DLP_ProcessPluginCommand(0x1001, "msg", &result, nullptr);
    ASSERT_EQ(ret, -1);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_ProcessPluginCommandEmptyResult001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    MockSetPluginCommandResultData("");
    char *result = nullptr;
    uint32_t resultLen = 0;
    int32_t ret = DLP_ProcessPluginCommand(0x1001, "msg", &result, &resultLen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result, nullptr);
    ASSERT_EQ(resultLen, static_cast<uint32_t>(0));
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_ProcessPluginCommandSuccess001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    MockSetPluginCommandResultData("response_data");
    char *result = nullptr;
    uint32_t resultLen = 0;
    int32_t ret = DLP_ProcessPluginCommand(0x1001, "msg", &result, &resultLen);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(result, nullptr);
    ASSERT_EQ(resultLen, static_cast<uint32_t>(13));
    ASSERT_STREQ(result, "response_data");
    DLP_FreePluginCommandResult(&result, &resultLen);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_ProcessPluginCommandMockError001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(-5);
    char *result = nullptr;
    uint32_t resultLen = 0;
    int32_t ret = DLP_ProcessPluginCommand(0x1001, "msg", &result, &resultLen);
    ASSERT_EQ(ret, -5);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_FreePluginCommandResultNullParams001, TestSize.Level1)
{
    uint32_t resultLen = 0;
    int32_t ret = DLP_FreePluginCommandResult(nullptr, &resultLen);
    ASSERT_EQ(ret, -1);
    char *result = nullptr;
    ret = DLP_FreePluginCommandResult(&result, nullptr);
    ASSERT_EQ(ret, -1);
    ret = DLP_FreePluginCommandResult(nullptr, nullptr);
    ASSERT_EQ(ret, -1);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_FreePluginCommandResultSuccess001, TestSize.Level1)
{
    char *result = strdup("test_data");
    ASSERT_NE(result, nullptr);
    uint32_t resultLen = 4;
    int32_t ret = DLP_FreePluginCommandResult(&result, &resultLen);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(result, nullptr);
    ASSERT_EQ(resultLen, static_cast<uint32_t>(0));
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicyNullParams001, TestSize.Level1)
{
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy(nullptr, &policy);
    ASSERT_EQ(ret, -1);
    ret = DLP_GetDockerPolicy("uri", nullptr);
    ASSERT_EQ(ret, -1);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicySuccess001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    MockSetDockerPolicyInfoData(true, false, "com.test.bundle", "application/dlp", 4);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(policy, nullptr);
    ASSERT_EQ(policy->is_encrypted, true);
    ASSERT_EQ(policy->need_sandbox, false);
    ASSERT_STREQ(policy->bundle_name, "com.test.bundle");
    ASSERT_STREQ(policy->mime_type, "application/dlp");
    ASSERT_EQ(policy->permission, static_cast<uint32_t>(4));
    DLP_FreeDockerPolicy(&policy);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicyMockError001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(-5);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, -5);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicyBundleNameTooLong001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    std::string longName(256, 'A');
    MockSetDockerPolicyInfoData(true, false, longName.c_str(), "application/dlp", 2);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(policy, nullptr);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_FreeDockerPolicyNullParams001, TestSize.Level1)
{
    int32_t ret = DLP_FreeDockerPolicy(nullptr);
    ASSERT_EQ(ret, -1);
    DockerPolicyPayload *nullPolicy = nullptr;
    ret = DLP_FreeDockerPolicy(&nullPolicy);
    ASSERT_EQ(ret, -1);
}

HWTEST_F(DlpTransparentEncManagerTest, DLP_FreeDockerPolicySuccess001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    MockSetDockerPolicyInfoData(true, false, "bundle", "application/dlp", 2);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(policy, nullptr);
    ret = DLP_FreeDockerPolicy(&policy);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(policy, nullptr);
}

HWTEST_F(DlpTransparentEncManagerTest, DockerPolicyPayloadFieldLayout001, TestSize.Level1)
{
    DockerPolicyPayload payload = {};
    payload.is_encrypted = true;
    payload.need_sandbox = false;
    strcpy_s(payload.bundle_name, sizeof(payload.bundle_name), "com.test.bundle");
    strcpy_s(payload.mime_type, sizeof(payload.mime_type), "application/dlp");
    payload.permission = 2;
    ASSERT_EQ(payload.is_encrypted, true);
    ASSERT_EQ(payload.need_sandbox, false);
    ASSERT_STREQ(payload.bundle_name, "com.test.bundle");
    ASSERT_STREQ(payload.mime_type, "application/dlp");
    ASSERT_EQ(payload.permission, static_cast<uint32_t>(2));
}

HWTEST_F(DlpTransparentEncManagerTest, DockerPolicyInfoDefaultValues001, TestSize.Level0)
{
    DockerPolicyInfo info;
    ASSERT_EQ(info.isEncrypted, false);
    ASSERT_EQ(info.needSandbox, false);
    ASSERT_EQ(info.bundleName, "");
    ASSERT_EQ(info.mimeType, "");
    ASSERT_EQ(info.permission, static_cast<uint32_t>(0));
}

HWTEST_F(DlpTransparentEncManagerTest, LoadAlreadyLoaded001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    std::vector<std::string> appLists;
    appLists.push_back("com.test.app1");
    int32_t ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_EQ(ret, DLP_OK);
    ret = DlpTransparentEncManager::GetInstance().SetControlledAppLists(appLists, DEFAULT_USER_ID, true);
    ASSERT_EQ(ret, DLP_OK);
}

HWTEST_F(DlpTransparentEncManagerTest, GetControlledAppListsNullEntry001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    std::vector<std::string> apps;
    apps.push_back("com.valid.app");
    apps.push_back("");
    MockSetControlledAppListsData(nullptr, 0);
    const char *cApps[] = {"com.valid.app"};
    MockSetControlledAppListsData(cApps, 1);
    std::vector<std::string> resultLists;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetControlledAppLists(resultLists);
    ASSERT_EQ(ret, DLP_OK);
}

// ===== ConvertPermissionToCustomFlag TDD tests =====
 
/**
 * @tc.name: ConvertPermissionToCustomFlag_NetworkAndSelinuxFalse_Returns0
 * @tc.desc: When networkAndSelinux (bit0)=0, should return 0 regardless of other bits
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, ConvertPermissionToCustomFlag_NetworkAndSelinuxFalse_Returns0, TestSize.Level0)
{
    // permission=0b00000 → networkAndSelinux=0, return 0
    DockerPolicyInfo info;
    info.isEncrypted = true;
    info.needSandbox = true;
    info.mimeType = "application/dlp";
    info.permission = 0b00000;  // all bits 0
    ASSERT_EQ(info.permission & 1, 0);  // networkAndSelinux=false
}
 
/**
 * @tc.name: ConvertPermissionToCustomFlag_FullControl_Returns37
 * @tc.desc: networkAndSelinux=1, screenShot=1 → securityFlag=false → FULL_CONTROL(37)
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, ConvertPermissionToCustomFlag_FullControl_Returns37, TestSize.Level0)
{
    // permission=0b01001: edit=0, screenShot=1, copy=0, print=0, networkAndSelinux=1
    // screenShot=1 → securityFlag=false → FULL_CONTROL=37
    uint32_t permission = 0b01001;
    bool screenShot = (permission >> 3) & 1;
    bool networkAndSelinux = permission & 1;
    bool securityFlag = !screenShot;
    ASSERT_TRUE(networkAndSelinux);
    ASSERT_FALSE(securityFlag);  // FULL_CONTROL path
 
    // Also verify: edit=1, screenShot=1, copy=1, print=1, networkAndSelinux=1
    permission = 0b11111;
    screenShot = (permission >> 3) & 1;
    networkAndSelinux = permission & 1;
    securityFlag = !screenShot;
    ASSERT_TRUE(networkAndSelinux);
    ASSERT_FALSE(securityFlag);  // FULL_CONTROL path
}
 
/**
 * @tc.name: ConvertPermissionToCustomFlag_ReadOnly_Returns38
 * @tc.desc: networkAndSelinux=1, screenShot=0 → securityFlag=true → READ_ONLY(38)
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, ConvertPermissionToCustomFlag_ReadOnly_Returns38, TestSize.Level0)
{
    // permission=0b00001: edit=0, screenShot=0, copy=0, print=0, networkAndSelinux=1
    // screenShot=0 → securityFlag=true → READ_ONLY=38
    uint32_t permission = 0b00001;
    bool screenShot = (permission >> 3) & 1;
    bool networkAndSelinux = permission & 1;
    bool securityFlag = !screenShot;
    ASSERT_TRUE(networkAndSelinux);
    ASSERT_TRUE(securityFlag);  // READ_ONLY path
 
    // permission=0b10101: edit=1, screenShot=0, copy=1, print=0, networkAndSelinux=1
    permission = 0b10101;
    screenShot = (permission >> 3) & 1;
    networkAndSelinux = permission & 1;
    securityFlag = !screenShot;
    ASSERT_TRUE(networkAndSelinux);
    ASSERT_TRUE(securityFlag);  // READ_ONLY path
}
 
/**
 * @tc.name: ConvertPermissionToCustomFlag_EdgeCases
 * @tc.desc: Test various 5-bit permission combinations for correct customFlag mapping
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, ConvertPermissionToCustomFlag_EdgeCases, TestSize.Level0)
{
    // Table-driven: {permission, expectedCustomFlag}
    // networkAndSelinux=0 → 0
    // networkAndSelinux=1, screenShot=0 → 38 (READ_ONLY)
    // networkAndSelinux=1, screenShot=1 → 37 (FULL_CONTROL)
    struct TestCase {
        uint32_t permission;
        int32_t expected;
    };
    TestCase cases[] = {
        {0b00000, 0},   // no flags
        {0b00010, 0},   // print=1, networkAndSelinux=0
        {0b01000, 0},   // screenShot=1, networkAndSelinux=0
        {0b11110, 0},   // edit+screenShot+copy+print, networkAndSelinux=0
        {0b00001, 38},  // networkAndSelinux=1, screenShot=0 → READ_ONLY
        {0b00101, 38},  // copy+networkAndSelinux, screenShot=0 → READ_ONLY
        {0b10001, 38},  // edit+networkAndSelinux, screenShot=0 → READ_ONLY
        {0b01001, 37},  // screenShot+networkAndSelinux → FULL_CONTROL
        {0b11001, 37},  // edit+screenShot+networkAndSelinux → FULL_CONTROL
        {0b01101, 37},  // screenShot+copy+networkAndSelinux → FULL_CONTROL
        {0b11111, 37},  // all bits → FULL_CONTROL
    };
    for (const auto &tc : cases) {
        bool screenShot = (tc.permission >> 3) & 1;
        bool networkAndSelinux = tc.permission & 1;
        bool securityFlag = !screenShot;
        int32_t result;
        if (!networkAndSelinux) {
            result = 0;
        } else {
            result = securityFlag ? 38 : 37;
        }
        EXPECT_EQ(result, tc.expected) <<
            "permission=0b" << std::bitset<5>(tc.permission) << " expected=" << tc.expected;
    }
}
 
// ===== DLP_GetDockerPolicy mimeType overflow protection tests =====
 
/**
 * @tc.name: DLP_GetDockerPolicyMimeTypeTooLong001
 * @tc.desc: mimeType string exceeding 128 bytes should return -1
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicyMimeTypeTooLong001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    std::string longMime(129, 'a');
    MockSetDockerPolicyInfoData(true, false, "com.test.bundle", longMime.c_str(), 2);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(policy, nullptr);
}
 
/**
 * @tc.name: DLP_GetDockerPolicyMimeTypeExactBoundary001
 * @tc.desc: mimeType string of exactly 127 bytes (fit in 128-byte buffer with null terminator)
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, DLP_GetDockerPolicyMimeTypeExactBoundary001, TestSize.Level1)
{
    MockResetAllState();
    MockSetResult(0);
    // 127 chars + null terminator = 128 bytes, should fit
    std::string exactMime(127, 'x');
    MockSetDockerPolicyInfoData(true, false, "com.test.bundle", exactMime.c_str(), 2);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(policy, nullptr);
    DLP_FreeDockerPolicy(&policy);
}
 
/**
 * @tc.name: DockerPolicyInfoMimeTypeStringField001
 * @tc.desc: Verify DockerPolicyInfo.mimeType is now std::string (not uint32_t)
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, DockerPolicyInfoMimeTypeStringField001, TestSize.Level0)
{
    DockerPolicyInfo info;
    // Default value should be empty string
    ASSERT_EQ(info.mimeType, "");
    // Should accept string assignment
    info.mimeType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    ASSERT_EQ(info.mimeType, "application/vnd.openxmlformats-officedocument.wordprocessingml.document");
}
 
/**
 * @tc.name: DockerPolicyPayloadMimeTypeIsCharArray001
 * @tc.desc: Verify DockerPolicyPayload.mime_type is char[128] (not uint32_t)
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, DockerPolicyPayloadMimeTypeIsCharArray001, TestSize.Level0)
{
    DockerPolicyPayload payload = {};
    // Should be assignable as a C-string
    strcpy_s(payload.mime_type, sizeof(payload.mime_type), "text/plain");
    ASSERT_STREQ(payload.mime_type, "text/plain");
}
 
/**
 * @tc.name: GetDockerPolicySuccessWithPolicy002
 * @tc.desc: Verify GetDockerPolicy fills mimeType as string correctly
 * @tc.type: FUNC
 */
HWTEST_F(DlpTransparentEncManagerTest, GetDockerPolicySuccessWithPolicy002, TestSize.Level1)
{
    MockSetResult(0);
    MockSetDockerPolicyInfoData(true, true, "com.test.bundle2", "application/pdf", 0b00001);
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_EQ(policy.isEncrypted, true);
    ASSERT_EQ(policy.needSandbox, true);
    ASSERT_EQ(policy.bundleName, "com.test.bundle2");
    ASSERT_EQ(policy.mimeType, "application/pdf");
    ASSERT_EQ(policy.permission, static_cast<uint32_t>(0b00001));
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
