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
    const char *bundleName, uint32_t mimeType, uint32_t permission);
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
    MockSetDockerPolicyInfoData(true, true, "com.test.bundle", 1, 2);
    DockerPolicyInfo policy;
    int32_t ret = DlpTransparentEncManager::GetInstance().GetDockerPolicy("file://test.dlp", policy);
    ASSERT_EQ(ret, DLP_OK);
    ASSERT_EQ(policy.isEncrypted, true);
    ASSERT_EQ(policy.needSandbox, true);
    ASSERT_EQ(policy.bundleName, "com.test.bundle");
    ASSERT_EQ(policy.mimeType, static_cast<uint32_t>(1));
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
    MockSetDockerPolicyInfoData(true, false, "com.test.bundle", 3, 4);
    DockerPolicyPayload *policy = nullptr;
    int32_t ret = DLP_GetDockerPolicy("file://test.dlp", &policy);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(policy, nullptr);
    ASSERT_EQ(policy->is_encrypted, true);
    ASSERT_EQ(policy->need_sandbox, false);
    ASSERT_STREQ(policy->bundle_name, "com.test.bundle");
    ASSERT_EQ(policy->mime_type, static_cast<uint32_t>(3));
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
    MockSetDockerPolicyInfoData(true, false, longName.c_str(), 1, 2);
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
    MockSetDockerPolicyInfoData(true, false, "bundle", 1, 2);
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
    payload.mime_type = 1;
    payload.permission = 2;
    ASSERT_EQ(payload.is_encrypted, true);
    ASSERT_EQ(payload.need_sandbox, false);
    ASSERT_STREQ(payload.bundle_name, "com.test.bundle");
    ASSERT_EQ(payload.mime_type, static_cast<uint32_t>(1));
    ASSERT_EQ(payload.permission, static_cast<uint32_t>(2));
}

HWTEST_F(DlpTransparentEncManagerTest, DockerPolicyInfoDefaultValues001, TestSize.Level0)
{
    DockerPolicyInfo info;
    ASSERT_EQ(info.isEncrypted, false);
    ASSERT_EQ(info.needSandbox, false);
    ASSERT_EQ(info.bundleName, "");
    ASSERT_EQ(info.mimeType, static_cast<uint32_t>(0));
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

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
