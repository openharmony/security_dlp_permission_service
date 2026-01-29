/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
 
#include "dlp_permission_static_test.h"
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <iostream>
#include "account_adapt.h"
#include "cert_parcel.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_async_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_parcel.h"
#include "dlp_credential.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "securec.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#define private public
#include "dlp_permission_service.h"
#include "dlp_permission_service.cpp"
namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr uint32_t WAIT_FOR_ACCESS_TOKEN_START = 500;
#define AC_TKN_SVC "accesstoken_service"
#define SVC_CTRL "service_control"
static constexpr char PID_OF_ACCESS_TOKEN_SERVICE[] = "pidof " AC_TKN_SVC;
uint64_t g_selfTokenId = 0;
std::shared_ptr<DlpPermissionService> dlpPermissionService_ = nullptr;
}
static void RestartAccessTokenService()
{
    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " stop " AC_TKN_SVC);

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " start " AC_TKN_SVC);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_ACCESS_TOKEN_START));

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);
}
void DlpPermissionStaticTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    uint64_t tokenId;
    const char *acls[] = {
        PERMISSION_ACCESS_DLP_FILE.c_str(),
    };
    const char *perms[] = {
        PERMISSION_ACCESS_DLP_FILE.c_str(),
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };
    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "test_get_local_account";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    RestartAccessTokenService();
}

void DlpPermissionStaticTest::TearDownTestCase()
{
    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
    RestartAccessTokenService();
}

void DlpPermissionStaticTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "setup");
    dlpPermissionService_ = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    ASSERT_NE(nullptr, dlpPermissionService_);
    dlpPermissionService_->appStateObserver_ = new (std::nothrow) AppStateObserver();
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_ != nullptr);
}
 
void DlpPermissionStaticTest::TearDown() {}
 
/**
 * @tc.name: DlpPermissionStaticTest001
 * @tc.desc: previewBindInstall test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest001, TestSize.Level1)
{
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
    int32_t userId = 100;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    ASSERT_EQ(appInfo.bindAppIndex, 1001);
    appInfo.bindAppIndex = -1;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    appInfo.appIndex = 1001;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    appInfo.bindAppIndex = 1001;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    ASSERT_EQ(appInfo.bindAppIndex, 1001);
}

/**
 * @tc.name: DlpPermissionStaticTest002
 * @tc.desc: InstallDlpSandboxExecute test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest002, TestSize.Level1)
{
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
    int32_t userId = 100;
    std::string bundleName = HIPREVIEW_HIGH;
    bool isNeedInstall = false;
    int32_t ret = InstallDlpSandboxExecute(isNeedInstall,
        dlpFileAccess, bundleName, userId, appInfo);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: DlpPermissionStaticTest003
 * @tc.desc: GetSandboxExternalAuthorization test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DlpPermissionStaticTest003");

    int sandboxUid = -1;
    AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    int32_t ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::DENY_START_ABILITY);
    sandboxUid = 0;
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    want.SetBundle(HIPREVIEW_LOW);
    DlpSandboxInfo appInfo = {
        .uid = -1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
    appInfo.appIndex = 1001;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
    sandboxUid = -1;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS