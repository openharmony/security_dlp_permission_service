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

#include "dlp_permission_service_test.h"
#include <openssl/rand.h>
#include <string>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "app_uninstall_observer.h"
#include "cert_parcel.h"
#include "critical_handler.h"
#include "critical_helper.h"
#define private public
#include "dlp_sandbox_change_callback_manager.h"
#include "open_dlp_file_callback_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_sandbox_change_callback_proxy.h"
#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "file_operator.h"
#include "ipc_skeleton.h"
#include "open_dlp_file_callback_proxy.h"
#include "open_dlp_file_callback_stub.h"
#include "open_dlp_file_callback_death_recipient.h"
#include "permission_policy.h"
#include "retention_file_manager.h"
#include "sandbox_json_manager.h"
#include "visited_dlp_file_info.h"
#define private public
#include "visit_record_file_manager.h"
#include "visit_record_json_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using namespace std::chrono;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionServiceTest"};
static const int32_t DEFAULT_USERID = 100;
static const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
static const std::string PERMISSION_APP = "com.ohos.permissionmanager";
static const std::string HIPREVIEW_HIGH = "com.huawei.hmos.hipreview";
}


/**
 * @tc.name:InstallDlpSandbox003
 * @tc.desc:InstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox003");
    SandboxInfo sandboxInfo;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    int32_t editAppIndex = sandboxInfo.appIndex;
    std::set<std::string> docUriSet;
    docUriSet.insert("testUri");
    RetentionInfo info;
    info.appIndex = editAppIndex;
    info.tokenId = sandboxInfo.tokenId;
    info.bundleName = HIPREVIEW_HIGH;
    info.userId = DEFAULT_USERID;
    RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
    ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    editAppIndex = sandboxInfo.appIndex;
    ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri1");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    editAppIndex = sandboxInfo.appIndex;
    info.appIndex = editAppIndex;
    info.tokenId = sandboxInfo.tokenId;
    RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
    ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name:InstallDlpSandbox004
 * @tc.desc:InstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox004, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox004");
    SandboxInfo sandboxInfo;
    DlpPermissionServiceTest::permType = -1;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        HIPREVIEW_HIGH, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
}

/**
 * @tc.name:DelWaterMarkInfo001
 * @tc.desc:DelWaterMarkInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelWaterMarkInfo001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelWaterMarkInfo001");
    WaterMarkInfo wmInfo;
    wmInfo.accountAndUserId = "test";
    dlpPermissionService_->waterMarkInfo_ = wmInfo;
    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "test");
    dlpPermissionService_->DelWaterMarkInfo();
    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");
}