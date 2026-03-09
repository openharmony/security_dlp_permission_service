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
static const uint32_t MAX_APPID_SIZE = 1024;
static const uint32_t MAX_BUNDLENAME_SIZE = 1024;
static const uint32_t MAX_URI_SIZE = 4095;
static const uint32_t MAX_MASKINFO_SIZE = 128;
static const uint32_t MAX_ACCOUNT_SIZE = 1024;
static const uint32_t MAX_FILEID_SIZE = 1024;
static const uint32_t MAX_ENTERPRISEPOLICY_SIZE = 1024 * 1024 * 4;
static const uint32_t MAX_CERT_SIZE = 1024 * 1024 * 40 * 2;
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

/**
 * @tc.name: ParseDlpCertificate003
 * @tc.desc: ParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, ParseDlpCertificate003, TestSize.Level1)
{
    sptr<IDlpPermissionCallback> callback = nullptr;
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ASSERT_NE(callback, nullptr);
    std::string appId(MAX_APPID_SIZE + 1, 'a');
    int32_t ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, appId, true);
    ASSERT_EQ(DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED, ret);
    appId = "testAppId";

    // cert is too long
    certParcel->cert = std::vector<uint8_t>(MAX_CERT_SIZE + 1, 0x01);
    ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, appId, true);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: InstallDlpSandbox005
 * @tc.desc: InstallDlpSandbox with too long bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox005, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox004");
    SandboxInfo sandboxInfo;
    std::string longBundleName(MAX_BUNDLENAME_SIZE + 1, 'a');

    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        longBundleName,
        DLPFileAccess::READ_ONLY,
        DEFAULT_USERID,
        sandboxInfo,
        "validUri");
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: InstallDlpSandbox006
 * @tc.desc: InstallDlpSandbox with too long uri
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox006, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox005");
    SandboxInfo sandboxInfo;
    std::string longUri(MAX_URI_SIZE + 1, 'b');

    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP,
        DLPFileAccess::READ_ONLY,
        DEFAULT_USERID,
        sandboxInfo,
        longUri);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}


/**
 * @tc.name:UninstallDlpSandbox003
 * @tc.desc:UninstallDlpSandbox with too long bundle name
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, UninstallDlpSandbox003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "UninstallDlpSandbox003");
    std::string longBundleName(MAX_BUNDLENAME_SIZE + 1, 'a');
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        dlpPermissionService_->UninstallDlpSandbox(longBundleName, 1, 1));
}

/**
 * @tc.name: GetSandboxExternalAuthorization003
 * @tc.desc: bundleName size > MAX_BUNDLENAME_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetSandboxExternalAuthorization003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetSandboxExternalAuthorization003");
    int sandboxUid = 0;
    SandBoxExternalAuthorType authType;

    AAFwk::Want want;
    std::string longBundle(MAX_BUNDLENAME_SIZE + 1, 'a');
    want.SetBundle(longBundle);
    int32_t ret =
        dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: SetEnterprisePolicy002
 * @tc.desc: SetEnterprisePolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterprisePolicy002, TestSize.Level1)
{
    std::string longPolicy(MAX_ENTERPRISEPOLICY_SIZE + 1, 'a');
    int32_t ret = dlpPermissionService_->SetEnterprisePolicy(longPolicy);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: ValidateStringList001
 * @tc.desc: ValidateStringList abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, ValidateStringList001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ValidateStringList001");
    std::vector<std::string> stringVec;
    stringVec.push_back(std::string(MAX_URI_SIZE + 1, 'a'));
    int32_t ret = dlpPermissionService_->SetRetentionState(stringVec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    ret = dlpPermissionService_->CancelRetentionState(stringVec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    stringVec.clear();
    stringVec.push_back(std::string(MAX_APPID_SIZE + 1, 'a'));
    ret = dlpPermissionService_->SetMDMPolicy(stringVec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: SetFileInfo002
 * @tc.desc: SetFileInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetFileInfo002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetFileInfo002");

    FileInfo fileInfo;
    fileInfo.accountName = "acc";
    fileInfo.fileId = "file";
    fileInfo.maskInfo = "mask";
    std::string longUri(MAX_URI_SIZE + 1, 'a');
    int32_t ret = dlpPermissionService_->SetFileInfo(longUri, fileInfo);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_URI_EMPTY);
}

/**
 * @tc.name: SetFileInfo003
 * @tc.desc: SetFileInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetFileInfo003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetFileInfo003");

    FileInfo fileInfo;
    std::string uri;

    // uri size > MAX_URI_SIZE
    uri = std::string(MAX_URI_SIZE + 1, 'a');
    int32_t ret = dlpPermissionService_->SetFileInfo(uri, fileInfo);
    ASSERT_NE(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    uri = "validUri";

    // accountName too long
    fileInfo.accountName = std::string(MAX_ACCOUNT_SIZE + 1, 'a');
    fileInfo.fileId = "file";
    fileInfo.maskInfo = "mask";
    ret = dlpPermissionService_->SetFileInfo(uri, fileInfo);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    // fileId too long
    fileInfo.accountName = "acc";
    fileInfo.fileId = std::string(MAX_FILEID_SIZE + 1, 'b');
    fileInfo.maskInfo = "mask";
    ret = dlpPermissionService_->SetFileInfo(uri, fileInfo);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    // maskInfo too long
    fileInfo.accountName = "acc";
    fileInfo.fileId = "file";
    fileInfo.maskInfo = std::string(MAX_MASKINFO_SIZE + 1, 'c');
    ret = dlpPermissionService_->SetFileInfo(uri, fileInfo);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}