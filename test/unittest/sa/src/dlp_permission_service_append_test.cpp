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
#include "file_uri.h"
#include "ipc_skeleton.h"
#include "open_dlp_file_callback_proxy.h"
#include "open_dlp_file_callback_stub.h"
#include "open_dlp_file_callback_death_recipient.h"
#include "permission_policy.h"
#include "huks_apply_permission_test_common.h"
#include "retention_file_manager.h"
#include "sandbox_json_manager.h"
#include "token_setproc.h"
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
using OHOS::AppExecFwk::RunningProcessInfo;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionServiceTest"};
static const int32_t DEFAULT_USERID = 100;
static const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
static const std::string PERMISSION_APP = "com.ohos.permissionmanager";
static const std::string HIPREVIEW_HIGH = "com.huawei.hmos.hipreview";
static const std::string PASTEBOARD_SERVICE_NAME = "pasteboard_service";
static const uint32_t MAX_APPID_SIZE = 1024;
static const uint32_t MAX_BUNDLENAME_SIZE = 1024;
static const uint32_t MAX_URI_SIZE = 4095;
static const uint32_t MAX_MASKINFO_SIZE = 128;
static const uint32_t MAX_ACCOUNT_SIZE = 1024;
static const uint32_t MAX_FILEID_SIZE = 1024;
static const uint32_t MAX_CLASSIFICATION_LABEL_SIZE = 255;
static const uint32_t MAX_ENTERPRISEPOLICY_SIZE = 1024 * 1024 * 4;
static const uint32_t MAX_CERT_SIZE = 1024 * 1024 * 40 * 2;
static const std::string CALLER_APP_IDENTIFIER = "1234567890";
}

static bool ContainsUri(const std::vector<std::string>& uris, const std::string& uri)
{
    for (const auto& item : uris) {
        if (item == uri) {
            return true;
        }
    }
    return false;
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

/**
 * @tc.name: SetDlpFeature002
 * @tc.desc: SetDlpFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetDlpFeature002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetDlpFeature002");

    std::string backupIdentifier = DlpPermissionServiceTest::mockAppIdentifier;

    DlpPermissionServiceTest::mockAppIdentifier = "1234567890";
    uint32_t dlpFeatureInfo = 1;
    bool statusSetInfo = true;
    int32_t ret = dlpPermissionService_->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    ASSERT_EQ(DLP_SERVICE_ERROR_NOT_SYSTEM_APP, ret);
    ASSERT_FALSE(statusSetInfo);

    DlpPermissionServiceTest::mockAppIdentifier = "6917562860841254665";
    ret = SetIdsTokenForAcrossAccountsPermission();
    ASSERT_EQ(DLP_OK, ret);

    statusSetInfo = false;
    ret = dlpPermissionService_->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_TRUE(statusSetInfo);

    DlpPermissionServiceTest::mockAppIdentifier = backupIdentifier;
}

/**
 * @tc.name: SetEnterpriseInfos001
 * @tc.desc: SetEnterpriseInfos success and input check test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterpriseInfos001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetEnterpriseInfos001");
    std::string uri = "enterprise_uri_001";
    std::string fileId = "file_id_001";
    std::string label = "label_001";
    std::string appIdentifier = CALLER_APP_IDENTIFIER;

    int32_t ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, fileId, DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_OK, ret);

    EnterpriseInfo enterpriseInfo;
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_->GetEnterpriseInfoByUri(uri, enterpriseInfo));
    ASSERT_EQ(enterpriseInfo.fileId, fileId);
    ASSERT_EQ(enterpriseInfo.classificationLabel, label);
    ASSERT_EQ(enterpriseInfo.appIdentifier, appIdentifier);

    std::string longLabel(MAX_CLASSIFICATION_LABEL_SIZE + 1, 'a');
    ret = dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_002", "file_id_002", DLPFileAccess::READ_ONLY, longLabel, appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DlpPermissionServiceTest::permType = -1;
    ret = dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_003", "file_id_003", DLPFileAccess::READ_ONLY, "label", appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
    DlpPermissionServiceTest::permType = 0;
}

/**
 * @tc.name: SetEnterpriseInfos002
 * @tc.desc: SetEnterpriseInfos uri empty and uri size check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterpriseInfos002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetEnterpriseInfos002");
    std::string fileId = "file_id_uri";
    std::string label = "label_uri";
    std::string appIdentifier = CALLER_APP_IDENTIFIER;

    int32_t ret = dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_uri", fileId, DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_OK, ret);

    ret = dlpPermissionService_->SetEnterpriseInfos(
        "", fileId, DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    std::string longUri(MAX_URI_SIZE + 1, 'a');
    ret = dlpPermissionService_->SetEnterpriseInfos(
        longUri, fileId, DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: SetEnterpriseInfos003
 * @tc.desc: SetEnterpriseInfos fileId and appIdentifier size check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterpriseInfos003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetEnterpriseInfos003");
    std::string uri = "enterprise_uri_size";
    std::string label = "label_size";
    std::string appIdentifier = CALLER_APP_IDENTIFIER;

    int32_t ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, "file_id_size", DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_OK, ret);

    std::string longFileId(MAX_FILEID_SIZE + 1, 'b');
    ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, longFileId, DLPFileAccess::READ_ONLY, label, appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    std::string longAppIdentifier(MAX_APPID_SIZE + 1, 'c');
    ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, "file_id_size2", DLPFileAccess::READ_ONLY, label, longAppIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: SetEnterpriseInfos004
 * @tc.desc: SetEnterpriseInfos label size and dlpFileAccess range check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterpriseInfos004, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetEnterpriseInfos004");
    std::string uri = "enterprise_uri_access";
    std::string fileId = "file_id_access";
    std::string appIdentifier = CALLER_APP_IDENTIFIER;

    int32_t ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, fileId, DLPFileAccess::FULL_CONTROL, "label_access", appIdentifier);
    ASSERT_EQ(DLP_OK, ret);

    std::string longLabel(MAX_CLASSIFICATION_LABEL_SIZE + 1, 'd');
    ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, fileId, DLPFileAccess::READ_ONLY, longLabel, appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DLPFileAccess tooLargeAccess = static_cast<DLPFileAccess>(
        static_cast<int32_t>(DLPFileAccess::FULL_CONTROL) + 1);
    ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, fileId, tooLargeAccess, "label_access2", appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    ret = dlpPermissionService_->SetEnterpriseInfos(
        uri, fileId, DLPFileAccess::NO_PERMISSION, "label_access3", appIdentifier);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: QueryOpenedEnterpriseDlpFiles001
 * @tc.desc: QueryOpenedEnterpriseDlpFiles filters by label and appIdentifier
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, QueryOpenedEnterpriseDlpFiles001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "QueryOpenedEnterpriseDlpFiles001");

    ASSERT_EQ(DLP_OK, dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_q1", "file_q1", DLPFileAccess::READ_ONLY, "L1", CALLER_APP_IDENTIFIER));
    ASSERT_EQ(DLP_OK, dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_q2", "file_q2", DLPFileAccess::READ_ONLY, "L2", CALLER_APP_IDENTIFIER));
    ASSERT_EQ(DLP_OK, dlpPermissionService_->SetEnterpriseInfos(
        "enterprise_uri_q3", "file_q3", DLPFileAccess::READ_ONLY, "L1", "another_app"));

    dlpPermissionService_->appStateObserver_->UpdateEnterpriseUidByUri("enterprise_uri_q1", "file_q1", 301);
    dlpPermissionService_->appStateObserver_->UpdateEnterpriseUidByUri("enterprise_uri_q2", "file_q2", 302);
    dlpPermissionService_->appStateObserver_->UpdateEnterpriseUidByUri("enterprise_uri_q3", "file_q3", 303);

    std::vector<std::string> uris;
    int32_t ret = dlpPermissionService_->QueryOpenedEnterpriseDlpFiles("L1", uris);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(uris.size(), 1);
    ASSERT_TRUE(ContainsUri(uris, "enterprise_uri_q1"));

    uris.clear();
    ret = dlpPermissionService_->QueryOpenedEnterpriseDlpFiles("", uris);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(uris.size(), 2);
    ASSERT_TRUE(ContainsUri(uris, "enterprise_uri_q1"));
    ASSERT_TRUE(ContainsUri(uris, "enterprise_uri_q2"));

    std::string longLabel(MAX_CLASSIFICATION_LABEL_SIZE + 1, 'a');
    ret = dlpPermissionService_->QueryOpenedEnterpriseDlpFiles(longLabel, uris);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DlpPermissionServiceTest::permType = -1;
    ret = dlpPermissionService_->QueryOpenedEnterpriseDlpFiles("L1", uris);
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
    DlpPermissionServiceTest::permType = 0;
}

/**
 * @tc.name: CloseOpenedEnterpriseDlpFiles001
 * @tc.desc: CloseOpenedEnterpriseDlpFiles parameter and permission check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, CloseOpenedEnterpriseDlpFiles001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "CloseOpenedEnterpriseDlpFiles001");

    std::string backupIdentifier = DlpPermissionServiceTest::mockAppIdentifier;
    DlpPermissionServiceTest::mockAppIdentifier = CALLER_APP_IDENTIFIER;

    DlpSandboxInfo appInfo;
    appInfo.uid = 1301;
    appInfo.userId = DEFAULT_USERID;
    appInfo.appIndex = 101;
    appInfo.tokenId = 1301;
    appInfo.bundleName = DLP_MANAGER_APP;
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.classificationLabel = "L1";
    appInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);

    int32_t ret = dlpPermissionService_->CloseOpenedEnterpriseDlpFiles("L1");
    ASSERT_EQ(DLP_PARSE_ERROR_BMS_ERROR, ret);

    std::string longLabel(MAX_CLASSIFICATION_LABEL_SIZE + 1, 'a');
    ret = dlpPermissionService_->CloseOpenedEnterpriseDlpFiles(longLabel);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DlpPermissionServiceTest::permType = -1;
    ret = dlpPermissionService_->CloseOpenedEnterpriseDlpFiles("L1");
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
    DlpPermissionServiceTest::permType = 0;

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    DlpPermissionServiceTest::mockAppIdentifier = backupIdentifier;
}

/**
 * @tc.name: InstallDlpSandbox007
 * @tc.desc: InstallDlpSandbox enter enterprise branch and clear enterprise info when install failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox007, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox007");

    std::string uri = "datashare:///media/file/777";
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();

    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = "enterprise_file_007";
    enterpriseInfo.classificationLabel = "L1";
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_->AddUriAndEnterpriseInfo(path, enterpriseInfo));

    SandboxInfo sandboxInfo;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        "com.invalid.bundle", DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, uri);
    ASSERT_NE(DLP_OK, ret);

    EnterpriseInfo queryInfo;
    ASSERT_FALSE(dlpPermissionService_->appStateObserver_->GetEnterpriseInfoByUri(path, queryInfo));
}

/**
 * @tc.name: HandleEnterpriseInstallDlpSandbox001
 * @tc.desc: HandleEnterpriseInstallDlpSandbox return error when retention query fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, HandleEnterpriseInstallDlpSandbox001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "HandleEnterpriseInstallDlpSandbox001");

    SandboxInfo sandboxInfo;
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = "enterprise_file_001";
    enterpriseInfo.classificationLabel = "L1";
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;

    // Empty bundleName forces GetRetentionSandboxList path to return non-DLP_OK.
    InputSandboxInfo inputSandboxInfo = {"", DLPFileAccess::READ_ONLY, DEFAULT_USERID,
        "datashare:///media/file/1001", ""};
    int32_t ret = dlpPermissionService_->HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo,
        enterpriseInfo);
    ASSERT_NE(DLP_OK, ret);
}

/**
 * @tc.name: HandleEnterpriseInstallDlpSandbox002
 * @tc.desc: HandleEnterpriseInstallDlpSandbox erase enterprise info when install branch failed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, HandleEnterpriseInstallDlpSandbox002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "HandleEnterpriseInstallDlpSandbox002");

    std::string uri = "datashare:///media/file/1002";
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();

    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = "enterprise_file_002";
    enterpriseInfo.classificationLabel = "L2";
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_->AddUriAndEnterpriseInfo(path, enterpriseInfo));

    SandboxInfo sandboxInfo;
    InputSandboxInfo inputSandboxInfo = {"com.invalid.bundle", DLPFileAccess::READ_ONLY,
        DEFAULT_USERID, uri, path};
    int32_t ret = dlpPermissionService_->HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo,
        enterpriseInfo);
    ASSERT_NE(DLP_OK, ret);

    EnterpriseInfo queryInfo;
    ASSERT_FALSE(dlpPermissionService_->appStateObserver_->GetEnterpriseInfoByUri(path, queryInfo));
}

/**
 * @tc.name: HandleEnterpriseInstallDlpSandbox003
 * @tc.desc: HandleEnterpriseInstallDlpSandbox covers read-only reuse branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, HandleEnterpriseInstallDlpSandbox003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "HandleEnterpriseInstallDlpSandbox003");

    DlpSandboxInfo existInfo;
    existInfo.uid = 2101;
    existInfo.userId = DEFAULT_USERID;
    existInfo.appIndex = 88;
    existInfo.tokenId = 2101;
    existInfo.bundleName = DLP_MANAGER_APP;
    existInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    existInfo.classificationLabel = "L3";
    existInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(existInfo);

    SandboxInfo sandboxInfo;
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = "enterprise_file_003";
    enterpriseInfo.classificationLabel = "L3";
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    std::string uri = "datashare:///media/file/1003";
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();
    InputSandboxInfo inputSandboxInfo = {DLP_MANAGER_APP, DLPFileAccess::READ_ONLY, DEFAULT_USERID, uri, path};

    int32_t ret = dlpPermissionService_->HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo,
        enterpriseInfo);
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(existInfo.uid);
}

class MockAppMgrProxyForInstall final : public AppExecFwk::AppMgrProxy {
public:
    explicit MockAppMgrProxyForInstall(const std::vector<RunningProcessInfo>& infoVec)
        : AppExecFwk::AppMgrProxy(nullptr), infoVec_(infoVec) {}

    int32_t GetAllRunningProcesses(std::vector<RunningProcessInfo>& infoVec) override
    {
        infoVec = infoVec_;
        return ERR_OK;
    }

private:
    std::vector<RunningProcessInfo> infoVec_;
};

static RunningProcessInfo MakeRunningProcessInfoForInstall(int32_t uid, const std::string& processName,
    AppExecFwk::AppProcessState state, int32_t pid)
{
    RunningProcessInfo info;
    info.uid_ = uid;
    info.processName_ = processName;
    info.state_ = state;
    info.pid_ = pid;
    info.bundleNames = {processName};
    return info;
}

/**
 * @tc.name: HandleEnterpriseInstallDlpSandbox004
 * @tc.desc: Cover opened enterprise sandbox fast-return branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, HandleEnterpriseInstallDlpSandbox004, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "HandleEnterpriseInstallDlpSandbox004");

    std::string uri = "datashare:///media/file/1004";
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();

    DlpSandboxInfo openedInfo;
    openedInfo.uid = 2201;
    openedInfo.userId = DEFAULT_USERID;
    openedInfo.appIndex = 66;
    openedInfo.bindAppIndex = 16;
    openedInfo.tokenId = 2201;
    openedInfo.bundleName = DLP_MANAGER_APP;
    openedInfo.uri = uri;
    openedInfo.fileId = "enterprise_file_004";
    openedInfo.classificationLabel = "L4";
    openedInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(openedInfo);

    std::vector<RunningProcessInfo> infoVec = {
        MakeRunningProcessInfoForInstall(
            openedInfo.uid, DLP_MANAGER_APP, AppExecFwk::AppProcessState::APP_STATE_FOREGROUND, 401),
    };
    dlpPermissionService_->appStateObserver_->SetAppProxy(new (std::nothrow) MockAppMgrProxyForInstall(infoVec));

    SandboxInfo sandboxInfo;
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = openedInfo.fileId;
    enterpriseInfo.classificationLabel = openedInfo.classificationLabel;
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    InputSandboxInfo inputSandboxInfo = {DLP_MANAGER_APP, DLPFileAccess::READ_ONLY, DEFAULT_USERID, uri, path};

    int32_t ret = dlpPermissionService_->HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo,
        enterpriseInfo);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(openedInfo.appIndex, sandboxInfo.appIndex);
    ASSERT_EQ(openedInfo.bindAppIndex, sandboxInfo.bindAppIndex);
    ASSERT_EQ(openedInfo.tokenId, sandboxInfo.tokenId);

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(openedInfo.uid);
}

/**
 * @tc.name: HandleEnterpriseInstallDlpSandbox005
 * @tc.desc: Cover isNeedInstall && isReadOnly branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, HandleEnterpriseInstallDlpSandbox005, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "HandleEnterpriseInstallDlpSandbox005");

    std::string uri = "datashare:///media/file/1005";
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string path = fileUri.GetRealPath();

    SandboxInfo sandboxInfo;
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.fileId = "enterprise_file_005";
    enterpriseInfo.classificationLabel = "L5";
    enterpriseInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    InputSandboxInfo inputSandboxInfo = {"com.branch.cover.bundle", DLPFileAccess::READ_ONLY,
        DEFAULT_USERID, uri, path};

    int32_t ret = dlpPermissionService_->HandleEnterpriseInstallDlpSandbox(sandboxInfo, inputSandboxInfo,
        enterpriseInfo);
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: DelSandboxInfoByAccount001
 * @tc.desc: DelSandboxInfoByAccount covers HIPREVIEW_HIGH branch with valid bindAppIndex
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelSandboxInfoByAccount001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelSandboxInfoByAccount001");

    dlpPermissionService_->waterMarkInfo_.accountAndUserId = "test_watermark_before";

    DlpSandboxInfo hippreviewHighInfo;
    hippreviewHighInfo.uid = 3301;
    hippreviewHighInfo.userId = DEFAULT_USERID;
    hippreviewHighInfo.appIndex = 101;
    hippreviewHighInfo.bindAppIndex = 201;
    hippreviewHighInfo.tokenId = 3301;
    hippreviewHighInfo.bundleName = HIPREVIEW_HIGH;
    hippreviewHighInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    hippreviewHighInfo.accountName = "test_account_del";
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(hippreviewHighInfo);

    DlpSandboxInfo queryInfo;
    bool existsBefore = dlpPermissionService_->appStateObserver_->GetSandboxInfo(hippreviewHighInfo.uid, queryInfo);
    ASSERT_TRUE(existsBefore);

    dlpPermissionService_->DelSandboxInfoByAccount(false);

    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(hippreviewHighInfo.uid);
}

/**
 * @tc.name: DelSandboxInfoByAccount002
 * @tc.desc: DelSandboxInfoByAccount covers HIPREVIEW_HIGH branch with isRegister=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelSandboxInfoByAccount002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelSandboxInfoByAccount002");

    dlpPermissionService_->waterMarkInfo_.accountAndUserId = "test_watermark_register";

    DlpSandboxInfo hippreviewHighInfo;
    hippreviewHighInfo.uid = 3302;
    hippreviewHighInfo.userId = DEFAULT_USERID;
    hippreviewHighInfo.appIndex = 102;
    hippreviewHighInfo.bindAppIndex = 202;
    hippreviewHighInfo.tokenId = 3302;
    hippreviewHighInfo.bundleName = HIPREVIEW_HIGH;
    hippreviewHighInfo.dlpFileAccess = DLPFileAccess::CONTENT_EDIT;
    hippreviewHighInfo.accountName = "register_account_del";
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(hippreviewHighInfo);

    DlpSandboxInfo queryInfo;
    bool existsBefore = dlpPermissionService_->appStateObserver_->GetSandboxInfo(hippreviewHighInfo.uid, queryInfo);
    ASSERT_TRUE(existsBefore);

    dlpPermissionService_->DelSandboxInfoByAccount(true);

    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(hippreviewHighInfo.uid);
}

/**
 * @tc.name: DelSandboxInfoByAccount003
 * @tc.desc: DelSandboxInfoByAccount covers non-HIPREVIEW_HIGH bundle (skip bind uninstall)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelSandboxInfoByAccount003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelSandboxInfoByAccount003");

    dlpPermissionService_->waterMarkInfo_.accountAndUserId = "test_watermark_normal";

    DlpSandboxInfo normalInfo;
    normalInfo.uid = 3303;
    normalInfo.userId = DEFAULT_USERID;
    normalInfo.appIndex = 103;
    normalInfo.bindAppIndex = 203;
    normalInfo.tokenId = 3303;
    normalInfo.bundleName = DLP_MANAGER_APP;
    normalInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    normalInfo.accountName = "normal_account_del";
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(normalInfo);

    DlpSandboxInfo queryInfo;
    bool existsBefore = dlpPermissionService_->appStateObserver_->GetSandboxInfo(normalInfo.uid, queryInfo);
    ASSERT_TRUE(existsBefore);

    dlpPermissionService_->DelSandboxInfoByAccount(false);

    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(normalInfo.uid);
}

/**
 * @tc.name: DelSandboxInfoByAccount004
 * @tc.desc: DelSandboxInfoByAccount with empty accountName skips processing for that entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelSandboxInfoByAccount004, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelSandboxInfoByAccount004");

    dlpPermissionService_->waterMarkInfo_.accountAndUserId = "test_watermark_empty";

    DlpSandboxInfo emptyAccountInfo;
    emptyAccountInfo.uid = 3304;
    emptyAccountInfo.userId = DEFAULT_USERID;
    emptyAccountInfo.appIndex = 104;
    emptyAccountInfo.bindAppIndex = 204;
    emptyAccountInfo.tokenId = 3304;
    emptyAccountInfo.bundleName = HIPREVIEW_HIGH;
    emptyAccountInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    emptyAccountInfo.accountName = "";
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(emptyAccountInfo);

    DlpSandboxInfo queryInfo;
    bool existsBefore = dlpPermissionService_->appStateObserver_->GetSandboxInfo(emptyAccountInfo.uid, queryInfo);
    ASSERT_TRUE(existsBefore);

    dlpPermissionService_->DelSandboxInfoByAccount(false);

    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");

    bool existsAfter = dlpPermissionService_->appStateObserver_->GetSandboxInfo(emptyAccountInfo.uid, queryInfo);
    ASSERT_TRUE(existsAfter);

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(emptyAccountInfo.uid);
}

/**
 * @tc.name: DelSandboxInfoByAccount005
 * @tc.desc: DelSandboxInfoByAccount with different userId skips processing for that entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DelSandboxInfoByAccount005, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DelSandboxInfoByAccount005");

    dlpPermissionService_->waterMarkInfo_.accountAndUserId = "test_watermark_diff_user";

    DlpSandboxInfo differentUserIdInfo;
    differentUserIdInfo.uid = 3305;
    differentUserIdInfo.userId = 200;
    differentUserIdInfo.appIndex = 105;
    differentUserIdInfo.bindAppIndex = 205;
    differentUserIdInfo.tokenId = 3305;
    differentUserIdInfo.bundleName = HIPREVIEW_HIGH;
    differentUserIdInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    differentUserIdInfo.accountName = "different_user_account";
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(differentUserIdInfo);

    DlpSandboxInfo queryInfo;
    bool existsBefore = dlpPermissionService_->appStateObserver_->GetSandboxInfo(differentUserIdInfo.uid, queryInfo);
    ASSERT_TRUE(existsBefore);

    dlpPermissionService_->DelSandboxInfoByAccount(false);

    ASSERT_EQ(dlpPermissionService_->waterMarkInfo_.accountAndUserId, "");

    bool existsAfter = dlpPermissionService_->appStateObserver_->GetSandboxInfo(differentUserIdInfo.uid, queryInfo);
    ASSERT_TRUE(existsAfter);

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(differentUserIdInfo.uid);
}

/**
 * @tc.name: QueryOpenedEnterpriseDlpFiles002
 * @tc.desc: QueryOpenedEnterpriseDlpFiles returns DLP_PARSE_ERROR_BMS_ERROR when GetAppIdentifierForCalling fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, QueryOpenedEnterpriseDlpFiles002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "QueryOpenedEnterpriseDlpFiles002");

    bool backupSuccess = DlpPermissionServiceTest::mockGetAppIdentifierSuccess;
    DlpPermissionServiceTest::mockGetAppIdentifierSuccess = false;

    std::vector<std::string> uris;
    int32_t ret = dlpPermissionService_->QueryOpenedEnterpriseDlpFiles("L1", uris);
    ASSERT_EQ(DLP_PARSE_ERROR_BMS_ERROR, ret);

    DlpPermissionServiceTest::mockGetAppIdentifierSuccess = backupSuccess;
}

/**
 * @tc.name: CloseOpenedEnterpriseDlpFiles002
 * @tc.desc: CloseOpenedEnterpriseDlpFiles returns DLP_PARSE_ERROR_BMS_ERROR when GetAppIdentifierForCalling fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, CloseOpenedEnterpriseDlpFiles002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "CloseOpenedEnterpriseDlpFiles002");

    bool backupSuccess = DlpPermissionServiceTest::mockGetAppIdentifierSuccess;
    DlpPermissionServiceTest::mockGetAppIdentifierSuccess = false;

    int32_t ret = dlpPermissionService_->CloseOpenedEnterpriseDlpFiles("L1");
    ASSERT_EQ(DLP_PARSE_ERROR_BMS_ERROR, ret);

    DlpPermissionServiceTest::mockGetAppIdentifierSuccess = backupSuccess;
}

/**
 * @tc.name: CloseOpenedEnterpriseDlpFiles003
 * @tc.desc: CloseOpenedEnterpriseDlpFiles returns DLP_PARSE_ERROR_BMS_ERROR when UninstallDlpSandboxApp fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, CloseOpenedEnterpriseDlpFiles003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "CloseOpenedEnterpriseDlpFiles003");

    std::string backupIdentifier = DlpPermissionServiceTest::mockAppIdentifier;
    DlpPermissionServiceTest::mockAppIdentifier = CALLER_APP_IDENTIFIER;

    DlpSandboxInfo appInfo;
    appInfo.uid = 1401;
    appInfo.userId = DEFAULT_USERID;
    appInfo.appIndex = 301;
    appInfo.tokenId = 1401;
    appInfo.bundleName = "com.test.uninstall.fail";
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.classificationLabel = "L1";
    appInfo.appIdentifier = CALLER_APP_IDENTIFIER;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);

    int32_t ret = dlpPermissionService_->CloseOpenedEnterpriseDlpFiles("L1");
    ASSERT_EQ(DLP_PARSE_ERROR_BMS_ERROR, ret);

    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    DlpPermissionServiceTest::mockAppIdentifier = backupIdentifier;
}
