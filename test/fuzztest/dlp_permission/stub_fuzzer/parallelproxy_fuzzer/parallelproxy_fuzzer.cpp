/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "parallelproxy_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "securec.h"
#include "token_setproc.h"
#include "dlp_permission_service_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "iremote_stub.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
const uint32_t STRING_LENGTH = 10;
const uint32_t BUFFER_LENGTH = 30;
}


namespace OHOS {
class DlpFuzzRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.fuzz");
    DlpFuzzRemoteObj() = default;
    virtual ~DlpFuzzRemoteObj() noexcept = default;
};

static sptr<IDlpPermissionService> GetProxy()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return nullptr;
    }
    auto remoteObj = samgr->GetSystemAbility(SA_ID_DLP_PERMISSION_SERVICE);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    return iface_cast<IDlpPermissionService>(remoteObj);
}

static std::string ConsumeString(FuzzedDataProvider& fdp)
{
    return fdp.ConsumeBytesAsString(BUFFER_LENGTH);
}

// Individual Interface Functions
static void FuzzGenerateDlpCertificate(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    sptr<DlpPolicyParcel> policy = new (std::nothrow) DlpPolicyParcel();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    proxy->GenerateDlpCertificate(policy, callback);
}

static void FuzzParseDlpCertificate(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    sptr<CertParcel> cert = new (std::nothrow) CertParcel();
    std::string appId = ConsumeString(fdp);
    bool offline = fdp.ConsumeBool();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    proxy->ParseDlpCertificate(cert, callback, appId, offline);
}

static void FuzzGetWaterMark(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    bool waterMarkConfig = fdp.ConsumeBool();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    proxy->GetWaterMark(waterMarkConfig, callback);
}

static void FuzzInstallDlpSandbox(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::string bundleName = ConsumeString(fdp);
    DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    SandboxInfo sandboxInfo;
    std::string uri = ConsumeString(fdp);
    proxy->InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
}

static void FuzzUninstallDlpSandbox(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::string bundleName = ConsumeString(fdp);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    proxy->UninstallDlpSandbox(bundleName, appIndex, userId);
}

static void FuzzGetSandboxExternalAuth(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    int32_t sandboxUid = fdp.ConsumeIntegral<int32_t>();
    OHOS::AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    proxy->GetSandboxExternalAuthorization(sandboxUid, want, authType);
}

static void FuzzSetWaterMark(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    proxy->SetWaterMark(pid);
}

static void FuzzQueryDlpFileCopyable(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    bool copyable;
    unsigned int tokenId = fdp.ConsumeIntegral<unsigned int>();
    proxy->QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

static void FuzzQueryDlpFileAccess(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    DLPPermissionInfoParcel permInfoParcel;
    proxy->QueryDlpFileAccess(permInfoParcel);
}

static void FuzzIsInDlpSandbox(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    bool inSandbox;
    proxy->IsInDlpSandbox(inSandbox);
}

static void FuzzGetDlpSupportFileType(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    std::vector<std::string> supportFileType;
    proxy->GetDlpSupportFileType(supportFileType);
}

static void FuzzRegisterDlpSandboxChangeCallback(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> callbackRemote;
    proxy->RegisterDlpSandboxChangeCallback(callbackRemote);
}

static void FuzzUnRegisterDlpSandboxChangeCallback(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    bool result;
    proxy->UnRegisterDlpSandboxChangeCallback(result);
}

static void FuzzRegisterOpenDlpFileCallback(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> callbackRemote;
    proxy->RegisterOpenDlpFileCallback(callbackRemote);
}

static void FuzzUnRegisterOpenDlpFileCallback(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> callbackRemote;
    proxy->UnRegisterOpenDlpFileCallback(callbackRemote);
}

static void FuzzGetDlpGatheringPolicy(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    bool isGathering;
    proxy->GetDlpGatheringPolicy(isGathering);
}

static void FuzzSetRetentionState(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
    std::vector<std::string> docUriVec;
    for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
    proxy->SetRetentionState(docUriVec);
}

static void FuzzCancelRetentionState(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
    std::vector<std::string> docUriVec;
    for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
    proxy->CancelRetentionState(docUriVec);
}

static void FuzzGetRetentionSandboxList(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::string bundleName = ConsumeString(fdp);
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    proxy->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
}

static void FuzzClearUnreservedSandbox(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    proxy->ClearUnreservedSandbox();
}

static void FuzzGetDlpFileVisitRecord(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    std::vector<VisitedDLPFileInfo> infoVec;
    proxy->GetDLPFileVisitRecord(infoVec);
}

static void FuzzSetSandboxAppConfig(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::string configInfo = ConsumeString(fdp);
    proxy->SetSandboxAppConfig(configInfo);
}

static void FuzzCleanSandboxAppConfig(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    proxy->CleanSandboxAppConfig();
}

static void FuzzGetSandboxAppConfig(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    std::string configInfo;
    proxy->GetSandboxAppConfig(configInfo);
}

static void FuzzIsDLPFeatureProvided(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    bool isProvideDLPFeature;
    proxy->IsDLPFeatureProvided(isProvideDLPFeature);
}

static void FuzzSetDlpFeature(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    unsigned int dlpFeatureInfo = fdp.ConsumeIntegral<unsigned int>();
    bool statusSetInfo;
    proxy->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
}

static void FuzzSetReadFlag(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    unsigned int uid = fdp.ConsumeIntegral<unsigned int>();
    proxy->SetReadFlag(uid);
}

static void FuzzSetMDMPolicy(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
    std::vector<std::string> appIdList;
    for (size_t i = 0; i < n; ++i) appIdList.push_back(ConsumeString(fdp));
    proxy->SetMDMPolicy(appIdList);
}

static void FuzzGetMDMPolicy(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void) fdp;
    if (proxy == nullptr) {
        return;
    }
    std::vector<std::string> appIdList;
    proxy->GetMDMPolicy(appIdList);
}

static void FuzzRemoveMDMPolicy(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    proxy->RemoveMDMPolicy();
}

static void FuzzSetEnterprisePolicy(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::string policy = ConsumeString(fdp);
    proxy->SetEnterprisePolicy(policy);
}

static void FuzzSetNotOwnerAndReadOnce(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    FileInfo fileInfo;
    std::string uri = ConsumeString(fdp);
    fileInfo.isNotOwnerAndReadOnce = fdp.ConsumeBool();
    proxy->SetFileInfo(uri, fileInfo);
}
static void FuzzGetAbilityInfos(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    if (proxy == nullptr) {
        return;
    }
    std::vector<std::string> appIdList;
    OHOS::AAFwk::Want want;
    int32_t flags = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    proxy->GetAbilityInfos(want, flags, userId, abilityInfos);
}

static void FuzzGetDomainAccountNameInfo(FuzzedDataProvider& fdp, sptr<IDlpPermissionService> proxy)
{
    (void)fdp;
    if (proxy == nullptr) {
        return;
    }
    std::string accountNameInfo;
    proxy->GetDomainAccountNameInfo(accountNameInfo);
}

void ParallelFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    sptr<IDlpPermissionService> proxy = GetProxy();
    if (proxy == nullptr) {
        return;
    }

    // Sequential call of all interfaces
    FuzzGenerateDlpCertificate(fdp, proxy);
    FuzzParseDlpCertificate(fdp, proxy);
    FuzzGetWaterMark(fdp, proxy);
    FuzzInstallDlpSandbox(fdp, proxy);
    FuzzUninstallDlpSandbox(fdp, proxy);
    FuzzGetSandboxExternalAuth(fdp, proxy);
    FuzzSetWaterMark(fdp, proxy);
    FuzzQueryDlpFileCopyable(fdp, proxy);
    FuzzQueryDlpFileAccess(fdp, proxy);
    FuzzIsInDlpSandbox(fdp, proxy);
    FuzzGetDlpSupportFileType(fdp, proxy);
    FuzzRegisterDlpSandboxChangeCallback(fdp, proxy);
    FuzzUnRegisterDlpSandboxChangeCallback(fdp, proxy);
    FuzzRegisterOpenDlpFileCallback(fdp, proxy);
    FuzzUnRegisterOpenDlpFileCallback(fdp, proxy);
    FuzzGetDlpGatheringPolicy(fdp, proxy);
    FuzzSetRetentionState(fdp, proxy);
    FuzzCancelRetentionState(fdp, proxy);
    FuzzGetRetentionSandboxList(fdp, proxy);
    FuzzClearUnreservedSandbox(fdp, proxy);
    FuzzGetDlpFileVisitRecord(fdp, proxy);
    FuzzSetSandboxAppConfig(fdp, proxy);
    FuzzCleanSandboxAppConfig(fdp, proxy);
    FuzzGetSandboxAppConfig(fdp, proxy);
    FuzzIsDLPFeatureProvided(fdp, proxy);
    FuzzSetDlpFeature(fdp, proxy);
    FuzzSetReadFlag(fdp, proxy);
    FuzzSetMDMPolicy(fdp, proxy);
    FuzzGetMDMPolicy(fdp, proxy);
    FuzzRemoveMDMPolicy(fdp, proxy);
    FuzzSetEnterprisePolicy(fdp, proxy);
    FuzzSetNotOwnerAndReadOnce(fdp, proxy);
    FuzzGetAbilityInfos(fdp, proxy);
    FuzzGetDomainAccountNameInfo(fdp, proxy);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParallelFuzzTest(data, size);
    return 0;
}
