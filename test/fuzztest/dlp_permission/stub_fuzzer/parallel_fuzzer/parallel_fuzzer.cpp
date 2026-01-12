/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "parallel_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <fcntl.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"

#include "token_setproc.h"
#include "dlp_permission_service.h"
#include "dlp_policy_parcel.h"
#include "cert_parcel.h"
#include "dlp_permission_callback.h"
#include "want.h"
#include "retention_sandbox_info.h"
#include "visited_dlp_file_info.h"
#include "dlp_permission_info_parcel.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
const uint32_t STRING_LENGTH = 10;
const uint32_t BUFFER_LENGTH = 30;
const uint32_t METHOD_NUMBER = 32;
const uint32_t METHOD_NUMBER_GROUP = 8;
enum class DlpPermissionServiceMethod {
    GENERATE_DLP_CERTIFICATE = 0,
    PARSE_DLP_CERTIFICATE,
    GET_WATER_MARK,
    INSTALL_DLP_SANDBOX,
    UNINSTALL_DLP_SANDBOX,
    GET_SANDBOX_EXTERNAL_AUTH,
    SET_WATER_MARK,
    QUERY_DLP_FILE_COPYABLE,
    QUERY_DLP_FILE_ACCESS,
    IS_IN_DLP_SANDBOX,
    GET_DLP_SUPPORT_FILE_TYPE,
    REGISTER_DLP_SANDBOX_CHANGE_CALLBACK,
    UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK,
    REGISTER_OPEN_DLP_FILE_CALLBACK,
    UNREGISTER_OPEN_DLP_FILE_CALLBACK,
    GET_DLP_GATHERING_POLICY,
    SET_RETENTION_STATE,
    CANCEL_RETENTION_STATE,
    GET_RETENTION_SANDBOX_LIST,
    CLEAR_UNRESERVED_SANDBOX,
    GET_DLP_FILE_VISIT_RECORD,
    SET_SANDBOX_APP_CONFIG,
    CLEAN_SANDBOX_APP_CONFIG,
    GET_SANDBOX_APP_CONFIG,
    IS_DLP_FEATURE_PROVIDED,
    SET_DLP_FEATURE,
    SET_READ_FLAG,
    SET_MDM_POLICY,
    GET_MDM_POLICY,
    REMOVE_MDM_POLICY,
    SET_ENTERPRISE_POLICY,
    SET_NOT_OWNER_AND_READ_ONCE
};
enum class DlpPermissionServiceMethodGroup {
    FIRSTGROUP = 0,
    SECONDGROUP,
    THIRDGROUP,
    FOURTHGROUP,
    FIFTHGROUP,
    SIXTHGROUP,
    SEVENTHGROUP,
    EIGHTHGROUP,
};
} // namespace

namespace OHOS {
class DlpFuzzRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.fuzz");
    DlpFuzzRemoteObj() = default;
    virtual ~DlpFuzzRemoteObj() noexcept = default;
};

static std::string ConsumeString(FuzzedDataProvider& fdp)
{
    return fdp.ConsumeBytesAsString(BUFFER_LENGTH);
}

static void CallInterfaceByIndexFirst(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::GENERATE_DLP_CERTIFICATE: {
            sptr<DlpPolicyParcel> policy = new (std::nothrow) DlpPolicyParcel();
            service->GenerateDlpCertificate(policy, callback);
            break;
        }
        case DlpPermissionServiceMethod::PARSE_DLP_CERTIFICATE: {
            sptr<CertParcel> cert = new (std::nothrow) CertParcel();
            std::string appId = ConsumeString(fdp);
            bool offline = fdp.ConsumeBool();
            service->ParseDlpCertificate(cert, callback, appId, offline);
            break;
        }
        case DlpPermissionServiceMethod::GET_WATER_MARK: {
            bool waterMarkConfig = fdp.ConsumeBool();
            service->GetWaterMark(waterMarkConfig, callback);
            break;
        }
        case DlpPermissionServiceMethod::INSTALL_DLP_SANDBOX: {
            std::string bundleName = ConsumeString(fdp);
            DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
            int32_t userId = fdp.ConsumeIntegral<int32_t>();
            SandboxInfo sandboxInfo;
            std::string uri = ConsumeString(fdp);
            service->InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexSecond(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::UNINSTALL_DLP_SANDBOX: {
            std::string bundleName = ConsumeString(fdp);
            int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
            int32_t userId = fdp.ConsumeIntegral<int32_t>();
            service->UninstallDlpSandbox(bundleName, appIndex, userId);
            break;
        }
        case DlpPermissionServiceMethod::GET_SANDBOX_EXTERNAL_AUTH: {
            int32_t sandboxUid = fdp.ConsumeIntegral<int32_t>();
            Want want;
            SandBoxExternalAuthorType authType;
            service->GetSandboxExternalAuthorization(sandboxUid, want, authType);
            break;
        }
        case DlpPermissionServiceMethod::SET_WATER_MARK: {
            int32_t pid = fdp.ConsumeIntegral<int32_t>();
            service->SetWaterMark(pid);
            break;
        }
        case DlpPermissionServiceMethod::QUERY_DLP_FILE_COPYABLE: {
            bool copyable;
            unsigned int tokenId = fdp.ConsumeIntegral<unsigned int>();
            service->QueryDlpFileCopyableByTokenId(copyable, tokenId);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexThird(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::QUERY_DLP_FILE_ACCESS: {
            DLPPermissionInfoParcel permInfoParcel;
            service->QueryDlpFileAccess(permInfoParcel);
            break;
        }
        case DlpPermissionServiceMethod::IS_IN_DLP_SANDBOX: {
            bool inSandbox;
            service->IsInDlpSandbox(inSandbox);
            break;
        }
        case DlpPermissionServiceMethod::GET_DLP_SUPPORT_FILE_TYPE: {
            std::vector<std::string> supportFileType;
            service->GetDlpSupportFileType(supportFileType);
            break;
        }
        case DlpPermissionServiceMethod::REGISTER_DLP_SANDBOX_CHANGE_CALLBACK: {
            service->RegisterDlpSandboxChangeCallback(callbackRemote);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexFourth(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK: {
            bool result;
            service->UnRegisterDlpSandboxChangeCallback(result);
            break;
        }
        case DlpPermissionServiceMethod::REGISTER_OPEN_DLP_FILE_CALLBACK: {
            service->RegisterOpenDlpFileCallback(callbackRemote);
            break;
        }
        case DlpPermissionServiceMethod::UNREGISTER_OPEN_DLP_FILE_CALLBACK: {
            service->UnRegisterOpenDlpFileCallback(callbackRemote);
            break;
        }
        case DlpPermissionServiceMethod::GET_DLP_GATHERING_POLICY: {
            bool isGathering;
            service->GetDlpGatheringPolicy(isGathering);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexFifth(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::SET_RETENTION_STATE: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
            std::vector<std::string> docUriVec;
            for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
            service->SetRetentionState(docUriVec);
            break;
        }
        case DlpPermissionServiceMethod::CANCEL_RETENTION_STATE: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
            std::vector<std::string> docUriVec;
            for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
            service->CancelRetentionState(docUriVec);
            break;
        }
        case DlpPermissionServiceMethod::GET_RETENTION_SANDBOX_LIST: {
            std::string bundleName = ConsumeString(fdp);
            std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
            service->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
            break;
        }
        case DlpPermissionServiceMethod::CLEAR_UNRESERVED_SANDBOX: {
            service->ClearUnreservedSandbox();
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexSixth(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::GET_DLP_FILE_VISIT_RECORD: {
            std::vector<VisitedDLPFileInfo> infoVec;
            service->GetDLPFileVisitRecord(infoVec);
            break;
        }
        case DlpPermissionServiceMethod::SET_SANDBOX_APP_CONFIG: {
            std::string configInfo = ConsumeString(fdp);
            service->SetSandboxAppConfig(configInfo);
            break;
        }
        case DlpPermissionServiceMethod::CLEAN_SANDBOX_APP_CONFIG: {
            service->CleanSandboxAppConfig();
            break;
        }
        case DlpPermissionServiceMethod::GET_SANDBOX_APP_CONFIG: {
            std::string configInfo;
            service->GetSandboxAppConfig(configInfo);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexSeventh(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::IS_DLP_FEATURE_PROVIDED: {
            bool isProvideDLPFeature;
            service->IsDLPFeatureProvided(isProvideDLPFeature);
            break;
        }
        case DlpPermissionServiceMethod::SET_DLP_FEATURE: {
            unsigned int dlpFeatureInfo = fdp.ConsumeIntegral<unsigned int>();
            bool statusSetInfo;
            service->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
            break;
        }
        case DlpPermissionServiceMethod::SET_READ_FLAG: {
            unsigned int uid = fdp.ConsumeIntegral<unsigned int>();
            service->SetReadFlag(uid);
            break;
        }
        case DlpPermissionServiceMethod::SET_MDM_POLICY: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, STRING_LENGTH);
            std::vector<std::string> appIdList;
            for (size_t i = 0; i < n; ++i) appIdList.push_back(ConsumeString(fdp));
            service->SetMDMPolicy(appIdList);
            break;
        }
        default:
            break;
    }
}

static void CallInterfaceByIndexEighth(FuzzedDataProvider& fdp, int index)
{
    DlpPermissionServiceMethod newMethod = static_cast<DlpPermissionServiceMethod>(index);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    sptr<DlpFuzzRemoteObj> callback2 = new (std::nothrow) IRemoteStub<DlpFuzzRemoteObj>();
    sptr<IDlpPermissionCallback> callback = iface_cast<IDlpPermissionCallback>(callback2->AsObject());
    sptr<IRemoteObject> callbackRemote;
    switch (newMethod) {
        case DlpPermissionServiceMethod::GET_MDM_POLICY: {
            std::vector<std::string> appIdList;
            service->GetMDMPolicy(appIdList);
            break;
        }
        case DlpPermissionServiceMethod::REMOVE_MDM_POLICY: {
            service->RemoveMDMPolicy();
            break;
        }
        case DlpPermissionServiceMethod::SET_ENTERPRISE_POLICY: {
            std::string policy = ConsumeString(fdp);
            service->SetEnterprisePolicy(policy);
            break;
        }
        case DlpPermissionServiceMethod::SET_NOT_OWNER_AND_READ_ONCE: {
            FileInfo fileInfo;
            std::string uri = ConsumeString(fdp);
            fileInfo.isNotOwnerAndReadOnce = fdp.ConsumeBool();
            service->SetFileInfo(uri, fileInfo);
            break;
        }
        default:
            break;
    }
}
void ParallelFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    size_t callCount = fdp.ConsumeIntegral<size_t>() % METHOD_NUMBER + 1;
    for (size_t i = 0; i < callCount && fdp.remaining_bytes() > 0; ++i) {
        int methodIndex = fdp.ConsumeIntegral<int>() % METHOD_NUMBER;
        switch (static_cast<DlpPermissionServiceMethodGroup>(methodIndex / METHOD_NUMBER_GROUP)) {
            case DlpPermissionServiceMethodGroup::FIRSTGROUP: {
                CallInterfaceByIndexFirst(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::SECONDGROUP: {
                CallInterfaceByIndexSecond(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::THIRDGROUP: {
                CallInterfaceByIndexThird(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::FOURTHGROUP: {
                CallInterfaceByIndexFourth(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::FIFTHGROUP: {
                CallInterfaceByIndexFifth(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::SIXTHGROUP: {
                CallInterfaceByIndexSixth(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::SEVENTHGROUP: {
                CallInterfaceByIndexSeventh(fdp, methodIndex);
                break;
            }
            case DlpPermissionServiceMethodGroup::EIGHTHGROUP: {
                CallInterfaceByIndexEighth(fdp, methodIndex);
                break;
            }
            default: {
                break;
            }
        }
    }
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