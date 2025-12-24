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
#include "parallel_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <vector>
#include <string>

// 假设头文件路径（请按实际项目调整）
#include "dlp_permission_service.h"
#include "dlp_policy_parcel.h"
#include "cert_parcel.h"
#include "dlp_permission_callback_stub.h"
#include "want.h"
#include "dlp_file_access.h"
#include "sandbox_info.h"
#include "retention_sandbox_info.h"
#include "visited_dlp_file_info.h"
#include "dlp_permission_info_parcel.h"

using namespace OHOS;

class MockDlpPermissionCallback : public IDlpPermissionCallback {
public:
    int OnPermissionResult(int32_t result) override { return 0; }
};

static std::string ConsumeString(FuzzedDataProvider& fdp) {
    return fdp.ConsumeRandomLengthString(256);
}

// 单次调用封装（避免 switch 重复）
static void CallInterfaceByIndex(
    const std::shared_ptr<DlpPermissionService>& service,
    FuzzedDataProvider& fdp,
    int index)
{
    switch (index) {
        case 0: {
            sptr<DlpPolicyParcel> policy = new (nothrow) DlpPolicyParcel();
            sptr<MockDlpPermissionCallback> cb = new (nothrow) MockDlpPermissionCallback();
            if (policy && cb) service->GenerateDlpCertificate(policy, cb);
            break;
        }
        case 1: {
            sptr<CertParcel> cert = new (nothrow) CertParcel();
            sptr<MockDlpPermissionCallback> cb = new (nothrow) MockDlpPermissionCallback();
            std::string appId = ConsumeString(fdp);
            bool offline = fdp.ConsumeBool();
            if (cert && cb) service->ParseDlpCertificate(cert, cb, appId, offline);
            break;
        }
        case 2: {
            bool waterMarkConfig = fdp.ConsumeBool();
            sptr<MockDlpPermissionCallback> cb = new (nothrow) MockDlpPermissionCallback();
            if (cb) service->GetWaterMark(waterMarkConfig, cb);
            break;
        }
        case 3: {
            std::string bundleName = ConsumeString(fdp);
            DLPFileAccess dlpFileAccess;
            int32_t userId = fdp.ConsumeIntegral<int32_t>();
            SandboxInfo sandboxInfo;
            std::string uri = ConsumeString(fdp);
            service->InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, uri);
            break;
        }
        case 4: {
            std::string bundleName = ConsumeString(fdp);
            int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
            int32_t userId = fdp.ConsumeIntegral<int32_t>();
            service->UninstallDlpSandbox(bundleName, appIndex, userId);
            break;
        }
        case 5: {
            int32_t sandboxUid = fdp.ConsumeIntegral<int32_t>();
            Want want;
            SandBoxExternalAuthorType authType;
            service->GetSandboxExternalAuthorization(sandboxUid, want, authType);
            break;
        }
        case 6: {
            int32_t pid = fdp.ConsumeIntegral<int32_t>();
            service->SetWaterMark(pid);
            break;
        }
        case 7: {
            bool copyable;
            unsigned int tokenId = fdp.ConsumeIntegral<unsigned int>();
            service->QueryDlpFileCopyableByTokenId(copyable, tokenId);
            break;
        }
        case 8: {
            DLPPermissionInfoParcel permInfoParcel;
            service->QueryDlpFileAccess(permInfoParcel);
            break;
        }
        case 9: {
            bool inSandbox;
            service->IsInDlpSandbox(inSandbox);
            break;
        }
        case 10: {
            std::vector<std::string> supportFileType;
            service->GetDlpSupportFileType(supportFileType);
            break;
        }
        case 11: {
            sptr<IRemoteObject> cb = new (nothrow) IRemoteObject();
            if (cb) service->RegisterDlpSandboxChangeCallback(cb);
            break;
        }
        case 12: {
            bool res;
            service->UnRegisterDlpSandboxChangeCallback(res);
            break;
        }
        case 13: {
            sptr<IRemoteObject> cb = new (nothrow) IRemoteObject();
            if (cb) service->RegisterOpenDlpFileCallback(cb);
            break;
        }
        case 14: {
            sptr<IRemoteObject> cb = new (nothrow) IRemoteObject();
            if (cb) service->UnRegisterOpenDlpFileCallback(cb);
            break;
        }
        case 15: {
            bool isGathering;
            service->GetDlpGatheringPolicy(isGathering);
            break;
        }
        case 16: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 10);
            std::vector<std::string> docUriVec;
            for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
            service->SetRetentionState(docUriVec);
            break;
        }
        case 17: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 10);
            std::vector<std::string> docUriVec;
            for (size_t i = 0; i < n; ++i) docUriVec.push_back(ConsumeString(fdp));
            service->CancelRetentionState(docUriVec);
            break;
        }
        case 18: {
            std::string bundleName = ConsumeString(fdp);
            std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
            service->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
            break;
        }
        case 19: {
            service->ClearUnreservedSandbox();
            break;
        }
        case 20: {
            std::vector<VisitedDLPFileInfo> infoVec;
            service->GetDLPFileVisitRecord(infoVec);
            break;
        }
        case 21: {
            std::string configInfo = ConsumeString(fdp);
            service->SetSandboxAppConfig(configInfo);
            break;
        }
        case 22: {
            service->CleanSandboxAppConfig();
            break;
        }
        case 23: {
            std::string configInfo;
            service->GetSandboxAppConfig(configInfo);
            break;
        }
        case 24: {
            bool isProvideDLPFeature;
            service->IsDLPFeatureProvided(isProvideDLPFeature);
            break;
        }
        case 25: {
            unsigned int dlpFeatureInfo = fdp.ConsumeIntegral<unsigned int>();
            bool statusSetInfo;
            service->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
            break;
        }
        case 26: {
            unsigned int uid = fdp.ConsumeIntegral<unsigned int>();
            service->SetReadFlag(uid);
            break;
        }
        case 27: {
            size_t n = fdp.ConsumeIntegralInRange<size_t>(0, 10);
            std::vector<std::string> appIdList;
            for (size_t i = 0; i < n; ++i) appIdList.push_back(ConsumeString(fdp));
            service->SetMDMPolicy(appIdList);
            break;
        }
        case 28: {
            std::vector<std::string> appIdList;
            service->GetMDMPolicy(appIdList);
            break;
        }
        case 29: {
            service->RemoveMDMPolicy();
            break;
        }
        case 30: {
            std::string policy = ConsumeString(fdp);
            service->SetEnterprisePolicy(policy);
            break;
        }
        case 31: {
            std::string uri = ConsumeString(fdp);
            bool isNotOwnerAndReadOnce = fdp.ConsumeBool();
            service->SetNotOwnerAndReadOnce(uri, isNotOwnerAndReadOnce);
            break;
        }
        default:
            break;
    }
}

void ParallelFuzzTest(const uint8_t* data, size_t size)
{
    if (size < 8) return;

    FuzzedDataProvider fdp(data, size);

    constexpr int SA_ID_DLP_PERMISSION_SERVICE = 1001;
    constexpr int STATUS_NUM = 4;
    auto service = std::make_shared<DlpPermissionService>(
        SA_ID_DLP_PERMISSION_SERVICE,
        static_cast<int>(fdp.ConsumeIntegral<uint8_t>() % STATUS_NUM)
    );
    if (!service) return;

    size_t callCount = fdp.ConsumeIntegralInRange<size_t>(1, 20);

    for (size_t i = 0; i < callCount && fdp.remaining_bytes() > 0; ++i) {
        int methodIndex = fdp.ConsumeIntegralInRange<int>(0, 31); 
        CallInterfaceByIndex(service, fdp, methodIndex);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParallelFuzzTest(data, size);
    return 0;
}
