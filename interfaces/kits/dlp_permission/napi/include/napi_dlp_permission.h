/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H
#define INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H

#include "dlp_permission_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "parcel.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static thread_local napi_ref dlpFileRef_;
const std::string DLP_FILE_CLASS_NAME = "dlpFile";
const int STRING_LEN_LIMIT = 1024;

class NapiDlpPermission {
public:
    static napi_value Init(napi_env env, napi_value exports);

private:
    static void InitFunction(napi_env env, napi_value exports);

    static napi_value JsConstructor(napi_env env, napi_callback_info cbinfo);
    static napi_value DlpFile(napi_env env, napi_callback_info cbInfo);
    static bool IsSystemApp(napi_env env);

    static void GenerateDlpFileExcute(napi_env env, void* data);
    static void GenerateDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value GenerateDlpFile(napi_env env, napi_callback_info cbInfo);

    static void OpenDlpFileExcute(napi_env env, void* data);
    static void OpenDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value OpenDlpFile(napi_env env, napi_callback_info cbInfo);

    static void IsDlpFileExcute(napi_env env, void* data);
    static void IsDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value IsDlpFile(napi_env env, napi_callback_info cbInfo);

    static void AddDlpLinkFileExcute(napi_env env, void* data);
    static void AddDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value AddDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void StopDlpLinkFileExcute(napi_env env, void* data);
    static void StopDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value StopDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void ReplaceDlpLinkFileExcute(napi_env env, void* data);
    static void ReplaceDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value ReplaceDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void RestartDlpLinkFileExcute(napi_env env, void* data);
    static void RestartDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value RestartDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void DeleteDlpLinkFileExcute(napi_env env, void* data);
    static void DeleteDlpLinkFileComplete(napi_env env, napi_status status, void* data);
    static napi_value DeleteDlpLinkFile(napi_env env, napi_callback_info cbInfo);

    static void RecoverDlpFileExcute(napi_env env, void* data);
    static void RecoverDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value RecoverDlpFile(napi_env env, napi_callback_info cbInfo);

    static void CloseDlpFileExcute(napi_env env, void* data);
    static void CloseDlpFileComplete(napi_env env, napi_status status, void* data);
    static napi_value CloseDlpFile(napi_env env, napi_callback_info cbInfo);

    static void InstallDlpSandboxExcute(napi_env env, void* data);
    static void InstallDlpSandboxComplete(napi_env env, napi_status status, void* data);
    static napi_value InstallDlpSandbox(napi_env env, napi_callback_info cbInfo);

    static void UninstallDlpSandboxExcute(napi_env env, void* data);
    static void UninstallDlpSandboxComplete(napi_env env, napi_status status, void* data);
    static napi_value UninstallDlpSandbox(napi_env env, napi_callback_info cbInfo);

    static void GetDLPPermissionInfoExcute(napi_env env, void* data);
    static void GetDLPPermissionInfoComplete(napi_env env, napi_status status, void* data);
    static napi_value GetDLPPermissionInfo(napi_env env, napi_callback_info cbInfo);

    static void IsInSandboxExcute(napi_env env, void* data);
    static void IsInSandboxComplete(napi_env env, napi_status status, void* data);
    static napi_value IsInSandbox(napi_env env, napi_callback_info cbInfo);

    static napi_value GetDLPSuffix(napi_env env, napi_callback_info cbInfo);

    static napi_value GetOriginalFileName(napi_env env, napi_callback_info cbInfo);

    static void GetDlpSupportFileTypeExcute(napi_env env, void* data);
    static void GetDlpSupportFileTypeComplete(napi_env env, napi_status status, void* data);
    static napi_value GetDlpSupportFileType(napi_env env, napi_callback_info cbInfo);

    static napi_value RegisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo);
    static napi_value UnregisterSandboxChangeCallback(napi_env env, napi_callback_info cbInfo);

    static napi_value Subscribe(napi_env env, napi_callback_info cbInfo);
    static napi_value UnSubscribe(napi_env env, napi_callback_info cbInfo);
    static napi_value SubscribeOpenDlpFile(const napi_env env, const napi_value thisVar, napi_ref &callback);
    static napi_value UnSubscribeOpenDlpFile(const napi_env env, napi_ref &callback);

    static void GetDlpGatheringPolicyExcute(napi_env env, void* data);
    static void GetDlpGatheringPolicyComplete(napi_env env, napi_status status, void* data);
    static napi_value GetDlpGatheringPolicy(napi_env env, napi_callback_info cbInfo);

    static void SetRetentionStateExcute(napi_env env, void* data);
    static void SetRetentionStateComplete(napi_env env, napi_status status, void* data);
    static napi_value SetRetentionState(napi_env env, napi_callback_info cbInfo);

    static void CancelRetentionStateExcute(napi_env env, void* data);
    static void CancelRetentionStateComplete(napi_env env, napi_status status, void* data);
    static napi_value CancelRetentionState(napi_env env, napi_callback_info cbInfo);

    static void GetRetentionSandboxListExcute(napi_env env, void* data);
    static void GetRetentionSandboxListComplete(napi_env env, napi_status status, void* data);
    static napi_value GetRetentionSandboxList(napi_env env, napi_callback_info cbInfo);

    static void GetDLPFileVisitRecordExcute(napi_env env, void* data);
    static void GetDLPFileVisitRecordComplete(napi_env env, napi_status status, void* data);
    static napi_value GetDLPFileVisitRecord(napi_env env, napi_callback_info cbInfo);

    static void SetSandboxAppConfigExecute(napi_env env, void* data);
    static void SetSandboxAppConfigComplete(napi_env env, napi_status status, void* data);
    static napi_value SetSandboxAppConfig(napi_env env, napi_callback_info cbInfo);

    static void CleanSandboxAppConfigExecute(napi_env env, void* data);
    static void CleanSandboxAppConfigComplete(napi_env env, napi_status status, void* data);
    static napi_value CleanSandboxAppConfig(napi_env env, napi_callback_info cbInfo);

    static void GetSandboxAppConfigExecute(napi_env env, void* data);
    static void GetSandboxAppConfigComplete(napi_env env, napi_status status, void* data);
    static napi_value GetSandboxAppConfig(napi_env env, napi_callback_info cbInfo);

    static napi_value StartDLPManagerForResult(napi_env env, napi_callback_info cbInfo);

    static napi_value IsDLPFeatureProvided(napi_env env, napi_callback_info cbInfo);
    static void IsDLPFeatureProvidedExcute(napi_env env, void* data);
    static void IsDLPFeatureProvidedComplete(napi_env env, napi_status status, void* data);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
/*
 * function for module exports
 */
static napi_value Init(napi_env env, napi_value exports);

#endif /*  INTERFACES_KITS_DLP_PERMISSION_NAPI_INCLUDE_NAPI_H */
