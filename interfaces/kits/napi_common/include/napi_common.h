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

#ifndef INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H
#define INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H

#include <vector>
#include <unistd.h>
#include <uv.h>

#include "ability_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_base_context.h"
#include "napi_common_want.h"
#include "dlp_file.h"
#include "dlp_sandbox_callback_info.h"
#include "dlp_sandbox_change_callback_customize.h"
#include "open_dlp_file_callback_customize.h"
#include "permission_policy.h"
#include "retention_sandbox_info.h"
#include "ui_content.h"
#include "visited_dlp_file_info.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM4 = 4;
constexpr int32_t PARAM_SIZE_ONE = 1;
constexpr int32_t PARAM_SIZE_TWO = 2;
constexpr int32_t PARAM_SIZE_THREE = 3;
constexpr int32_t PARAM_SIZE_FOUR = 4;
constexpr int32_t PARAM_SIZE_FIVE = 5;
const std::string ON_OFF_SANDBOX = "uninstallDLPSandbox";

#define NAPI_CALL_BASE_WITH_SCOPE(env, theCall, retVal, scope) \
    do {                                                       \
        if ((theCall) != napi_ok) {                            \
            GET_AND_THROW_LAST_ERROR((env));                   \
            napi_close_handle_scope(env, scope);               \
            return retVal;                                     \
        }                                                      \
    } while (0)

#define NAPI_CALL_RETURN_VOID_WITH_SCOPE(env, theCall, scope) \
    NAPI_CALL_BASE_WITH_SCOPE(env, theCall, NAPI_RETVAL_NOTHING, scope)

class RegisterDlpSandboxChangeScopePtr : public DlpSandboxChangeCallbackCustomize {
public:
    RegisterDlpSandboxChangeScopePtr();
    ~RegisterDlpSandboxChangeScopePtr() override;
    void DlpSandboxChangeCallback(DlpSandboxCallbackInfo &result) override;
    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);
    void SetValid(bool valid);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    bool valid_ = true;
    std::mutex validMutex_;
};

struct CommonAsyncContext {
    explicit CommonAsyncContext(napi_env napiEnv);
    virtual ~CommonAsyncContext();
    napi_env env = nullptr;
    napi_status status = napi_invalid_arg;
    int32_t errCode = 0;
    napi_deferred deferred = nullptr;  // promise handle
    napi_ref callbackRef = nullptr;    // callback handle
    napi_async_work work = nullptr;    // work handle
};

struct RegisterDlpSandboxChangeWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    DlpSandboxCallbackInfo result;
    RegisterDlpSandboxChangeScopePtr *subscriber = nullptr;
};

struct DlpSandboxChangeContext {
    virtual ~DlpSandboxChangeContext();
    napi_env env = nullptr;
    napi_ref callbackRef = nullptr;
    int32_t errCode = 0;
    std::string changeType;
    std::shared_ptr<RegisterDlpSandboxChangeScopePtr> subscriber = nullptr;
    void DeleteNapiRef();
};

typedef DlpSandboxChangeContext RegisterDlpSandboxChangeInfo;

struct UnregisterSandboxChangeCallbackAsyncContext : public CommonAsyncContext {
    explicit UnregisterSandboxChangeCallbackAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    bool result = false;
    std::string changeType;
};
class OpenDlpFileSubscriberPtr : public OpenDlpFileCallbackCustomize {
public:
    OpenDlpFileSubscriberPtr();
    ~OpenDlpFileSubscriberPtr() override;
    void OnOpenDlpFile(OpenDlpFileCallbackInfo &result) override;
    void SetEnv(const napi_env &env);
    void SetCallbackRef(const napi_ref &ref);
    void SetValid(bool valid);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    bool valid_ = true;
    std::mutex validMutex_;
};

struct OpenDlpFileSubscriberWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    OpenDlpFileCallbackInfo result;
    OpenDlpFileSubscriberPtr *subscriber = nullptr;
};

struct OpenDlpFileSubscriberContext {
    virtual ~OpenDlpFileSubscriberContext();
    napi_env env = nullptr;
    napi_ref callbackRef = nullptr;
    int32_t errCode = 0;
    std::shared_ptr<OpenDlpFileSubscriberPtr> subscriber = nullptr;
    void DeleteNapiRef();
};

struct OpenDlpFileUnSubscriberContext : public CommonAsyncContext {
    explicit OpenDlpFileUnSubscriberContext(napi_env env) : CommonAsyncContext(env) {};
    bool result = false;
};

struct GenerateDlpFileAsyncContext : public CommonAsyncContext {
    explicit GenerateDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    int64_t plaintextFd = -1;
    int64_t ciphertextFd = -1;
    DlpProperty property;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct DlpFileAsyncContext : public CommonAsyncContext {
    explicit DlpFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    int64_t ciphertextFd = -1;
    std::string appId;
    DlpProperty property;
    bool isDlpFile = false;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct DlpLinkFileAsyncContext : public CommonAsyncContext {
    explicit DlpLinkFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string linkFileName = "";
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct RecoverDlpFileAsyncContext : public CommonAsyncContext {
    explicit RecoverDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    int64_t plaintextFd = -1;
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct CloseDlpFileAsyncContext : public CommonAsyncContext {
    explicit CloseDlpFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::shared_ptr<DlpFile> dlpFileNative = nullptr;
};

struct DlpSandboxAsyncContext : public CommonAsyncContext {
    explicit DlpSandboxAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string bundleName;
    DLPFileAccess dlpFileAccess = NO_PERMISSION;
    int32_t userId = -1;
    SandboxInfo sandboxInfo;
    std::string uri = "";
};

struct GetPermInfoAsyncContext : public CommonAsyncContext {
    explicit GetPermInfoAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    DLPPermissionInfo permInfo;
};

struct IsInSandboxAsyncContext : public CommonAsyncContext {
    explicit IsInSandboxAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    bool inSandbox = false;
};

struct IsDLPFeatureProvidedAsyncContext : public CommonAsyncContext {
    explicit IsDLPFeatureProvidedAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    bool isProvideDLPFeature = false;
};

struct GetOriginalFileAsyncContext : public CommonAsyncContext {
    explicit GetOriginalFileAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string dlpFilename = "";
    std::string oriFilename = "";
};

struct GetSuffixAsyncContext : public CommonAsyncContext {
    explicit GetSuffixAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string extension = "";
};

struct GetDlpSupportFileTypeAsyncContext : public CommonAsyncContext {
    explicit GetDlpSupportFileTypeAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::vector<std::string> supportFileType;
};

void UvQueueWorkDeleteRef(uv_work_t *work, int32_t status);

struct GetGatheringPolicyContext : public CommonAsyncContext {
    explicit GetGatheringPolicyContext(napi_env env) : CommonAsyncContext(env) {};
    bool isGathering = false;
};

struct RetentionStateAsyncContext : public CommonAsyncContext {
    explicit RetentionStateAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::vector<std::string> docUris;
};

struct GetRetentionSandboxListAsyncContext : public CommonAsyncContext {
    explicit GetRetentionSandboxListAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string bundleName = "";
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
};

struct GetDLPFileVisitRecordAsyncContext : public CommonAsyncContext {
    explicit GetDLPFileVisitRecordAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::vector<VisitedDLPFileInfo> visitedDlpFileInfoVec;
};

struct SandboxAppConfigAsyncContext : public CommonAsyncContext {
    explicit SandboxAppConfigAsyncContext(napi_env env) : CommonAsyncContext(env) {};
    std::string configInfo = "";
};

struct UIExtensionRequestContext : public CommonAsyncContext {
    explicit UIExtensionRequestContext(napi_env env) : CommonAsyncContext(env) {};
    std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> context = nullptr;
    OHOS::AAFwk::Want requestWant;
};

class UIExtensionCallback {
public:
    explicit UIExtensionCallback(std::shared_ptr<UIExtensionRequestContext>& reqContext);
    void SetSessionId(int32_t sessionId);
    void OnRelease(int32_t releaseCode);
    void OnResult(int32_t resultCode, const OHOS::AAFwk::Want& result);
    void OnReceive(const OHOS::AAFwk::WantParams& request);
    void OnError(int32_t code, const std::string& name, const std::string& message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy);
    void OnDestroy();
    void SendMessageBack();

private:
    bool SetErrorCode(int32_t code);
    int32_t sessionId_ = 0;
    int32_t resultCode_ = 0;
    OHOS::AAFwk::Want resultWant_;
    std::shared_ptr<UIExtensionRequestContext> reqContext_ = nullptr;
    bool alreadyCallback_ = false;
};

void ThrowParamError(const napi_env env, const std::string& param, const std::string& type);
void DlpNapiThrow(napi_env env, int32_t nativeErrCode);
void DlpNapiThrow(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg);
napi_value GenerateBusinessError(napi_env env, int32_t jsErrCode, const std::string &jsErrMsg);
bool NapiCheckArgc(const napi_env env, int32_t argc, int32_t reqSize);

napi_value CreateEnumDLPFileAccess(napi_env env);
napi_value CreateEnumAccountType(napi_env env);
napi_value CreateEnumActionFlags(napi_env env);
napi_value CreateEnumGatheringPolicy(napi_env env);

void ProcessCallbackOrPromise(napi_env env, const CommonAsyncContext* asyncContext, napi_value data);

bool GetGenerateDlpFileParams(
    const napi_env env, const napi_callback_info info, GenerateDlpFileAsyncContext& asyncContext);
bool GetOpenDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext);
bool GetIsDlpFileParams(const napi_env env, const napi_callback_info info, DlpFileAsyncContext& asyncContext);

bool GetDlpLinkFileParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext);
bool GetLinkFileStatusParams(const napi_env env, const napi_callback_info info, DlpLinkFileAsyncContext& asyncContext);
bool GetRecoverDlpFileParams(
    const napi_env env, const napi_callback_info info, RecoverDlpFileAsyncContext& asyncContext);
bool GetCloseDlpFileParams(const napi_env env, const napi_callback_info info, CloseDlpFileAsyncContext& asyncContext);
bool GetInstallDlpSandboxParams(
    const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext);
bool GetUninstallDlpSandboxParams(
    const napi_env env, const napi_callback_info info, DlpSandboxAsyncContext& asyncContext);
bool GetThirdInterfaceParams(
    const napi_env env, const napi_callback_info info, CommonAsyncContext& asyncContext);

bool FillDlpSandboxChangeInfo(const napi_env env, const napi_value* argv, const std::string& type,
    const napi_value thisVar, RegisterDlpSandboxChangeInfo& registerSandboxChangeInfo);
bool ParseInputToRegister(const napi_env env, const napi_callback_info cbInfo,
    RegisterDlpSandboxChangeInfo &registerSandboxChangeInfo);
bool GetUnregisterSandboxParams(const napi_env env, const napi_callback_info info,
    UnregisterSandboxChangeCallbackAsyncContext &asyncContext);
bool GetRetentionStateParams(const napi_env env, const napi_callback_info info,
    RetentionStateAsyncContext& asyncContext);
bool GetRetentionSandboxListParams(const napi_env env, const napi_callback_info info,
    GetRetentionSandboxListAsyncContext& asyncContext);
bool GetOriginalFilenameParams(const napi_env env, const napi_callback_info info,
    GetOriginalFileAsyncContext& asyncContext);
bool GetSandboxAppConfigParams(const napi_env env, const napi_callback_info info,
    SandboxAppConfigAsyncContext* asyncContext);
void GetDlpPropertyExpireTime(napi_env env, napi_value jsObject, DlpProperty& property);
bool GetDlpProperty(napi_env env, napi_value object, DlpProperty& property);
bool ParseCallback(const napi_env& env, const napi_value& value, napi_ref& callbackRef);

napi_value GetNapiValue(napi_env env, napi_value jsObject, const std::string& key);
bool GetStringValue(napi_env env, napi_value jsObject, std::string& result);
bool GetStringValueByKey(napi_env env, napi_value jsObject, const std::string& key, std::string& result);
bool GetBoolValueByKey(napi_env env, napi_value jsObject, const std::string& key, bool& result);
bool GetBoolValue(napi_env env, napi_value jsObject, bool& result);
bool GetInt64Value(napi_env env, napi_value jsObject, int64_t& result);
bool GetInt64ValueByKey(napi_env env, napi_value jsObject, const std::string& key, int64_t& result);
bool GetUint32Value(napi_env env, napi_value jsObject, uint32_t& result);
bool GetUint32ValueByKey(napi_env env, napi_value jsObject, const std::string& key, uint32_t& result);
napi_value GetArrayValueByKey(napi_env env, napi_value jsObject, const std::string& key);
bool GetVectorAuthUser(napi_env env, napi_value jsObject, std::vector<AuthUserInfo>& resultVec);
bool GetVectorAuthUserByKey(
    napi_env env, napi_value jsObject, const std::string& key, std::vector<AuthUserInfo>& resultVec);
bool GetVectorDocUriByKey(napi_env env, napi_value jsObject, const std::string& key,
    std::vector<std::string>& docUriVec);
napi_value VectorUint32ToJs(napi_env env, const std::vector<uint32_t>& value);
bool GetVectorUint32(napi_env env, napi_value jsObject, std::vector<uint32_t>& resultVec);

napi_value RetentionSandboxInfoToJs(napi_env env, const std::vector<RetentionSandBoxInfo>& infoVec);
napi_value VisitInfoToJs(napi_env env, const std::vector<VisitedDLPFileInfo>& infoVec);
napi_value DlpPropertyToJs(napi_env env, const DlpProperty& property);
napi_value VectorAuthUserToJs(napi_env env, const std::vector<AuthUserInfo>& users);
napi_value VectorStringToJs(napi_env env, const std::vector<std::string>& value);
napi_value SetStringToJs(napi_env env, const std::set<std::string>& value);
napi_value DlpPermissionInfoToJs(napi_env env, const DLPPermissionInfo& permInfo);
napi_value SandboxInfoToJs(napi_env env, const SandboxInfo& sandboxInfo);

bool ParseUIAbilityContextReq(
    napi_env env, const napi_value& obj, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext);
bool ParseWantReq(napi_env env, const napi_value& obj, OHOS::AAFwk::Want& requestWant);
void StartUIExtensionAbility(std::shared_ptr<UIExtensionRequestContext> asyncContext);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_KITS_NAPI_COMMON_INCLUDE_NAPI_H */
