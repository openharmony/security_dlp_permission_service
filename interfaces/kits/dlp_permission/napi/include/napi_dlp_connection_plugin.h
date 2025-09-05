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

#ifndef INTERFACES_KITS_NAPI_DLP_CONNECTION_PLUGIN_H
#define INTERFACES_KITS_NAPI_DLP_CONNECTION_PLUGIN_H

#include "dlp_permission_callback.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "parcel.h"
#include "permission_policy.h"
#include "napi_common.h"

#ifdef SUPPORT_DLP_CREDENTIAL
#include "dlp_connection_callback.h"
#include "dlp_connection_plugin.h"
#include "dlp_connection_client.h"
#else
#include "dlp_connection_static_mock.h"
#endif

namespace OHOS {
namespace Security {
namespace DlpConnection {

struct ThreadLockInfo {
    std::mutex mutex;
    std::condition_variable condition;
    int32_t count = 0;
};

struct JsDlpConnPlugin {
    napi_ref funcRef = nullptr;
    napi_ref context = nullptr;
};

struct CommonAsyncContextPlugin {
    CommonAsyncContextPlugin() {};
    CommonAsyncContextPlugin(napi_env napiEnv, bool throwAble = false) : env(napiEnv), throwErr(throwAble) {}
    napi_env env = nullptr;
    napi_deferred deferred = nullptr;  // promise handle
    napi_ref callbackRef = nullptr;    // callback handle
    napi_async_work work = nullptr;    // work handle
    napi_status status = napi_invalid_arg;
    ErrCode errcode = ERR_OK;
    std::string errMsg;
    bool throwErr = false;
};

struct JsDlpConnectionParam : public CommonAsyncContextPlugin {
    JsDlpConnectionParam(napi_env napiEnv) : CommonAsyncContextPlugin(napiEnv) {}
    napi_ref func = nullptr;
    napi_ref context = nullptr;
    std::shared_ptr<DlpConnectionCallback> callback = nullptr;
    ThreadLockInfo *lockInfo = nullptr;
    std::string requestId = "";
    std::string requestData = "";
};

class NapiDlpConnectionPlugin final: public DlpConnectionPlugin {
public:
    NapiDlpConnectionPlugin(napi_env env, const JsDlpConnPlugin &jsPlugin);
    ~NapiDlpConnectionPlugin();

    void ConnectServer(const std::string requestId, const std::string requestData,
        const std::shared_ptr<DlpConnectionCallback> &callback) override;
private:
    napi_env env_ = nullptr;
    JsDlpConnPlugin jsPlugin_;
    ThreadLockInfo lockInfo_;
};

napi_value ProcessEnterpriseAccount(napi_env env, napi_callback_info cbInfo);
napi_value InitDlpConnectFunction(napi_env env, napi_value exports);
}  // namespace DlpConnection
}  // namespace Security
}  // namespace OHOS

#endif /*  INTERFACES_KITS_NAPI_DLP_CONNECTION_PLUGIN_H */
