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

#ifndef DLP_CONNECTION_STATIC_MOCK_H
#define DLP_CONNECTION_STATIC_MOCK_H

#include "iremote_broker.h"

namespace OHOS {
namespace Security {
namespace DlpConnection {
class IDlpConnectionCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.Security.IDlpConnectionCallback");

    virtual void OnResult(const int32_t errCode, std::string &data) = 0;
};

class IDlpConnectionPlugin : public IRemoteBroker {
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.Security.IDlpConnectionPlugin");

    virtual int32_t ConnectServer(const std::string requestId, const std::string requestData,
        const sptr<IDlpConnectionCallback> &callback) = 0;
};

class DlpConnectionCallback {
public:
    virtual void OnResult(const int32_t errCode, std::string &data) = 0;
};

class DlpConnectionPlugin {
    virtual void ConnectServer(const std::string requestId, const std::string requestData,
        const std::shared_ptr<DlpConnectionCallback> &callback);
};

class DlpConnectionClient {
public:
    static DlpConnectionClient &GetInstance();
    int32_t RegisterPlugin(const std::shared_ptr<DlpConnectionPlugin> &plugin, uint64_t &pluginId);
private:
    DlpConnectionClient();
    ~DlpConnectionClient() = default;
};
} // DlpConnection
} // Security
} // OHOS
#endif // DLP_CONNECTION_STATIC_MOCK_H