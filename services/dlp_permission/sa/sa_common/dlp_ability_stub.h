/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef DLP_ABILITY_STUB_H
#define DLP_ABILITY_STUB_H

#include <mutex>
#include <string>
#include <iremote_stub.h>

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace OHOS;

typedef int32_t(*ReceiveDataCallback)(int32_t errCode, uint64_t reqId, uint8_t *outData, uint32_t outDataLen);

class IDlpAbilityCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DlpPermStubCallback");
    virtual void OnResult(uint64_t reqId, int32_t userId, std::string &jsonRes) = 0;
};

class DlpAbilityStub : public IRemoteStub<IDlpAbilityCallback> {
public:
    static sptr<DlpAbilityStub> GetInstance(ReceiveDataCallback callback);
    int32_t OnRemoteRequest(uint32_t errCode, MessageParcel &data,
        MessageParcel &reply, MessageOption &opt) override;
    void OnResult(uint64_t reqId, int32_t userId, std::string &jsonRes) override;

private:
    explicit DlpAbilityStub(ReceiveDataCallback callback);
    ~DlpAbilityStub() = default;
    static std::mutex mutex_;
    ReceiveDataCallback callback_{nullptr};
    static sptr<DlpAbilityStub> singleton_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif