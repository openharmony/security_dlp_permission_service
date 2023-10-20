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

#include "cert_parcel.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "CertParcel" };
}

CertParcel::CertParcel()
{
    isNeedAdapter = false;
    contactAccount = "";
}

bool CertParcel::Marshalling(Parcel& data) const
{
    if (!data.WriteBool(this->isNeedAdapter)) {
        DLP_LOG_ERROR(LABEL, "Write bool isNeedAdapter fail");
        return false;
    }
    if (!data.WriteString(this->contactAccount)) {
        DLP_LOG_ERROR(LABEL, "Write string contactAccount fail");
        return false;
    }
    if (!data.WriteUInt8Vector(this->cert)) {
        DLP_LOG_ERROR(LABEL, "Write uint8 vector fail");
        return false;
    }
    if (!data.WriteUInt8Vector(this->offlineCert)) {
        DLP_LOG_ERROR(LABEL, "Write uint8 offlineCert vector fail");
        return false;
    }
    return true;
}

static CertParcel* FreeCertParcel(CertParcel* parcel)
{
    delete parcel;
    parcel = nullptr;
    return nullptr;
}

CertParcel* CertParcel::Unmarshalling(Parcel& data)
{
    auto* parcel = new (std::nothrow) CertParcel();
    if (parcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!data.ReadBool(parcel->isNeedAdapter)) {
        DLP_LOG_ERROR(LABEL, "Read isNeedAdapter fail");
        return FreeCertParcel(parcel);
    }
    if (!data.ReadString(parcel->contactAccount)) {
        DLP_LOG_ERROR(LABEL, "Read contactAccount fail");
        return FreeCertParcel(parcel);
    }
    if (!data.ReadUInt8Vector(&parcel->cert)) {
        DLP_LOG_ERROR(LABEL, "Read cert fail");
        return FreeCertParcel(parcel);
    }
    if (!data.ReadUInt8Vector(&parcel->offlineCert)) {
        DLP_LOG_ERROR(LABEL, "Read cert fail");
        return FreeCertParcel(parcel);
    }
    return parcel;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
