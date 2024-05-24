/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dlp_permission_info_parcel.h"
#include "dlp_permission_log.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionParcel"};
}
bool DLPPermissionInfoParcel::Marshalling(Parcel& out) const
{
    if (!(out.WriteUint32(this->permInfo_.dlpFileAccess))) {
        DLP_LOG_ERROR(LABEL, "Write dlp file access fail");
        return false;
    }
    if (!(out.WriteUint32(this->permInfo_.flags))) {
        DLP_LOG_ERROR(LABEL, "Write flags fail");
        return false;
    }
    return true;
}

DLPPermissionInfoParcel* DLPPermissionInfoParcel::Unmarshalling(Parcel& in)
{
    auto permInfoParcel = new (std::nothrow) DLPPermissionInfoParcel();
    if (permInfoParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for perm info parcel fail");
        return nullptr;
    }

    uint32_t res;
    if (!(in.ReadUint32(res))) {
        DLP_LOG_ERROR(LABEL, "Read dlpFileAccess fail");
        delete permInfoParcel;
        permInfoParcel = nullptr;
        return nullptr;
    }
    permInfoParcel->permInfo_.dlpFileAccess = static_cast<DLPFileAccess>(res);

    if (!(in.ReadUint32(res))) {
        DLP_LOG_ERROR(LABEL, "Read flags fail");
        delete permInfoParcel;
        permInfoParcel = nullptr;
        return nullptr;
    }
    permInfoParcel->permInfo_.flags = static_cast<ActionFlags>(res);
    return permInfoParcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
