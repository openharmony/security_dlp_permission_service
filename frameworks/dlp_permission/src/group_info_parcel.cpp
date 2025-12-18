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

#include "group_info_parcel.h"
#include "dlp_permission_log.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "GroupParcel"};
}
bool GroupInfoParcel::Marshalling(Parcel& out) const
{
    if (!(out.WriteString(this->groupInfo_.groupName))) {
        DLP_LOG_ERROR(LABEL, "Write group name fail");
        return false;
    }
    if (!(out.WriteBool(this->groupInfo_.waterMarkConfig))) {
        DLP_LOG_ERROR(LABEL, "Write group watermarkconfig fail");
        return false;
    }
    return true;
}

GroupInfoParcel* GroupInfoParcel::Unmarshalling(Parcel& in)
{
    auto groupInfoParcel = new (std::nothrow) GroupInfoParcel();
    if (groupInfoParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for group info parcel fail");
        return nullptr;
    }

    if (!(in.ReadString(groupInfoParcel->groupInfo_.groupName))) {
        DLP_LOG_ERROR(LABEL, "Read group account fail");
        delete groupInfoParcel;
        groupInfoParcel = nullptr;
        return nullptr;
    }
    if (!(in.ReadBool(groupInfoParcel->groupInfo_.waterMarkConfig))) {
        DLP_LOG_ERROR(LABEL, "Read group watermarkconfig fail");
        delete groupInfoParcel;
        groupInfoParcel = nullptr;
        return nullptr;
    }

    return groupInfoParcel;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
