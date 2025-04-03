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

#include "retention_sandbox_info.h"
#include "dlp_permission_log.h"
#include "i_json_operator.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION,
                                                       "RetentionSandBoxInfo" };
constexpr uint32_t APP_INDEX = 0;
}

RetentionSandBoxInfo::RetentionSandBoxInfo()
{
    bundleName_ = "";
    appIndex_ = APP_INDEX;
    dlpFileAccess_ = DLPFileAccess::NO_PERMISSION;
    hasRead_ = false;
    docUriSet_.clear();
}

bool RetentionSandBoxInfo::Marshalling(Parcel& out) const
{
    if (!(out.WriteInt32(this->appIndex_))) {
        DLP_LOG_ERROR(LABEL, "Write appIndex fail");
        return false;
    }
    if (!(out.WriteString(this->bundleName_))) {
        DLP_LOG_ERROR(LABEL, "Write bundleName fail");
        return false;
    }
    std::vector<std::string> docUriVec(this->docUriSet_.begin(), this->docUriSet_.end());
    if (!(out.WriteStringVector(docUriVec))) {
        DLP_LOG_ERROR(LABEL, "Write docUriVec fail");
        return false;
    }
    return true;
}

RetentionSandBoxInfo* RetentionSandBoxInfo::Unmarshalling(Parcel& in)
{
    auto* parcel = new (std::nothrow) RetentionSandBoxInfo();
    if (parcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc buff for parcel fail");
        return nullptr;
    }
    if (!(in.ReadInt32(parcel->appIndex_))) {
        DLP_LOG_ERROR(LABEL, "Read appIndex fail");
        delete parcel;
        return nullptr;
    }
    if (!(in.ReadString(parcel->bundleName_))) {
        DLP_LOG_ERROR(LABEL, "Read bundleName fail");
        delete parcel;
        return nullptr;
    }
    std::vector<std::string> docUriVec;
    if (!(in.ReadStringVector(&docUriVec))) {
        DLP_LOG_ERROR(LABEL, "Read docUriVec fail");
        delete parcel;
        return nullptr;
    }

    std::set<std::string> docUriSet(docUriVec.begin(), docUriVec.end());
    parcel->docUriSet_ = docUriSet;
    return parcel;
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
