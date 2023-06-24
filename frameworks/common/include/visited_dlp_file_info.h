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

#ifndef VISITED_DLP_FILE_INFO_H
#define VISITED_DLP_FILE_INFO_H

#include <set>
#include <string>
#include "parcel.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class VisitedDLPFileInfo : public Parcelable {
public:
    VisitedDLPFileInfo();
    ~VisitedDLPFileInfo() override = default;

    virtual bool Marshalling(Parcel& parcel) const override;
    static VisitedDLPFileInfo* Unmarshalling(Parcel& parcel);

    int64_t visitTimestamp;
    std::string docUri;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // RETENTION_SANDBOX_INFO_H