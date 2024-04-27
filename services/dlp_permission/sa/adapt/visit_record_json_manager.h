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

#ifndef DLP_VISIT_RECORD_JSON_MANAGER_H
#define DLP_VISIT_RECORD_JSON_MANAGER_H

#include <string>
#include <list>
#include <mutex>
#include "i_json_operator.h"
#include "nlohmann/json.hpp"
#include "visited_dlp_file_info.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct VisitRecordInfo {
    std::string bundleName = "";
    std::string docUri = "";
    int32_t userId = -1;
    int64_t timestamp = -1;
};

class VisitRecordJsonManager : public IJsonOperator {
public:
    VisitRecordJsonManager();
    ~VisitRecordJsonManager();

    int32_t AddVisitRecord(const std::string& bundleName, const int32_t& userId, const std::string& docUri);
    int32_t GetVisitRecordList(const std::string& bundleName, const int32_t& userId,
        std::vector<VisitedDLPFileInfo>& infoVec);

    Json ToJson() const override;
    void FromJson(const Json& jsonObject) override;
    std::string ToString() const override;

private:
    int32_t AddVisitRecord(const std::string& bundleName, const int32_t& userId, const std::string& docUri,
        int64_t timestamp);
    void VisitRecordInfoToJson(Json& json, const VisitRecordInfo& info) const;
    bool VisitRecordInfoFromJson(const Json& json, VisitRecordInfo& info) const;
    mutable std::mutex mutex_;
    std::list<VisitRecordInfo> infoList_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_VISIT_RECORD_JSON_MANAGER_H
