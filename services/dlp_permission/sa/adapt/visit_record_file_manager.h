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

#ifndef DLP_VISIT_RECORD_FILE_MANAGER_H
#define DLP_VISIT_RECORD_FILE_MANAGER_H

#include <mutex>
#include <map>

#include "file_operator.h"
#include "nlohmann/json.hpp"
#include "visited_dlp_file_info.h"
#include "visit_record_json_manager.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Json = nlohmann::json;

class VisitRecordFileManager {
public:
    VisitRecordFileManager();
    virtual ~VisitRecordFileManager();
    static VisitRecordFileManager& GetInstance();

    int32_t AddVisitRecord(const std::string& bundleName, const int32_t& userId, const std::string& docUri);
    int32_t GetVisitRecordList(const std::string& bundleName, const int32_t& userId,
        std::vector<VisitedDLPFileInfo>& infoVec);

private:
    bool Init();
    int32_t UpdateFile(const int32_t& jsonRes);
    bool hasInit_ = false;
    std::shared_ptr<FileOperator> fileOperator_;
    std::recursive_mutex mutex_;
    std::shared_ptr<VisitRecordJsonManager> visitRecordJsonManager_;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_VISIT_RECORD_FILE_MANAGER_H
