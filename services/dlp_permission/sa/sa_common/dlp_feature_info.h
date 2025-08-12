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

#ifndef DLP_FEATURE_INFO_H
#define DLP_FEATURE_INFO_H

#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using unordered_json = nlohmann::ordered_json;

class DlpFeatureInfo {
public:
    DlpFeatureInfo();
    ~DlpFeatureInfo();
    static int32_t SaveDlpFeatureInfoToFile(const unordered_json& dlpFeatureJson);
    static int32_t GetDlpFeatureInfoFromFile(const char *filePath, uint32_t& dlpFeature);
};

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_FEATURE_INFO_H