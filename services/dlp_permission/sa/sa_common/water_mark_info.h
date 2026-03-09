/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef WATER_MARK_INFO_H
#define WATER_MARK_INFO_H

#include <string>
#include <memory>
#include "transaction/rs_interfaces.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
struct WaterMarkInfo {
public:
    std::string accountAndUserId = "";
    std::shared_ptr<Media::PixelMap> waterMarkImg = nullptr;
    int32_t waterMarkFd = -1;
    std::string maskInfo = "";
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS

#endif