/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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


#include "set_dlp_config.h"
#include <string>
#include "dlp_permission_log.h"
#include "dlp_permission_client.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpSetConfig"};
static const std::string WATER_MARK_CONFIG_KEY = "ohos.dlp.params.waterMarkConfig";
}
using Want = OHOS::AAFwk::Want;

int32_t DlpSetConfig::SetDlpConfig(const Want &want)
{
    bool waterMarkConfig = want.GetBoolParam(WATER_MARK_CONFIG_KEY, false);
    if (!waterMarkConfig) {
        DLP_LOG_WARN(LABEL, "waterMarkConfig is false or null");
        return DLP_OK;
    }

    int32_t pid = getprocpid();
    DLP_LOG_INFO(LABEL, "start setting watermark.");
    return SetWaterMark(pid);
}

int32_t DlpSetConfig::SetWaterMark(const int32_t pid)
{
    return DlpPermissionClient::GetInstance().SetWaterMark(pid);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

