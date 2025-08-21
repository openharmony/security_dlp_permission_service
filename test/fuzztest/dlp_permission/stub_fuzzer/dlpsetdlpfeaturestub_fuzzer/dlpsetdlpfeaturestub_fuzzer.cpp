/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlpsetdlpfeaturestub_fuzzer.h"
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_manager_adapter.h"
#include "bundle_mgr_interface.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
constexpr uint8_t STATUS_NUM = 2;

namespace OHOS {
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || size < STATUS_NUM) {
        return;
    }
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    uint32_t dlpFeatureInfo = data[0] % STATUS_NUM;
    bool statusSetInfo;
    service1->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
}

bool SetDlpFeatureFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetDlpFeatureFuzzTest(data, size);
    return 0;
}
