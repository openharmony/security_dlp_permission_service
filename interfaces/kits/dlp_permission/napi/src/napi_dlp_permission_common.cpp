/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "napi_dlp_permission_common.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

bool CompareOnAndOffRef(const napi_env env, napi_ref subscriberRef, napi_ref unsubscriberRef)
{
    napi_value subscriberCallback;
    napi_status status = napi_get_reference_value(env, subscriberRef, &subscriberCallback);
    if (status != napi_ok) {
        return false;
    }
    napi_value unsubscriberCallback;
    status = napi_get_reference_value(env, unsubscriberRef, &unsubscriberCallback);
    if (status != napi_ok) {
        return false;
    }
    bool result = false;
    napi_strict_equals(env, subscriberCallback, unsubscriberCallback, &result);
    return result;
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
