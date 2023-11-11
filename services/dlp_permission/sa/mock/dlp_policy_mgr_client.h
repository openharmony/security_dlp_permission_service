/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DLP_POLICY_MGR_CLIENT_H
#define DLP_POLICY_MGR_CLIENT_H

#include <stdint.h>
#include "dlp_credential_client.h"

#ifdef __cplusplus
extern "C" {
#endif

__attribute__ ((visibility("default"))) int32_t DLP_AddPolicy(PolicyType type, const uint8_t *policy,
    uint32_t policyLen);

__attribute__ ((visibility("default"))) int32_t DLP_RemovePolicy(PolicyType type);

__attribute__ ((visibility("default"))) int32_t DLP_GetPolicy(PolicyType type, uint8_t *policy, uint32_t *policyLen);

__attribute__ ((visibility("default"))) int32_t DLP_CheckPermission(PolicyType type, PolicyHandle handle);

#ifdef __cplusplus
}
#endif

#endif