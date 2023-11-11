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

#ifndef MOCK_DLP_CREDENTIAL_CLIENT_H
#define MOCK_DLP_CREDENTIAL_CLIENT_H

#include <stdint.h>
#include "dlp_credential_client_defines.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    AUTHORIZED_APPLICATION_LIST = 1,
    FILE_CLASSIFICATION_POLICY,
} PolicyType;

typedef union {
    char *id;
    int32_t index;
} PolicyHandle;

__attribute__ ((visibility("default"))) int DLP_PackPolicy(uint32_t osAccountId, const DLP_PackPolicyParams *params,
    DLP_PackPolicyCallback callback, uint64_t *requestId);

__attribute__ ((visibility("default"))) int DLP_RestorePolicy(uint32_t osAccountId, const DLP_EncPolicyData *params,
    DLP_RestorePolicyCallback callback, uint64_t *requestId);

#ifdef __cplusplus
}
#endif

#endif
