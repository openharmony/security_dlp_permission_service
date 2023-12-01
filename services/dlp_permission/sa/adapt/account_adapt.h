/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ACCOUNT_ADAPT_H
#define ACCOUNT_ADAPT_H

#include <stdbool.h>
#include <stdint.h>
#include "dlp_credential_client.h"
#ifdef __cplusplus

#include <string>

int32_t GetLocalAccountUid(std::string& accountUid);

extern "C" {
#endif
typedef struct {
    uint32_t size;
    uint8_t* data;
} DlpBlob;

int32_t GetCallingUserId(void);
bool GetUserIdByActiveAccount(int32_t* userId);
int8_t GetLocalAccountName(char** account, uint32_t userId);
int8_t GetUserIdFromUid(int32_t uid, int32_t* userId);
int32_t GetDomainAccountName(char** account);
bool IsAccountLogIn(uint32_t osAccountId, AccountType accountType, const DlpBlob* accountId);
#ifdef __cplusplus
}
#endif

#endif