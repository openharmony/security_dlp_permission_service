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

#ifndef MOCK_DLP_CREDENTIAL_CLIENT_DEFINES_H
#define MOCK_DLP_CREDENTIAL_CLIENT_DEFINES_H

#include <stdint.h>

#define RESERVED_LEN 64

typedef enum {
    CLOUD_ACCOUNT = 1,
    DOMAIN_ACCOUNT,
    APPLICATION_ACCOUNT,
} AccountType;

typedef enum {
    RECEIVER_DECRYPT_MUST_USE_CLOUD_AND_RETURN_ENCRYPTION_VALUE = 0,
    RECEIVER_DECRYPT_MUST_USE_CLOUD = 1,
    ALLOW_RECEIVER_DECRYPT_WITHOUT_USE_CLOUD = 2,
} CloudEncOption;

typedef struct {
    CloudEncOption opt;
    uint8_t *extraInfo;
    uint32_t extraInfoLen;
} EncAndDecOptions;

typedef struct {
    uint8_t *accountId;
    uint32_t accountIdLen;
} AccountInfo;

typedef struct {
    char *featureName;
    uint8_t *data;
    uint32_t dataLen;
    EncAndDecOptions options;
    AccountType accountType;
    AccountInfo senderAccountInfo;
    uint8_t reserved[RESERVED_LEN];
} DLP_PackPolicyParams;

typedef struct {
    char *featureName;
    uint8_t *data;
    uint32_t dataLen;
    EncAndDecOptions options;
    AccountType accountType;
    AccountInfo receiverAccountInfo;
    uint8_t reserved[RESERVED_LEN];
} DLP_EncPolicyData;

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
    uint8_t reserved[RESERVED_LEN];
} DLP_RestorePolicyData;

typedef enum {
    DLP_SUCCESS = 0x00000000,
    DLP_ERROR = 0x00000001,
    DLP_ERR_INVALID_PARAMS = 0x00000002,
    DLP_ERR_GENERATE_KEY_FAILED = 0x00001001,
    DLP_ERR_IPC_INTERNAL_FAILED = 0x00002001,
    DLP_ERR_CONNECTION_TIME_OUT = 0x00003001,
    DLP_ERR_FILE_PATH = 0x00004001,
    DLP_ERR_CONNECTION_VIP_RIGHT_EXPIRED = 0x00003009,
    DLP_ERR_CONNECTION_POLICY_PERMISSION_EXPIRED = 0x0000300B,
    DLP_ERR_CONNECTION_NO_PERMISSION = 0x0000300C,
    DLP_ERR_CREDENTIAL_NOT_EXIST = 0x00005001,
    DLP_ERR_ACCOUNT_NOT_LOG_IN = 0x00006001,
    DLP_ERR_TOKEN_CONNECTION_FAIL = 0x00006006,
    DLP_ERR_TOKEN_CONNECTION_TIME_OUT = 0x00006007,
    DLP_ERR_APPID_NOT_AUTHORIZED = 0x00007005,
    DLP_ERR_CALLBACK_TIME_OUT = 0x0000200A,
} DLP_ErrorCode;

typedef void (*DLP_PackPolicyCallback)(uint64_t requestId, int errorCode, DLP_EncPolicyData *outParams);

typedef void (*DLP_RestorePolicyCallback)(uint64_t requestId, int errorCode, DLP_RestorePolicyData *outParams);

#endif
