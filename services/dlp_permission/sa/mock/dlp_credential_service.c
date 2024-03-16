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


#include <pthread.h>
#include <unistd.h>
#include "stdint.h"
#include "account_adapt.h"
#include "dlp_credential_client.h"
#include "dlp_permission_log.h"
#include "securec.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DlpCredentialService"
#endif

static uint64_t g_requestId = 0;
static const size_t STRING_LEN = 256;
static const uint32_t MAX_CERT_LEN = 1024 * 1024;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct PackPolicyCallbackTaskPara {
    DLP_PackPolicyCallback callback;
    uint32_t userId;
    uint64_t requestId;
    int errorCode;
    DLP_PackPolicyParams* packParams;
} PackPolicyCallbackTaskPara;

typedef struct RestorePolicyCallbackTaskPara {
    DLP_RestorePolicyCallback callback;
    uint32_t userId;
    uint64_t requestId;
    int errorCode;
    DLP_EncPolicyData* encData;
} RestorePolicyCallbackTaskPara;

static void FreePackPolicyCallbackTaskPara(PackPolicyCallbackTaskPara* taskParams)
{
    if (taskParams == NULL) {
        return;
    }
    if (taskParams->packParams == NULL) {
        free(taskParams);
        return;
    }
    if (taskParams->packParams->featureName != NULL) {
        free(taskParams->packParams->featureName);
        taskParams->packParams->featureName = NULL;
    }
    if (taskParams->packParams->data != NULL) {
        free(taskParams->packParams->data);
        taskParams->packParams->data = NULL;
    }
    free(taskParams->packParams);
    taskParams->packParams = NULL;
    free(taskParams);
}

static void FreeRestorePolicyCallbackTaskPara(RestorePolicyCallbackTaskPara* taskParams)
{
    if (taskParams == NULL) {
        return;
    }
    if (taskParams->encData == NULL) {
        free(taskParams);
        return;
    }
    if (taskParams->encData->featureName != NULL) {
        free(taskParams->encData->featureName);
        taskParams->encData->featureName = NULL;
    }
    if (taskParams->encData->data != NULL) {
        free(taskParams->encData->data);
        taskParams->encData->data = NULL;
    }
    free(taskParams->encData);
    taskParams->encData = NULL;
    free(taskParams);
}

bool GetAccountName(uint32_t accountType, uint32_t userId, char** account)
{
    DLP_LOG_INFO("accountName form  accountType:%{public}d DOMAIN_ACCOUNT:%{public}d", accountType, DOMAIN_ACCOUNT);
    if (accountType != DOMAIN_ACCOUNT) {
        if (GetLocalAccountName(account, userId) != 0) {
            DLP_LOG_ERROR("Get local account fail");
            return false;
        }
    } else {
        if (GetDomainAccountName(account) != 0) {
            DLP_LOG_ERROR("Get local account fail");
            return false;
        }
    }
    return true;
}

static int CheckAccount(const uint8_t* data, uint32_t len, uint32_t accountType, uint32_t userId, bool isNeedCheckList)
{
    int res = DLP_ERROR;
    char owner[STRING_LEN];
    char* account = NULL;
    char user[STRING_LEN];
    char everyone[STRING_LEN];
    if (len < 0) {
        DLP_LOG_ERROR("len error");
        return DLP_ERROR;
    }
    char* policy = (char*)malloc(len + 1);
    if (policy == NULL) {
        DLP_LOG_ERROR("policy == NULL");
        return DLP_ERROR;
    }
    if (memcpy_s(policy, len + 1, data, len) != EOK) {
        DLP_LOG_ERROR("memcpy_s error");
        goto end;
    }
    policy[len] = '\0';
    if (!GetAccountName(accountType, userId, &account)) {
        goto end;
    }
    if (sprintf_s(owner, STRING_LEN, "\"ownerAccountName\":\"%s\"", account) <= 0 ||
        sprintf_s(user, STRING_LEN, "\"%s\":{", account) <= 0 ||
        sprintf_s(everyone, STRING_LEN, "\"%s\":{", "everyone") <= 0) {
        DLP_LOG_ERROR("sprintf_s owner error");
        goto end;
    }
    if (!isNeedCheckList) {
        if (strstr(policy, owner) == NULL) {
            DLP_LOG_ERROR("policy owner check error");
        } else {
            res = DLP_SUCCESS;
        }
        goto end;
    }
    if (strstr(policy, owner) != NULL || strstr(policy, user) != NULL || strstr(policy, everyone) != NULL) {
        res = DLP_SUCCESS;
    } else {
        DLP_LOG_ERROR("No permission to parse policy");
    }
end:
    free(account);
    free(policy);
    return res;
}

static void* PackPolicyCallbackTask(void* inputTaskParams)
{
    if (inputTaskParams == NULL) {
        DLP_LOG_ERROR("InputTaskParams is null");
        return NULL;
    }
    PackPolicyCallbackTaskPara* taskParams = (PackPolicyCallbackTaskPara*)inputTaskParams;
    if (taskParams->callback == NULL) {
        DLP_LOG_ERROR("Callback is null");
        FreePackPolicyCallbackTaskPara(taskParams);
        return NULL;
    }
    if (taskParams->packParams == NULL) {
        DLP_LOG_ERROR("packParams is null");
        FreePackPolicyCallbackTaskPara(taskParams);
        return NULL;
    }
    const char* exInfo = "DlpRestorePolicyTest_NormalInput_ExtraInfo";
    EncAndDecOptions encAndDecOptions = {
        .opt = ALLOW_RECEIVER_DECRYPT_WITHOUT_USE_CLOUD,
        .extraInfo = (uint8_t*)(exInfo),
        .extraInfoLen = strlen(exInfo)
    };
    DLP_EncPolicyData outParams = {
        .featureName = taskParams->packParams->featureName,
        .data = taskParams->packParams->data,
        .dataLen = taskParams->packParams->dataLen,
        .options = encAndDecOptions,
        .accountType = taskParams->packParams->accountType,
    };
    if (CheckAccount(taskParams->packParams->data, taskParams->packParams->dataLen, taskParams->packParams->accountType,
        taskParams->userId, false) != DLP_SUCCESS) {
        taskParams->errorCode = DLP_ERR_CONNECTION_NO_PERMISSION;
        DLP_LOG_ERROR("get ownerAccount error");
    }
    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    DLP_LOG_INFO("End thread, requestId: %{public}llu", (unsigned long long)taskParams->requestId);
    FreePackPolicyCallbackTaskPara(taskParams);
    return NULL;
}

static void* RestorePolicyCallbackTask(void* inputTaskParams)
{
    if (inputTaskParams == NULL) {
        DLP_LOG_ERROR("InputTaskParams is null");
        return NULL;
    }
    RestorePolicyCallbackTaskPara* taskParams = (RestorePolicyCallbackTaskPara*)inputTaskParams;
    if ((taskParams->callback == NULL) || (taskParams->encData == NULL)) {
        DLP_LOG_ERROR("Callback is null");
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return NULL;
    }

    DLP_RestorePolicyData outParams;
    taskParams->errorCode = DLP_SUCCESS;
    outParams.data = NULL;
    outParams.dataLen = 0;
    DlpBlob accountIdBlob = { taskParams->encData->receiverAccountInfo.accountIdLen,
                              taskParams->encData->receiverAccountInfo.accountId };
    bool accountStatus = IsAccountLogIn(taskParams->userId, taskParams->encData->accountType, &accountIdBlob);
    if (!accountStatus) {
        taskParams->errorCode = DLP_ERR_ACCOUNT_NOT_LOG_IN;
        DLP_LOG_ERROR("Check accountStatus failed.");
        goto end;
    }
    if (CheckAccount(taskParams->encData->data, taskParams->encData->dataLen, taskParams->encData->accountType,
        taskParams->userId, true) != DLP_SUCCESS) {
        taskParams->errorCode = DLP_ERR_CONNECTION_NO_PERMISSION;
        DLP_LOG_ERROR("get ownerAccount error");
        goto end;
    }
    outParams.data = taskParams->encData->data;
    outParams.dataLen = taskParams->encData->dataLen;
end:
    taskParams->callback(taskParams->requestId, taskParams->errorCode, &outParams);
    DLP_LOG_INFO("End thread, requestId: %{public}llu", (unsigned long long)taskParams->requestId);
    FreeRestorePolicyCallbackTaskPara(taskParams);
    return NULL;
}

static PackPolicyCallbackTaskPara* TransPackPolicyParams(const DLP_PackPolicyParams* params,
    DLP_PackPolicyCallback callback, uint64_t requestId, uint32_t userId)
{
    PackPolicyCallbackTaskPara* taskParams = (PackPolicyCallbackTaskPara*)calloc(1, sizeof(PackPolicyCallbackTaskPara));
    if (taskParams == NULL) {
        goto err;
    }
    taskParams->callback = callback;
    taskParams->userId = userId;
    taskParams->requestId = requestId;
    taskParams->errorCode = 0;
    taskParams->packParams = (DLP_PackPolicyParams*)calloc(1, sizeof(DLP_PackPolicyParams));
    if (taskParams->packParams == NULL) {
        goto err;
    }
    taskParams->packParams->featureName = (char*)strdup(params->featureName);
    if (taskParams->packParams->featureName == NULL) {
        goto err;
    }
    taskParams->packParams->data = (uint8_t*)calloc(1, params->dataLen);
    if (taskParams->packParams->data == NULL) {
        goto err;
    }
    if (memcpy_s(taskParams->packParams->data, params->dataLen, params->data, params->dataLen) != EOK) {
        goto err;
    }
    taskParams->packParams->dataLen = params->dataLen;
    taskParams->packParams->accountType = params->accountType;
    taskParams->packParams->options = params->options;
    taskParams->packParams->senderAccountInfo = params->senderAccountInfo;
    return taskParams;
err:
    DLP_LOG_ERROR("Memory operate fail");
    FreePackPolicyCallbackTaskPara(taskParams);
    return NULL;
}

int DLP_PackPolicy(
    uint32_t osAccountId, const DLP_PackPolicyParams* params, DLP_PackPolicyCallback callback, uint64_t* requestId)
{
    DLP_LOG_DEBUG("enter mock");
    (void)osAccountId;
    if (params == NULL || params->data == NULL || params->featureName == NULL || callback == NULL ||
        requestId == NULL || params->dataLen == 0 || params->dataLen > MAX_CERT_LEN) {
        DLP_LOG_ERROR("Callback or params is null");
        return DLP_ERROR;
    }

    pthread_mutex_lock(&g_mutex);
    uint64_t id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    PackPolicyCallbackTaskPara* taskParams = TransPackPolicyParams(params, callback, *requestId, osAccountId);
    if (taskParams == NULL) {
        return DLP_ERROR;
    }

    pthread_t t;
    int32_t ret = pthread_create(&t, NULL, PackPolicyCallbackTask, taskParams);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_create failed %d\n", ret);
        FreePackPolicyCallbackTaskPara(taskParams);
        return DLP_ERROR;
    }
    ret = pthread_detach(t);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_detach failed %d\n", ret);
        FreePackPolicyCallbackTaskPara(taskParams);
        return DLP_ERROR;
    }
    DLP_LOG_INFO("Start new thread, requestId: %{public}llu", (unsigned long long)*requestId);
    return DLP_SUCCESS;
}

static RestorePolicyCallbackTaskPara* TransEncPolicyData(
    const DLP_EncPolicyData* params, DLP_RestorePolicyCallback callback, uint64_t requestId, uint32_t userId)
{
    RestorePolicyCallbackTaskPara* taskParams =
        (RestorePolicyCallbackTaskPara*)calloc(1, sizeof(RestorePolicyCallbackTaskPara));
    if (taskParams == NULL) {
        goto err;
    }
    taskParams->callback = callback;
    taskParams->userId = userId;
    taskParams->requestId = requestId;
    taskParams->errorCode = 0;
    taskParams->encData = (DLP_EncPolicyData*)calloc(1, sizeof(DLP_EncPolicyData));
    if (taskParams->encData == NULL) {
        goto err;
    }
    taskParams->encData->featureName = (char*)strdup(params->featureName);
    if (taskParams->encData->featureName == NULL) {
        goto err;
    }
    taskParams->encData->data = (uint8_t*)calloc(1, params->dataLen);
    if (taskParams->encData->data == NULL) {
        goto err;
    }
    if (memcpy_s(taskParams->encData->data, params->dataLen, params->data, params->dataLen) != EOK) {
        goto err;
    }
    taskParams->encData->dataLen = params->dataLen;
    taskParams->encData->accountType = params->accountType;
    taskParams->encData->options = params->options;
    taskParams->encData->receiverAccountInfo = params->receiverAccountInfo;
    return taskParams;
err:
    DLP_LOG_ERROR("Memory operate fail");
    FreeRestorePolicyCallbackTaskPara(taskParams);
    return NULL;
}

int DLP_RestorePolicy(
    uint32_t osAccountId, const DLP_EncPolicyData* params, DLP_RestorePolicyCallback callback, uint64_t* requestId)
{
    DLP_LOG_DEBUG("DLP enter mock");
    if (params == NULL || params->data == NULL || params->featureName == NULL || callback == NULL ||
        requestId == NULL || params->dataLen == 0 || params->dataLen > MAX_CERT_LEN) {
        DLP_LOG_ERROR("Callback or params is null");
        return DLP_ERROR;
    }

    char *tmp1 = "test_appId_passed_1";
    char *tmp2 = "test_appId_passed_2";
    if (strcmp(params->featureName, tmp1) || strcmp(params->featureName, tmp2)) {
        DLP_LOG_DEBUG("appId check pass");
    } else {
        return DLP_ERR_APPID_NOT_AUTHORIZED;
    }

    pthread_mutex_lock(&g_mutex);
    uint64_t id = ++g_requestId;  // Simulation allocation requestId.
    pthread_mutex_unlock(&g_mutex);
    *requestId = id;

    RestorePolicyCallbackTaskPara* taskParams = TransEncPolicyData(params, callback, *requestId, osAccountId);
    if (taskParams == NULL) {
        return DLP_ERROR;
    }

    pthread_t t;
    int32_t ret = pthread_create(&t, NULL, RestorePolicyCallbackTask, taskParams);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_create failed %d\n", ret);
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return DLP_ERROR;
    }
    ret = pthread_detach(t);
    if (ret != 0) {
        DLP_LOG_ERROR("pthread_detach failed %d\n", ret);
        FreeRestorePolicyCallbackTaskPara(taskParams);
        return DLP_ERROR;
    }
    DLP_LOG_INFO("Start new thread, requestId: %{public}llu", (unsigned long long)*requestId);
    return DLP_SUCCESS;
}

int32_t DLP_AddPolicy(PolicyType type, const uint8_t *policy, uint32_t policyLen)
{
    return DLP_SUCCESS;
}

int32_t DLP_GetPolicy(PolicyType type, uint8_t *policy, uint32_t *policyLen)
{
    if (*policyLen < 0) {
        DLP_LOG_ERROR("policyLen is null");
        return DLP_ERROR;
    }
    *policyLen = 0;
    return DLP_SUCCESS;
}

int32_t DLP_RemovePolicy(PolicyType type)
{
    return DLP_SUCCESS;
}

int32_t  DLP_CheckPermission(PolicyType type, PolicyHandle handle)
{
    return DLP_SUCCESS;
}