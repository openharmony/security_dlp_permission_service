/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "querydlpfileaccessstub_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static pthread_once_t g_callOnce = PTHREAD_ONCE_INIT;
const int32_t DEFAULT_API_VERSION = 8;
const PermissionDef INFO_MANAGER_TEST_PERM_DEF1 = {
    .permissionName = "open the door",
    .bundleName = "osaccount_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

const PermissionStateFull INFO_MANAGER_TEST_STATE1 = {
    .permissionName = "open the door",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {1},
    .grantFlags = {1}
};

static void InitTokenId()
{
    HapPolicyParams hapPolicyParams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {INFO_MANAGER_TEST_PERM_DEF1},
        .permStateList = {INFO_MANAGER_TEST_STATE1}
    };
    HapInfoParams hapInfoParams = {
        .userID = 100,
        .bundleName = "com.ohos.dlpmanager",
        .instIndex = 1,
        .dlpType = 1,
        .appIDDesc = "com.ohos.dlpmanager",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false
    };

    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfoParams, hapPolicyParams);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    SetSelfTokenID(tokenId);
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::QUERY_DLP_FILE_ACCESS);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->OnRemoteRequest(code, datas, reply, option);
}

bool QueryDlpFileAccessFuzzTest(const uint8_t* data, size_t size)
{
    pthread_once(&g_callOnce, InitTokenId);
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::QueryDlpFileAccessFuzzTest(data, size);
    return 0;
}
