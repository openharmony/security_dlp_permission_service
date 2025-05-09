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

#include "mock_sandbox_init.h"

using namespace OHOS::Security::AccessToken;
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

void InitTokenId()
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