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

#include "dlp_transparent_enc_policy_mock.h"
#include "dlp_permission.h"
#include "dlp_transparent_enc_manager.h"

#include <map>

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace TestMock {

static uint32_t g_callingTokenId = 0;
static uint32_t g_selfTokenId = 0;
static uint32_t g_nativeTokenId = 0;
static int g_verifyAccessTokenResult = -1;
static std::string g_getParameterResult = "";
static std::map<std::string, std::string> g_getParameterResultsByKey;
static int32_t g_getDockerPolicyResult = DLP_OK;
static DockerPolicyInfo g_dockerPolicyInfo;
static bool g_dockerPolicyInfoSet = false;
static std::map<std::string, int> g_permissionResults;

void SetCallingTokenId(uint32_t tokenId)
{
    g_callingTokenId = tokenId;
}

void SetSelfTokenId(uint32_t tokenId)
{
    g_selfTokenId = tokenId;
}

void SetNativeTokenId(uint32_t tokenId)
{
    g_nativeTokenId = tokenId;
}

void SetVerifyAccessTokenResult(int result)
{
    g_verifyAccessTokenResult = result;
}

void SetVerifyAccessTokenResultForPerm(const std::string &permission, int result)
{
    g_permissionResults[permission] = result;
}

void SetGetParameterResult(const std::string &value)
{
    g_getParameterResult = value;
}

void SetGetParameterResultForKey(const std::string &key, const std::string &value)
{
    g_getParameterResultsByKey[key] = value;
}

void SetGetDockerPolicyResult(int32_t result)
{
    g_getDockerPolicyResult = result;
}

void SetDockerPolicyInfo(const DockerPolicyInfo &info)
{
    g_dockerPolicyInfo = info;
    g_dockerPolicyInfoSet = true;
}

void ResetAllMockState()
{
    g_callingTokenId = 0;
    g_selfTokenId = 0;
    g_nativeTokenId = 0;
    g_verifyAccessTokenResult = -1;
    g_getParameterResult = "";
    g_getParameterResultsByKey.clear();
    g_getDockerPolicyResult = DLP_OK;
    g_dockerPolicyInfoSet = false;
    DockerPolicyInfo emptyInfo;
    g_dockerPolicyInfo = emptyInfo;
    g_permissionResults.clear();
}

uint32_t GetMockCallingTokenId()
{
    return g_callingTokenId;
}

uint32_t GetMockSelfTokenId()
{
    return g_selfTokenId;
}

uint32_t GetMockNativeTokenId()
{
    return g_nativeTokenId;
}

int GetMockVerifyAccessTokenResult()
{
    return g_verifyAccessTokenResult;
}

int GetMockVerifyAccessTokenResultForPerm(const std::string &permission)
{
    auto it = g_permissionResults.find(permission);
    if (it != g_permissionResults.end()) {
        return it->second;
    }
    return g_verifyAccessTokenResult;
}

std::string GetMockGetParameterResult()
{
    return g_getParameterResult;
}

std::string GetMockGetParameterResultForKey(const std::string &key)
{
    auto it = g_getParameterResultsByKey.find(key);
    if (it != g_getParameterResultsByKey.end()) {
        return it->second;
    }
    return g_getParameterResult;
}

int32_t GetMockGetDockerPolicyResult()
{
    return g_getDockerPolicyResult;
}

DockerPolicyInfo GetMockDockerPolicyInfo()
{
    return g_dockerPolicyInfo;
}

bool IsDockerPolicyInfoSet()
{
    return g_dockerPolicyInfoSet;
}

}  // namespace TestMock
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
