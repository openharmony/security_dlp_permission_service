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

#ifndef DLP_TRANSPARENT_ENC_POLICY_MOCK_H
#define DLP_TRANSPARENT_ENC_POLICY_MOCK_H

#include <string>
#include "dlp_permission.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

struct DockerPolicyInfo;

namespace TestMock {

void SetCallingTokenId(uint32_t tokenId);
void SetSelfTokenId(uint32_t tokenId);
void SetNativeTokenId(uint32_t tokenId);
void SetVerifyAccessTokenResult(int result);
void SetVerifyAccessTokenResultForPerm(const std::string &permission, int result);
void SetGetParameterResult(const std::string &value);
void SetGetParameterResultForKey(const std::string &key, const std::string &value);
void SetGetDockerPolicyResult(int32_t result);
void SetDockerPolicyInfo(const DockerPolicyInfo &info);
void ResetAllMockState();

uint32_t GetMockCallingTokenId();
uint32_t GetMockSelfTokenId();
uint32_t GetMockNativeTokenId();
int GetMockVerifyAccessTokenResult();
int GetMockVerifyAccessTokenResultForPerm(const std::string &permission);
std::string GetMockGetParameterResult();
std::string GetMockGetParameterResultForKey(const std::string &key);
int32_t GetMockGetDockerPolicyResult();
DockerPolicyInfo GetMockDockerPolicyInfo();
bool IsDockerPolicyInfoSet();

}  // namespace TestMock
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_TRANSPARENT_ENC_POLICY_MOCK_H
