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

#ifndef C_MOCK_COMMON_H
#define C_MOCK_COMMON_H

#include <map>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*CommonMockFuncT)(void);

struct DlpCMockCondition {
    std::vector<bool> mockSequence;
    uint32_t currentTimes;
    CommonMockFuncT mockCallback;
};

void SetMockConditions(const std::string& funcName, DlpCMockCondition& condition);

void CleanMockConditions(void);

bool IsFuncNeedMock(const std::string& funcName);

CommonMockFuncT GetMockFunc(const std::string& funcName);
void SetMockCallback(const std::string& funcName, CommonMockFuncT func);

uint32_t GetMockConditionCounts(const std::string& funcName);
#ifdef __cplusplus
}
#endif
#endif
