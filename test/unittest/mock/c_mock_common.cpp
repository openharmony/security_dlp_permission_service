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
#include "c_mock_common.h"

#ifdef __cplusplus
extern "C" {
#endif
static std::map<std::string, DlpCMockCondition> g_conditionList;

bool IsFuncNeedMock(const std::string& funcName)
{
    if (g_conditionList.count(funcName) == 0) {
        return false;
    }
    DlpCMockCondition& condition = g_conditionList[funcName];

    if (condition.mockSequence.size() == 0 ||
        condition.currentTimes > condition.mockSequence.size() - 1) {
        condition.currentTimes++;
        return false;
    }

    bool currentFail = condition.mockSequence[condition.currentTimes];
    condition.currentTimes++;
    return currentFail;
}

CommonMockFuncT GetMockFunc(const std::string& funcName)
{
    if (g_conditionList.count(funcName) == 0) {
        return nullptr;
    }
    return g_conditionList[funcName].mockCallback;
}

void SetMockConditions(const std::string& funcName, DlpCMockCondition& condition)
{
    condition.currentTimes = 0;
    g_conditionList[funcName] = condition;
}

void SetMockCallback(const std::string& funcName, CommonMockFuncT func)
{
    if (g_conditionList.count(funcName) == 0) {
        return;
    }

    g_conditionList[funcName].mockCallback = func;
}

void CleanMockConditions(void)
{
    g_conditionList.clear();
}

uint32_t GetMockConditionCounts(const std::string& funcName)
{
    if (g_conditionList.count(funcName) == 0) {
        return 0;
    }
    return g_conditionList[funcName].currentTimes;
}
#ifdef __cplusplus
}
#endif
