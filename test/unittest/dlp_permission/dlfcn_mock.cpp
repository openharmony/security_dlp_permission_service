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

#include "dlfcn_mock.h"

#ifdef DLP_FUZZ_TDD_TEST

#include <cstring>

#include "dlp_transparent_enc_mock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace TestMock {

static bool DLOPEN_SHOULD_FAIL = true;
static bool DLSYM_SHOULD_FAIL = false;
static const char *DLSYM_FAIL_SYMBOL = nullptr;
static void *MOCK_HANDLE = reinterpret_cast<void *>(0xDEADBEEF);

template<typename F>
static void *FuncToVoidPtr(F f)
{
    union {
        F fn;
        void *pv;
    } u;
    u.fn = f;
    return u.pv;
}

void SetDlopenShouldFail(bool shouldFail)
{
    DLOPEN_SHOULD_FAIL = shouldFail;
}

void SetDlsymShouldFailFor(const char *symbol)
{
    DLSYM_SHOULD_FAIL = true;
    DLSYM_FAIL_SYMBOL = symbol;
}

void ResetDlfcnMock()
{
    DLOPEN_SHOULD_FAIL = true;
    DLSYM_SHOULD_FAIL = false;
    DLSYM_FAIL_SYMBOL = nullptr;
}

}  // namespace TestMock
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

extern "C" {
using OHOS::Security::DlpPermission::DLP_SetControlledAppLists;
using OHOS::Security::DlpPermission::DLP_GetControlledAppLists;
using OHOS::Security::DlpPermission::DLP_FreeControlledAppLists;
using OHOS::Security::DlpPermission::DLP_ProcessPluginCommand;
using OHOS::Security::DlpPermission::DLP_FreePluginCommandResult;
using OHOS::Security::DlpPermission::DLP_GetDockerPolicy;
using OHOS::Security::DlpPermission::DLP_FreeDockerPolicy;

void *MockDlopen(const char *filename, int flag)
{
    using OHOS::Security::DlpPermission::TestMock::DLOPEN_SHOULD_FAIL;
    using OHOS::Security::DlpPermission::TestMock::MOCK_HANDLE;

    if (filename != nullptr &&
        (strcmp(filename, "/system/lib/libdlp_transparent_enc_sdk.z.so") == 0 ||
         strcmp(filename, "/system/lib64/libdlp_transparent_enc_sdk.z.so") == 0)) {
        if (DLOPEN_SHOULD_FAIL) {
            return nullptr;
        }
        return MOCK_HANDLE;
    }
    return dlopen(filename, flag);
}

void *MockDlsym(void *handle, const char *symbol)
{
    using OHOS::Security::DlpPermission::TestMock::DLSYM_SHOULD_FAIL;
    using OHOS::Security::DlpPermission::TestMock::DLSYM_FAIL_SYMBOL;
    using OHOS::Security::DlpPermission::TestMock::MOCK_HANDLE;
    using OHOS::Security::DlpPermission::TestMock::FuncToVoidPtr;

    if (handle == MOCK_HANDLE) {
        if (DLSYM_SHOULD_FAIL && DLSYM_FAIL_SYMBOL != nullptr && strcmp(symbol, DLSYM_FAIL_SYMBOL) == 0) {
            return nullptr;
        }
        if (strcmp(symbol, "DLP_SetControlledAppLists") == 0) return FuncToVoidPtr(DLP_SetControlledAppLists);
        if (strcmp(symbol, "DLP_GetControlledAppLists") == 0) return FuncToVoidPtr(DLP_GetControlledAppLists);
        if (strcmp(symbol, "DLP_FreeControlledAppLists") == 0) return FuncToVoidPtr(DLP_FreeControlledAppLists);
        if (strcmp(symbol, "DLP_ProcessPluginCommand") == 0) return FuncToVoidPtr(DLP_ProcessPluginCommand);
        if (strcmp(symbol, "DLP_FreePluginCommandResult") == 0) return FuncToVoidPtr(DLP_FreePluginCommandResult);
        if (strcmp(symbol, "DLP_GetDockerPolicy") == 0) return FuncToVoidPtr(DLP_GetDockerPolicy);
        if (strcmp(symbol, "DLP_FreeDockerPolicy") == 0) return FuncToVoidPtr(DLP_FreeDockerPolicy);
        return nullptr;
    }
    return dlsym(handle, symbol);
}

int MockDlclose(void *handle)
{
    using OHOS::Security::DlpPermission::TestMock::MOCK_HANDLE;

    if (handle == MOCK_HANDLE) {
        return 0;
    }
    return dlclose(handle);
}
}

#endif  // DLP_FUZZ_TDD_TEST
