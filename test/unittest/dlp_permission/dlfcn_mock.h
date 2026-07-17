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

#ifndef DLP_DLCFN_MOCK_H
#define DLP_DLCFN_MOCK_H

#include <dlfcn.h>

#ifdef DLP_FUZZ_TDD_TEST
#define dlopen MockDlopen
#define dlsym MockDlsym
#define dlclose MockDlclose
#endif

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace TestMock {

void SetDlopenShouldFail(bool shouldFail);
void SetDlsymShouldFailFor(const char *symbol);
void ResetDlfcnMock();

}  // namespace TestMock
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#ifdef DLP_FUZZ_TDD_TEST
extern "C" {
void *MockDlopen(const char *filename, int flag);
void *MockDlsym(void *handle, const char *symbol);
int MockDlclose(void *handle);
}
#endif

#endif  // DLP_DLCFN_MOCK_H
