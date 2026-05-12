/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <dlfcn.h>
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;

namespace {
static const std::string DLP_PERMISSION_SDK_PATH = "/system/lib64/libdlp_permission_sdk.z.so";
}

class DlpPermissionSdkLoadTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    void SetUp() {}

    void TearDown() {}
};

/**
 * @tc.name: DlopenAndDlclose001
 * @tc.desc: Test dlopen and dlclose libdlp_permission_sdk.z.so without crash on ARM64
 * @tc.type: FUNC
 * @tc.require:
 */
#ifdef _ARM64_
HWTEST_F(DlpPermissionSdkLoadTest, DlopenAndDlclose001, TestSize.Level0)
{
    void* handle = dlopen(DLP_PERMISSION_SDK_PATH.c_str(), RTLD_LAZY);
    ASSERT_NE(nullptr, handle) << "dlopen failed: " << dlerror();

    int ret = dlclose(handle);
    ASSERT_EQ(0, ret) << "dlclose failed: " << dlerror();
}
#endif