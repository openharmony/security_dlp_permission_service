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

#include "dlp_bundle_adapter_test.h"

#include "bundle_manager_adapter.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::AppExecFwk;
namespace {
const std::string BUNDLE_NAME = "com.ohos.launcher";
const int32_t USER_ID = 1;
} // namespace

void DlpBundleAdapterTest::SetUpTestCase() {}

void DlpBundleAdapterTest::TearDownTestCase() {}

void DlpBundleAdapterTest::SetUp() {}

void DlpBundleAdapterTest::TearDown() {}

/**
 * @tc.name: DlpBundleAdapterTest001
 * @tc.desc: test GetBundleInfo failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpBundleAdapterTest, DlpBundleAdapterTest001, TestSize.Level1)
{
    BundleInfo bundleInfo;
    bool result = BundleManagerAdapter::GetInstance().GetBundleInfo(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_EQ(result, false);
}

/**
 * @tc.name: DlpBundleAdapterTest002
 * @tc.desc: test GetBundleInfoV9 failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpBundleAdapterTest, DlpBundleAdapterTest002, TestSize.Level1)
{
    BundleInfo bundleInfo;
    int32_t result = BundleManagerAdapter::GetInstance().GetBundleInfoV9(
        BUNDLE_NAME, BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, USER_ID);
    ASSERT_NE(result, DLP_OK);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
