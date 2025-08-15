/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_feature_info_test.h"
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_feature_info.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "huks_apply_permission_test_common.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFeatureInfoTest" };
static const std::string MDM_ENABLE_VALUE = "status";
static const std::string MDM_BUNDLE_NAME = "appId";
}

void DlpFeatureInfoTest::SetUpTestCase() {}

void DlpFeatureInfoTest::TearDownTestCase() {}

void DlpFeatureInfoTest::SetUp() {}

void DlpFeatureInfoTest::TearDown() {}

/**
 * @tc.name: SaveDlpFeatureInfoToFile001
 * @tc.desc: SaveDlpFeatureInfoToFile test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, SaveDlpFeatureInfoToFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SaveDlpFeatureInfoToFile001");

    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, DLP_OK);

    uint32_t dlpFeatureInfo = 1;
    std::string callerBundleName = "com.dlpFeatureInfo.test";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = callerBundleName;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_NE(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: SaveDlpFeatureInfoToFile002
 * @tc.desc: SaveDlpFeatureInfoToFile have no status
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, SaveDlpFeatureInfoToFile002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SaveDlpFeatureInfoToFile002");

    std::string callerBundleName = "com.dlpFeatureInfo.test";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = callerBundleName;

    int32_t ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: SaveDlpFeatureInfoToFile003
 * @tc.desc: SaveDlpFeatureInfoToFile have invalid dlpFeatureInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, SaveDlpFeatureInfoToFile003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SaveDlpFeatureInfoToFile003");

    uint32_t dlpFeatureInfo = -1;
    std::string callerBundleName = "com.dlpFeatureInfo.test";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = callerBundleName;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    int32_t ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: SaveDlpFeatureInfoToFile004
 * @tc.desc: SaveDlpFeatureInfoToFile have no huks permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, SaveDlpFeatureInfoToFile004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SaveDlpFeatureInfoToFile004");

    uint32_t dlpFeatureInfo = 1;
    std::string callerBundleName = "com.dlpFeatureInfo.test";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = callerBundleName;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    int32_t ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_NE(ret, DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL);
}