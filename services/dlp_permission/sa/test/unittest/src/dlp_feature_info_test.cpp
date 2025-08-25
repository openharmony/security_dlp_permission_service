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
static const char *FEATURE_INFO_DATA_FILE_PATH = "/data/service/el1/public/dlp_permission_service/dlp_feature_info.txt";
static const char *FILE_PATH_TEST = "filePathTest";
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
    std::string appId = "123456789";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;
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

    std::string appId = "123456789";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;

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
    std::string appId = "123456789";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;
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
    std::string appId = "123456789";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    int32_t ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_NE(ret, DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL);
}

/**
 * @tc.name: GetDlpFeatureInfoFromFile001
 * @tc.desc: GetDlpFeatureInfoFromFile001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, GetDlpFeatureInfoFromFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetDlpFeatureInfoFromFile001");

    int32_t ret = SetIdsTokenForAcrossAccountsPermission();
    EXPECT_EQ(ret, DLP_OK);

    uint32_t dlpFeatureInfo = 1;
    std::string appId = "123456789";
    unordered_json featureJson;
    featureJson[MDM_BUNDLE_NAME] = appId;
    featureJson[MDM_ENABLE_VALUE] = dlpFeatureInfo;

    ret = DlpFeatureInfo::SaveDlpFeatureInfoToFile(featureJson);
    EXPECT_EQ(ret, DLP_OK);

    uint32_t dlpFeature = 0;
    ret = DlpFeatureInfo::GetDlpFeatureInfoFromFile(FEATURE_INFO_DATA_FILE_PATH, dlpFeature);
    EXPECT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: GetDlpFeatureInfoFromFile002
 * @tc.desc: GetDlpFeatureInfoFromFile002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, GetDlpFeatureInfoFromFile002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetDlpFeatureInfoFromFile002");

    uint32_t dlpFeature = 0;

    int32_t ret = DlpFeatureInfo::GetDlpFeatureInfoFromFile(nullptr, dlpFeature);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: GetDlpFeatureInfoFromFile003
 * @tc.desc: GetDlpFeatureInfoFromFile003 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFeatureInfoTest, GetDlpFeatureInfoFromFile003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetDlpFeatureInfoFromFile003");

    uint32_t dlpFeature = 1;

    int32_t ret = DlpFeatureInfo::GetDlpFeatureInfoFromFile(FILE_PATH_TEST, dlpFeature);
    EXPECT_EQ(ret, DLP_ERROR_FILE_NOT_EXIST);
}