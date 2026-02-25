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

#include "dlp_set_config_test.h"
#include "want.h"
#include "set_dlp_config.h"
#include "dlp_permission_client.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpSetConfigTest"};
static const std::string WATER_MARK_CONFIG_KEY = "ohos.dlp.params.waterMarkConfig";
}

void DlpSetConfigTest::SetUpTestCase() {}

void DlpSetConfigTest::TearDownTestCase() {}

void DlpSetConfigTest::SetUp() {}

void DlpSetConfigTest::TearDown() {}

/**
 * @tc.name: SerDlpConfig001
 * @tc.desc: SerDlpConfig test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSetConfigTest, SerDlpConfig001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SerDlpConfig001");

    OHOS::AAFwk::Want want;
    want.SetParam(WATER_MARK_CONFIG_KEY, false);
    ASSERT_EQ(DlpSetConfig::SetDlpConfig(want), DLP_OK);
}

/**
 * @tc.name: SerDlpConfig002
 * @tc.desc: SerDlpConfig test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSetConfigTest, SerDlpConfig002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SerDlpConfig002");

    OHOS::AAFwk::Want want;
    want.SetParam(WATER_MARK_CONFIG_KEY, true);
    ASSERT_NE(DlpSetConfig::SetDlpConfig(want), DLP_SERVICE_ERROR_VALUE_INVALID);
}