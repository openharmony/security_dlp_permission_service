/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_set_config_test.h"
#include "dlp_set_config.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpSetConfigTestTest"};
}

void DlpSetConfigTest::SetUpTestCase() {}

void DlpSetConfigTest::TearDownTestCase() {}

void DlpSetConfigTest::SetUp() {}

void DlpSetConfigTest::TearDown() {}

/**
 * @tc.name: SetDlpConfig001
 * @tc.desc: SetDlpConfig test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpSetConfigTest, SetDlpConfig001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetDlpConfig001");

    OHOS::AAFwk::Want want;
    want.SetBoolParam("ohos.dlp.params.waterMarkConfig", false);
    ASSERT_EQ(DLP_OK, DlpSetConfig::SetDlpConfig(want));

    want.SetBoolParam("ohos.dlp.params.waterMarkConfig", true);
    ASSERT_NE(DLP_OK, DlpSetConfig::SetDlpConfig(want));
}
