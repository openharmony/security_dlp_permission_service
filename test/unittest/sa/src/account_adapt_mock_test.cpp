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

#include "account_adapt_mock_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountAdaptMockTest"};
}

void AccountAdaptMockTest::SetUpTestCase() {}

void AccountAdaptMockTest::TearDownTestCase() {}

void AccountAdaptMockTest::SetUp() {}

void AccountAdaptMockTest::TearDown() {}

/**
 * @tc.name: IsAccountLogIn001
 * @tc.desc: IsAccountLogIn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountAdaptMockTest, IsAccountLogIn001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsAccountLogIn001");

    uint32_t osAccountId = 0;
    AccountType accountType = CLOUD_ACCOUNT;
    DlpBlob accountId;

    uint8_t data = 1;
    accountId.data = &data;
    accountId.size = 0;
    ASSERT_TRUE(IsAccountLogIn(osAccountId, accountType, &accountId));

    accountType = DOMAIN_ACCOUNT;
    ASSERT_TRUE(IsAccountLogIn(osAccountId, accountType, &accountId));
}

/**
 * @tc.name: GetDomainAccountName001
 * @tc.desc: GetDomainAccountName test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountAdaptMockTest, GetDomainAccountName001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetDomainAccountName001");

    char** account = new (std::nothrow) char*[10];
    ASSERT_EQ(DLP_OK, GetDomainAccountName(account));
    delete[] account;
}