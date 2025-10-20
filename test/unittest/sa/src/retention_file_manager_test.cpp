/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "retention_file_manager_test.h"
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
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "RetentionFileManagerTest"};
}

void RetentionFileManagerTest::SetUpTestCase() {}

void RetentionFileManagerTest::TearDownTestCase() {}

void RetentionFileManagerTest::SetUp() {}

void RetentionFileManagerTest::TearDown() {}

/**
 * @tc.name: UpdateReadFlag001
 * @tc.desc: UpdateReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, UpdateReadFlag001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateReadFlag001");

    uint32_t tokenId = 0;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().UpdateReadFlag(tokenId));
}