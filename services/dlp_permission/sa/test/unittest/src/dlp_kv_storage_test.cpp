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

#include "dlp_kv_storage_test.h"

#include "sandbox_config_kv_data_storage.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
namespace {
static const std::string BUNDLE_NAME = "test";
static const std::string CONFIG = "testConfig";
static const std::string APP_CONFIG_STORE_ID = "sandbox_app_config_info";
KvDataStorageOptions options = { .autoSync = false };
} // namespace

void DlpKvStorageTest::SetUpTestCase() {}

void DlpKvStorageTest::TearDownTestCase() {}

void DlpKvStorageTest::SetUp() {}

void DlpKvStorageTest::TearDown() {}

/**
 * @tc.name: DlpKvStorageTest001
 * @tc.desc: test GetBundleInfo failed with param is invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpKvStorageTest, DlpKvStorageTest001, TestSize.Level1)
{
    auto sandboxConfigKvDataStorage_ = std::make_shared<SandboxConfigKvDataStorage>(options);
    std::string configInfo;
    int32_t res = sandboxConfigKvDataStorage_->AddSandboxConfigIntoDataStorage(100, BUNDLE_NAME, CONFIG);
    ASSERT_EQ(res, DLP_OK);
    res = sandboxConfigKvDataStorage_->GetSandboxConfigFromDataStorage(100, BUNDLE_NAME, configInfo);
    ASSERT_EQ(res, DLP_OK);
    res = sandboxConfigKvDataStorage_->GetSandboxConfigFromDataStorage(1000, BUNDLE_NAME, configInfo);
    ASSERT_EQ(res, DLP_KV_GET_DATA_NOT_FOUND);
    std::set<std::string> keySet;
    res = sandboxConfigKvDataStorage_->GetKeySetByUserId(100, keySet);
    ASSERT_EQ(res, DLP_OK);
    res = sandboxConfigKvDataStorage_->DeleteSandboxConfigFromDataStorage(1000, BUNDLE_NAME);
    ASSERT_EQ(res, DLP_OK);
    res = sandboxConfigKvDataStorage_->DeleteSandboxConfigFromDataStorage(100, BUNDLE_NAME);
    ASSERT_EQ(res, DLP_OK);
}

/**
 * @tc.name: DlpKvStorageTest002
 * @tc.desc: test DlpKvDataStorage create
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpKvStorageTest, DlpKvStorageTest002, TestSize.Level1)
{
    options.area = DistributedKv::EL2;
    auto sandboxConfigKvDataStorage_ = std::make_shared<SandboxConfigKvDataStorage>(options);
    ASSERT_NE(sandboxConfigKvDataStorage_, nullptr);
}

/**
 * @tc.name: DlpKvStorageTest003
 * @tc.desc: test AddOrUpdateValue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpKvStorageTest, DlpKvStorageTest003, TestSize.Level1)
{
    auto kvDataStorage_ = std::make_shared<SandboxConfigKvDataStorage>(options);
    int32_t res = kvDataStorage_->AddOrUpdateValue("", CONFIG);
    ASSERT_EQ(res, DLP_KV_DATE_INFO_EMPTY_ERROR);
    res = kvDataStorage_->AddOrUpdateValue(BUNDLE_NAME, "");
    ASSERT_EQ(res, DLP_KV_DATE_INFO_EMPTY_ERROR);
    bool result = kvDataStorage_->IsKeyExists("");
    ASSERT_EQ(result, false);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
