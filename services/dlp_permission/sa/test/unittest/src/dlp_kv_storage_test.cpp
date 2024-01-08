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
#define protected public
#include "sandbox_config_kv_data_storage.h"
#undef protected
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpKvStorageTest"};
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
    std::string configInfo;
    int32_t res = SandboxConfigKvDataStorage::GetInstance().AddSandboxConfigIntoDataStorage(100, BUNDLE_NAME, CONFIG);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().GetSandboxConfigFromDataStorage(100, BUNDLE_NAME, configInfo);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().GetSandboxConfigFromDataStorage(1000, BUNDLE_NAME, configInfo);
    ASSERT_EQ(res, DLP_KV_GET_DATA_NOT_FOUND);
    std::set<std::string> keySet;
    res = SandboxConfigKvDataStorage::GetInstance().GetKeySetByUserId(100, keySet);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().GetKeySetByUserId(101, keySet);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(1000, BUNDLE_NAME);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(100, BUNDLE_NAME);
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().RemoveValueFromKvStore("testKey");
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().DeleteKvStore();
    ASSERT_EQ(res, DLP_OK);
}

/**
 * @tc.name: DlpKvStorageTest002
 * @tc.desc: test  DlpKvStorageTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpKvStorageTest, DlpKvStorageTest002, TestSize.Level1)
{
    int32_t res = SandboxConfigKvDataStorage::GetInstance().AddOrUpdateValue("", CONFIG);
    ASSERT_EQ(res, DLP_KV_DATE_INFO_EMPTY_ERROR);
    res = SandboxConfigKvDataStorage::GetInstance().AddOrUpdateValue(BUNDLE_NAME, "");
    ASSERT_EQ(res, DLP_KV_DATE_INFO_EMPTY_ERROR);
    bool result = SandboxConfigKvDataStorage::GetInstance().IsKeyExists("");
    ASSERT_EQ(result, false);
    res = SandboxConfigKvDataStorage::GetInstance().RemoveValueFromKvStore("testKey");
    ASSERT_EQ(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().DeleteKvStore();
    ASSERT_EQ(res, DLP_OK);
}

/**
 * @tc.name: DlpKvStorageTest003
 * @tc.desc: test DlpKvDataStorage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpKvStorageTest, DlpKvStorageTest003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DlpKvStorageTest003");
    std::string config;
    int32_t res = SandboxConfigKvDataStorage::GetInstance().GetSandboxConfigFromDataStorage(100, "", config);
    ASSERT_NE(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().AddSandboxConfigIntoDataStorage(100, "", config);
    ASSERT_NE(res, DLP_OK);
    res = SandboxConfigKvDataStorage::GetInstance().DeleteSandboxConfigFromDataStorage(100, "");
    ASSERT_NE(res, DLP_OK);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
