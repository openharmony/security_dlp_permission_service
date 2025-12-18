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

#include "sandbox_json_manager_test.h"
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
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "SandboxJsonManagerTest"};
}

void SandboxJsonManagerTest::SetUpTestCase() {}

void SandboxJsonManagerTest::TearDownTestCase() {}

void SandboxJsonManagerTest::SetUp() {}

void SandboxJsonManagerTest::TearDown() {}

/**
 * @tc.name: AddSandboxInfo001
 * @tc.desc: AddSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxJsonManagerTest, AddSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddSandboxInfo001");

    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    RetentionInfo retentionInfo = {
        .appIndex = -1,
        .tokenId = 827818,
        .bundleName = "testbundle1",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 10000
    };
    int32_t ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_INSERT_FILE_ERROR, ret);

    retentionInfo.appIndex = 1;
    retentionInfo.userId = -1;
    ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_INSERT_FILE_ERROR, ret);

    retentionInfo.userId = 10000;
    retentionInfo.tokenId = 0;
    ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_INSERT_FILE_ERROR, ret);
}

/**
 * @tc.name: UpdateReadFlag001
 * @tc.desc: UpdateReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxJsonManagerTest, UpdateReadFlag001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateReadFlag001");

    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    std::set<std::string> docUriSet = {"testUri"};
    RetentionInfo retentionInfo = {
        .appIndex = 0,
        .tokenId = 827818,
        .bundleName = "testbundle1",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 10000
    };
    int32_t ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_OK, ret);

    // tokenId == iter->tokenId && iter->docUriSet.empty()
    ret = sandboxJsonManager_->UpdateReadFlag(retentionInfo.tokenId);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, ret);

    // tokenId != iter->tokenId && iter->docUriSet.empty()
    ret = sandboxJsonManager_->UpdateReadFlag(retentionInfo.tokenId - 1);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, ret);

    retentionInfo.tokenId = 123;
    retentionInfo.docUriSet = docUriSet;
    ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_OK, ret);
    // tokenId != iter->tokenId && !iter->docUriSet.empty()
    ret = sandboxJsonManager_->UpdateReadFlag(retentionInfo.tokenId - 1);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, ret);

    // tokenId == iter->tokenId && !iter->docUriSet.empty()
    ret = sandboxJsonManager_->UpdateReadFlag(retentionInfo.tokenId);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: FromJson001
 * @tc.desc: FromJson test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxJsonManagerTest, FromJson001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FromJson001");
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    std::set<std::string> docUriSet = {"dlp_cert", "dlp_general_info", "encrypted_data"};

    // info.bundleName.empty()
    RetentionInfo info = {
        .appIndex = 0,
        .tokenId = 827818,
        .bundleName = "",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .docUriSet = docUriSet,
        .userId = 10000,
        .hasRead = false
    };
    Json infoJson;
    sandboxJsonManager_->RetentionInfoToJson(infoJson, info);
    Json jsonObject;
    jsonObject["retention"].push_back(infoJson);
    sandboxJsonManager_->FromJson(jsonObject);
    ASSERT_TRUE(sandboxJsonManager_->infoVec_.empty());
    jsonObject.erase("retention");

    // info.appIndex < 0
    info.bundleName = "com";
    info.appIndex = -1;
    sandboxJsonManager_->RetentionInfoToJson(infoJson, info);
    jsonObject["retention"].push_back(infoJson);
    sandboxJsonManager_->FromJson(jsonObject);
    ASSERT_TRUE(sandboxJsonManager_->infoVec_.empty());
    jsonObject.erase("retention");

    // info.userId < 0
    info.userId = -1;
    info.appIndex = 1;
    sandboxJsonManager_->RetentionInfoToJson(infoJson, info);
    jsonObject["retention"].push_back(infoJson);
    sandboxJsonManager_->FromJson(jsonObject);
    ASSERT_TRUE(sandboxJsonManager_->infoVec_.empty());
    jsonObject.erase("retention");

    // info.tokenId == 0
    info.userId = 1;
    info.tokenId = 0;
    sandboxJsonManager_->RetentionInfoToJson(infoJson, info);
    jsonObject["retention"].push_back(infoJson);
    sandboxJsonManager_->FromJson(jsonObject);
    ASSERT_TRUE(sandboxJsonManager_->infoVec_.empty());
    jsonObject.erase("retention");

    // succ
    info.userId = 1;
    info.tokenId = 1;
    sandboxJsonManager_->RetentionInfoToJson(infoJson, info);
    jsonObject["retention"].push_back(infoJson);
    sandboxJsonManager_->FromJson(jsonObject);
    ASSERT_TRUE(sandboxJsonManager_->infoVec_.size() == 1);
}

/**
 * @tc.name: RemoveRetentionInfoByUserIdTest001
 * @tc.desc: Test RemoveRetentionInfoByUserId with userId not matching
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxJsonManagerTest, RemoveRetentionInfoByUserIdTest001, TestSize.Level1) {
    SandboxJsonManager manager;
    int32_t userId = 1;
    std::set<std::string> bundleNameSet = {"bundle1"};
    RetentionInfo info;
    info.userId = 2;
    info.bundleName = "bundle1";
    info.appIndex = 0;
    manager.infoVec_.push_back(info);
 
    ASSERT_EQ(manager.RemoveRetentionInfoByUserId(userId, bundleNameSet), DLP_FILE_NO_NEED_UPDATE);
}
 
/**
 * @tc.name: RemoveRetentionInfoByUserIdTest002
 * @tc.desc: Test RemoveRetentionInfoByUserId with bundleName not matching and CheckReInstall returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SandboxJsonManagerTest, RemoveRetentionInfoByUserIdTest002, TestSize.Level1) {
    SandboxJsonManager manager;
    int32_t userId = 1;
    std::set<std::string> bundleNameSet = {"bundle2"};
    RetentionInfo info;
    info.userId = 1;
    info.bundleName = "bundle1";
    info.appIndex = 0;
    manager.infoVec_.push_back(info);
 
    ASSERT_EQ(manager.RemoveRetentionInfoByUserId(userId, bundleNameSet), DLP_FILE_NO_NEED_UPDATE);
}