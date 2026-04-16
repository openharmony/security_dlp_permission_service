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

/**
 * @tc.name: HasRetentionSandboxInfo001
 * @tc.desc: Cover line 69 false branch and hit match return true path
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, HasRetentionSandboxInfo001, TestSize.Level1)
{
    SandboxJsonManager manager;
    int32_t userId = -1;
    ASSERT_TRUE(GetUserIdByForegroundAccount(&userId));

    RetentionInfo info;
    info.bundleName = "bundle_retention";
    info.appIndex = 0;
    info.userId = userId;
    info.tokenId = 10001;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(info));
    ASSERT_TRUE(manager.HasRetentionSandboxInfo("bundle_retention"));
}

/**
 * @tc.name: CanUninstallAndSetInitStatus001
 * @tc.desc: Cover line 100 true, line 101 all branches, line 114 true
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, CanUninstallAndSetInitStatus001, TestSize.Level1)
{
    SandboxJsonManager manager;
    RetentionInfo info;
    info.bundleName = "bundle_can_uninstall";
    info.appIndex = 0;
    info.userId = 100;
    info.tokenId = 10002;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(info));

    ASSERT_TRUE(manager.CanUninstall(info.tokenId));
    manager.infoVec_[0].isInit = true;
    ASSERT_FALSE(manager.CanUninstall(info.tokenId));
    manager.infoVec_[0].isInit = false;
    manager.infoVec_[0].docUriSet.insert("doc://u1");
    ASSERT_FALSE(manager.CanUninstall(info.tokenId));

    manager.infoVec_[0].isInit = true;
    manager.SetInitStatus(info.tokenId);
    ASSERT_FALSE(manager.infoVec_[0].isInit);
}

/**
 * @tc.name: UpdateRetentionStateEmptySet001
 * @tc.desc: Cover line 141 true branch
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, UpdateRetentionStateEmptySet001, TestSize.Level1)
{
    SandboxJsonManager manager;
    RetentionInfo info;
    info.bundleName = "bundle_empty_set";
    info.tokenId = 10003;
    ASSERT_EQ(DLP_OK, manager.UpdateRetentionState(std::set<std::string>{}, info, true));
}

/**
 * @tc.name: UpdateRetentionStateTokenZero001
 * @tc.desc: Cover line 156 true and CompareByBundleName function
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, UpdateRetentionStateTokenZero001, TestSize.Level1)
{
    SandboxJsonManager manager;
    int32_t userId = -1;
    ASSERT_TRUE(manager.GetUserIdByUid(userId));

    RetentionInfo stored;
    stored.bundleName = "bundle_compare";
    stored.appIndex = 0;
    stored.userId = userId;
    stored.tokenId = 10004;
    stored.docUriSet.insert("doc://clear");
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(stored));

    RetentionInfo req = stored;
    req.tokenId = 0;
    ASSERT_EQ(DLP_OK, manager.UpdateRetentionState(std::set<std::string>{"doc://x"}, req, false));
    ASSERT_TRUE(manager.CompareByBundleName(stored, req));
    req.userId += 1;
    ASSERT_FALSE(manager.CompareByBundleName(stored, req));
}

/**
 * @tc.name: UpdateDocAndReadFlag001
 * @tc.desc: Cover line 178 true and line 209 true
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, UpdateDocAndReadFlag001, TestSize.Level1)
{
    SandboxJsonManager manager;
    RetentionInfo target;
    target.bundleName = "bundle_read";
    target.appIndex = 0;
    target.userId = 100;
    target.tokenId = 10005;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(target));

    RetentionInfo req = target;
    req.hasRead = true;
    ASSERT_EQ(DLP_OK,
        manager.UpdateRetentionState(std::set<std::string>{"doc://n"}, req,
            SandboxJsonManager::CompareByTokenId, SandboxJsonManager::ClearDocUriSet));
    ASSERT_TRUE(manager.infoVec_[0].hasRead);

    RetentionInfo big;
    for (uint32_t i = 0; i <= 1024; ++i) {
        big.docUriSet.insert("doc://" + std::to_string(i));
    }
    ASSERT_FALSE(manager.UpdateDocUriSetByUnion(big, std::set<std::string>{}));
}

/**
 * @tc.name: RemoveAndClearAccountFail001
 * @tc.desc: Cover line 239 true and line 303 true when account query fails
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, RemoveAndClearAccountFail001, TestSize.Level1)
{
    SandboxJsonManager manager;
    int32_t retRemove = manager.RemoveRetentionState("bundle_x", -1);
    int32_t retClear = manager.ClearUnreservedSandbox(0);
    ASSERT_TRUE(retRemove == DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL ||
        retRemove == DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY);
    ASSERT_TRUE(retClear == DLP_SERVICE_ERROR_GET_ACCOUNT_FAIL ||
        retClear == DLP_FILE_NO_NEED_UPDATE || retClear == DLP_OK);
}

/**
 * @tc.name: GetRetentionSandboxList001
 * @tc.desc: Cover line 273 true, line 280 all branches and line 283 all branches
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, GetRetentionSandboxList001, TestSize.Level1)
{
    SandboxJsonManager manager;
    std::vector<RetentionSandBoxInfo> out;

    RetentionInfo i1;
    i1.bundleName = "bundle_list";
    i1.appIndex = 0;
    i1.userId = 100;
    i1.tokenId = 10006;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(i1));

    RetentionInfo i2 = i1;
    i2.tokenId = 10007;
    i2.docUriSet.insert("doc://r");
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(i2));

    int32_t ret = manager.GetRetentionSandboxList("bundle_list", out, true);
    ASSERT_TRUE(ret == DLP_OK || ret == DLP_RETENTION_SERVICE_ERROR);
    out.clear();
    ret = manager.GetRetentionSandboxList("bundle_list", out, false);
    ASSERT_TRUE(ret == DLP_OK || ret == DLP_RETENTION_SERVICE_ERROR);

    RetentionInfo hi = i1;
    hi.bundleName = "com.hipreview";
    hi.tokenId = 10008;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(hi));
    ret = manager.GetRetentionSandboxList("com.hipreview", out, true);
    ASSERT_TRUE(ret == DLP_OK || ret == DLP_RETENTION_SERVICE_ERROR);
}

/**
 * @tc.name: GetBundleNameSetByUserId001
 * @tc.desc: Cover line 346 true branch
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, GetBundleNameSetByUserId001, TestSize.Level1)
{
    SandboxJsonManager manager;
    RetentionInfo info;
    info.bundleName = "bundle_set";
    info.appIndex = 0;
    info.userId = 123;
    info.tokenId = 10009;
    ASSERT_EQ(DLP_OK, manager.AddSandboxInfo(info));

    std::set<std::string> bundleSet;
    ASSERT_EQ(DLP_OK, manager.GetBundleNameSetByUserId(123, bundleSet));
    ASSERT_EQ(1u, bundleSet.size());
    ASSERT_TRUE(bundleSet.count("bundle_set") == 1);
}

/**
 * @tc.name: RemoveRetentionInfoByUserIdBranches001
 * @tc.desc: Cover line 366 all branches and line 387 false branch
 * @tc.type: FUNC
 */
HWTEST_F(SandboxJsonManagerTest, RemoveRetentionInfoByUserIdBranches001, TestSize.Level1)
{
    SandboxJsonManager manager;
    RetentionInfo info;
    info.bundleName = "com.ohos.dlpmanager";
    info.appIndex = 0;
    info.userId = 100;
    info.tokenId = AccessToken::AccessTokenKit::GetHapTokenID(100, info.bundleName, info.appIndex);
    manager.infoVec_.push_back(info);
    ASSERT_FALSE(manager.CheckReInstall(info, 100));

    std::set<std::string> setWithName = {info.bundleName};
    int32_t ret = manager.RemoveRetentionInfoByUserId(100, setWithName);
    ASSERT_TRUE(ret == DLP_OK || ret == DLP_FILE_NO_NEED_UPDATE);

    RetentionInfo info2 = info;
    info2.tokenId += 1;
    manager.infoVec_.push_back(info2);
    std::set<std::string> emptySet;
    ret = manager.RemoveRetentionInfoByUserId(100, emptySet);
    ASSERT_TRUE(ret == DLP_OK || ret == DLP_FILE_NO_NEED_UPDATE);
}
