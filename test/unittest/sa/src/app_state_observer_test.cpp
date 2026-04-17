/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "app_state_observer_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#define private public
#include "app_state_observer.h"
#include "app_uninstall_observer.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;
using OHOS::AppExecFwk::RunningProcessInfo;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppStateObserverTest"};
static const int32_t DEFAULT_USERID = 100;
static const int32_t INCORRECT_UID = 777;
static const std::string DLP_BUNDLENAME = "com.ohos.dlpmanager";
static const std::string HIPREVIEW_HIGH = "com.huawei.hmos.hipreview";
static const int32_t DEFAULT_NUM = 1;
static const int UID_DEAD_PROC = 201;
static const int UID_RUNNING_PROC = 202;
static const int UID_WRONG_LABEL = 203;
static const int UID_READ_ONCE = 301;
static const int UID_LABEL_MISMATCH = 302;
}

static bool VectorContainsUri(const std::vector<std::string>& uris, const std::string& uri)
{
    for (const auto& item : uris) {
        if (item == uri) {
            return true;
        }
    }
    return false;
}

class MockAppMgrProxy final : public AppExecFwk::AppMgrProxy {
public:
    explicit MockAppMgrProxy(const std::vector<RunningProcessInfo>& infoVec)
        : AppExecFwk::AppMgrProxy(nullptr), infoVec_(infoVec) {}

    int32_t GetAllRunningProcesses(std::vector<RunningProcessInfo>& infoVec) override
    {
        infoVec = infoVec_;
        return ERR_OK;
    }

private:
    std::vector<RunningProcessInfo> infoVec_;
};

static RunningProcessInfo MakeRunningProcessInfo(int32_t uid, const std::string& processName,
    AppExecFwk::AppProcessState state, int32_t pid)
{
    RunningProcessInfo info;
    info.uid_ = uid;
    info.processName_ = processName;
    info.state_ = state;
    info.pid_ = pid;
    info.bundleNames = {processName};
    return info;
}

static void SetMockAppProxy(AppStateObserver& observer, const std::vector<RunningProcessInfo>& infoVec)
{
    observer.SetAppProxy(new (std::nothrow) MockAppMgrProxy(infoVec));
}

static InputSandboxInfo MakeInputSandboxInfo(const std::string& bundleName, int32_t userId,
    const std::string& uri, const std::string& path)
{
    return {bundleName, DLPFileAccess::READ_ONLY, userId, uri, path};
}

static EnterpriseInfo MakeEnterpriseInfo(const std::string& classificationLabel, const std::string& fileId,
    const std::string& appIdentifier)
{
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.classificationLabel = classificationLabel;
    enterpriseInfo.fileId = fileId;
    enterpriseInfo.appIdentifier = appIdentifier;
    return enterpriseInfo;
}

struct EnterpriseSandboxSpec {
    int32_t uid;
    int32_t userId;
    int32_t appIndex;
    int32_t bindAppIndex;
    std::string bundleName;
    std::string uri;
    std::string fileId;
    std::string classificationLabel;
    DLPFileAccess access;
    bool isReadOnce = false;
};

static DlpSandboxInfo MakeEnterpriseSandboxInfo(const EnterpriseSandboxSpec& spec)
{
    return {
        .uid = spec.uid,
        .userId = spec.userId,
        .appIndex = spec.appIndex,
        .bindAppIndex = spec.bindAppIndex,
        .bundleName = spec.bundleName,
        .uri = spec.uri,
        .fileId = spec.fileId,
        .classificationLabel = spec.classificationLabel,
        .dlpFileAccess = spec.access,
        .isReadOnce = spec.isReadOnce
    };
}

void AppStateObserverTest::SetUpTestCase() {}

void AppStateObserverTest::TearDownTestCase() {}

void AppStateObserverTest::SetUp() {}

void AppStateObserverTest::TearDown() {}

/**
 * @tc.name: HasDlpSandboxForUser001
 * @tc.desc: HasDlpSandboxForUser test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, HasDlpSandboxForUser001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "HasDlpSandboxForUser001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo = {
        .uid = 0,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
    ASSERT_TRUE(observer.HasDlpSandboxForUser(appInfo.userId));
}

/**
 * @tc.name: HasDlpSandboxForUser002
 * @tc.desc: HasDlpSandboxForUser test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, HasDlpSandboxForUser002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "HasDlpSandboxForUser002");

    AppStateObserver observer;
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
    ASSERT_FALSE(observer.HasDlpSandboxForUser(0));
}

/**
 * @tc.name: OnProcessDied001
 * @tc.desc: OnProcessDied test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, OnProcessDied001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnProcessDied001");
    
    AppStateObserver observer1;
    RetentionInfo info1;
    info1.tokenId = INCORRECT_UID;

    DlpSandboxInfo appInfo1 = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .tokenId = INCORRECT_UID
    };
    observer1.UninstallAllDlpSandboxForUser(appInfo1.userId);

    AppStateObserver observer2;
    DlpSandboxInfo appInfo2 = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .tokenId = INCORRECT_UID
    };
    observer2.UninstallDlpSandbox(appInfo2);

    AppStateObserver observer3;
    OHOS::AppExecFwk::ProcessData processData1;
    processData1.bundleName = "com.ohos.dlpmanager";
    processData1.processName = "com.ohos.dlpmanager";
    processData1.uid = INCORRECT_UID;

    observer3.OnProcessDied(processData1);

    AppStateObserver observer;
    OHOS::AppExecFwk::ProcessData processData;
    processData.bundleName = "com.ohos.dlpmanager";
    processData.processName = "com.ohos.dlpmanager";
    processData.uid = 0;

    observer.OnProcessDied(processData);
    ASSERT_EQ(0, processData.uid);
}

/**
 * @tc.name: UninstallDlpSandboxTest001
 * @tc.desc: UninstallDlpSandboxTest001 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, UninstallDlpSandboxTest001, TestSize.Level1)
{
    AppStateObserver observer;
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
        .tokenId = INCORRECT_UID
    };
    observer.UninstallDlpSandbox(appInfo);
    ASSERT_EQ(appInfo.tokenId, INCORRECT_UID);
}

/**
 * @tc.name: UninstallDlpSandboxTest002
 * @tc.desc: UninstallDlpSandboxTest002 test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, UninstallDlpSandboxTest002, TestSize.Level1)
{
    AppStateObserver observer;
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = HIPREVIEW_HIGH,
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
        .tokenId = INCORRECT_UID
    };
    observer.UninstallDlpSandbox(appInfo);
    ASSERT_EQ(appInfo.tokenId, INCORRECT_UID);
    appInfo.bindAppIndex = -1;
    observer.UninstallDlpSandbox(appInfo);
    ASSERT_EQ(appInfo.tokenId, INCORRECT_UID);
    appInfo.bundleName = DLP_BUNDLENAME;
    observer.UninstallDlpSandbox(appInfo);
    ASSERT_EQ(appInfo.tokenId, INCORRECT_UID);
    appInfo.bindAppIndex = 1001;
    observer.UninstallDlpSandbox(appInfo);
    ASSERT_EQ(appInfo.tokenId, INCORRECT_UID);
}

/**
 * @tc.name: OnProcessDied002
 * @tc.desc: OnProcessDied test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, OnProcessDied002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnProcessDied002");

    AppStateObserver observer;
    OHOS::AppExecFwk::ProcessData processData;
    processData.bundleName = "com.huawei.hmos.dlpcredmgr";
    processData.uid = 0;
    processData.renderUid = 0;

    observer.OnProcessDied(processData);
    ASSERT_EQ(0, processData.uid);
}

/**
 * @tc.name: OnProcessDied003
 * @tc.desc: OnProcessDied test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, OnProcessDied003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnProcessDied003");

    AppStateObserver observer;
    OHOS::AppExecFwk::ProcessData processData;
    processData.bundleName = "com.ohos.dlpmanager";
    processData.processName = "com.huawei.hmos.dlpcredmgr";
    processData.uid = 1;
    observer.AddUidWithTokenId(0, 1);

    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);

    observer.OnProcessDied(processData);
    ASSERT_EQ(1, processData.uid);
}

/**
 * @tc.name: OnProcessDied004
 * @tc.desc: OnProcessDied test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, OnProcessDied004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnProcessDied004");

    AppStateObserver observer;
    OHOS::AppExecFwk::ProcessData processData;
    processData.bundleName = "com.ohos.dlpmanager";
    processData.processName = "com.huawei.hmos.dlpcredmgr";
    processData.uid = 1;
    observer.AddUidWithTokenId(0, 1);

    DlpSandboxInfo appInfo = {
        .uid = 0,
        .userId = 123,
        .appIndex = 0,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);

    observer.OnProcessDied(processData);
    ASSERT_EQ(1, processData.uid);
}
/**
 * @tc.name: CallbackListenerEmpty001
 * @tc.desc: CallbackListenerEmpty test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, CallbackListenerEmpty001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CallbackListenerEmpty001");

    AppStateObserver observer;
    bool ret = observer.CallbackListenerEmpty();
    ASSERT_TRUE(ret);
}

/**
 * @tc.name: CheckSandboxInfo001
 * @tc.desc: CheckSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, CheckSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CheckSandboxInfo001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    appInfo.bundleName = "com.ohos.dlpmanager";
    appInfo.uid = 1;
    appInfo.appIndex = 1001;
    appInfo.tokenId = 1;
    appInfo.userId = 1;

    observer.AddDlpSandboxInfo(appInfo);
    bool ret = observer.CheckSandboxInfo(appInfo.bundleName, appInfo.appIndex, appInfo.uid);
    ASSERT_TRUE(ret);

    ret = observer.CheckSandboxInfo(appInfo.bundleName, appInfo.appIndex + 1, appInfo.uid);
    ASSERT_FALSE(ret);
}

/**
 * @tc.name: EraseDlpSandboxInfo001
 * @tc.desc: EraseDlpSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, EraseDlpSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "EraseDlpSandboxInfo001");

    AppStateObserver observer;
    int uid = 0;

    bool ret = observer.EraseDlpSandboxInfo(uid);
    ASSERT_EQ(0, ret);
}

/**
 * @tc.name: AddDlpSandboxInfo001
 * @tc.desc: AddDlpSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddDlpSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddDlpSandboxInfo001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    SandboxInfo sandboxInfo;

    observer.AddDlpSandboxInfo(appInfo);
    bool res = observer.GetOpeningSandboxInfo(appInfo.bundleName,
        appInfo.uri, appInfo.userId, sandboxInfo, appInfo.fileId);
    ASSERT_EQ(res, false);
    appInfo.uid = INCORRECT_UID;

    observer.AddDlpSandboxInfo(appInfo);
    res = observer.GetOpeningSandboxInfo(appInfo.bundleName,
        appInfo.uri, appInfo.userId, sandboxInfo, appInfo.fileId);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: GetSandboxInfo001
 * @tc.desc: GetSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxInfo001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    DlpSandboxInfo sandboxInfo;
    std::unordered_map<int32_t, DlpSandboxInfo> delSandboxInfo;
    bool res = observer.GetSandboxInfo(0, sandboxInfo);
    observer.GetDelSandboxInfo(delSandboxInfo);
    ASSERT_EQ(res, false);
}

/**
 * @tc.name: QueryDlpFileAccessByUid001
 * @tc.desc: QueryDlpFileAccessByUid test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, QueryDlpFileAccessByUid001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "QueryDlpFileAccessByUid001");

    AppStateObserver observer;
    DLPFileAccess dlpFileAccess;
    DlpSandboxInfo appInfo;
    int32_t uid = 0;

    int32_t ret = observer.QueryDlpFileAccessByUid(dlpFileAccess, uid);
    ASSERT_EQ(DLP_SERVICE_ERROR_APPOBSERVER_ERROR, ret);
    dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.dlpFileAccess = dlpFileAccess;
    observer.sandboxInfo_[uid] = appInfo;
    ret = observer.QueryDlpFileAccessByUid(dlpFileAccess, uid);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId001
 * @tc.desc: QueryDlpFileCopyableByTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, QueryDlpFileCopyableByTokenId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "QueryDlpFileCopyableByTokenId001");

    AppStateObserver observer;
    bool copyable = false;
    uint32_t tokenId = 0;

    int32_t ret = observer.QueryDlpFileCopyableByTokenId(copyable, tokenId);
    ASSERT_EQ(DLP_SERVICE_ERROR_APPOBSERVER_ERROR, ret);

    observer.AddUidWithTokenId(tokenId, 1);
    ret = observer.QueryDlpFileCopyableByTokenId(copyable, tokenId);
    ASSERT_EQ(DLP_SERVICE_ERROR_APPOBSERVER_ERROR, ret);
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId002
 * @tc.desc: QueryDlpFileCopyableByTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, QueryDlpFileCopyableByTokenId002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "QueryDlpFileCopyableByTokenId002");

    AppStateObserver observer;
    bool copyable = false;
    uint32_t tokenId = 100;
    int32_t uid = 100;
    int32_t storeUid;

    observer.AddUidWithTokenId(tokenId, uid);
    observer.GetUidByTokenId(tokenId, storeUid);
    ASSERT_TRUE(uid == storeUid);

    std::string bundleName = "test";
    int32_t appIndex = 100;
    int32_t userId = 100;
    DlpSandboxInfo appInfo = {
        .uid = uid,
        .bundleName = bundleName,
        .appIndex = appIndex,
        .userId = userId,
        .dlpFileAccess = DLPFileAccess::FULL_CONTROL
    };

    observer.AddSandboxInfo(appInfo);
    ASSERT_TRUE(observer.CheckSandboxInfo(bundleName, appIndex, userId));

    int32_t ret = observer.QueryDlpFileCopyableByTokenId(copyable, tokenId);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_TRUE(copyable);
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId003
 * @tc.desc: QueryDlpFileCopyableByTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, QueryDlpFileCopyableByTokenId003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "QueryDlpFileCopyableByTokenId003");

    AppStateObserver observer;
    bool copyable = false;
    uint32_t tokenId = 100;
    int32_t uid = 100;
    int32_t storeUid;

    observer.AddUidWithTokenId(tokenId, uid);
    observer.GetUidByTokenId(tokenId, storeUid);
    ASSERT_TRUE(uid == storeUid);

    std::string bundleName = "test";
    int32_t appIndex = 100;
    int32_t userId = 100;
    DlpSandboxInfo appInfo = {
        .uid = uid,
        .bundleName = bundleName,
        .appIndex = appIndex,
        .userId = userId,
        .dlpFileAccess = DLPFileAccess::READ_ONLY
    };

    observer.AddSandboxInfo(appInfo);
    ASSERT_TRUE(observer.CheckSandboxInfo(bundleName, appIndex, userId));

    int32_t ret = observer.QueryDlpFileCopyableByTokenId(copyable, tokenId);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_FALSE(copyable);
}

/**
 * @tc.name: GetOpeningReadOnlySandbox001
 * @tc.desc: GetOpeningReadOnlySandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningReadOnlySandbox001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningReadOnlySandbox001");
    AppStateObserver observer;
    int32_t appIndex = -1;
    int32_t bindAppIndex = -1;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(appIndex, -1);
    ASSERT_EQ(bindAppIndex, -1);

    DlpSandboxInfo appInfo;
    appInfo.bundleName = DLP_BUNDLENAME;
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.uid = DEFAULT_NUM;
    appInfo.appIndex = DEFAULT_NUM;
    appInfo.tokenId = DEFAULT_NUM;
    appInfo.userId = DEFAULT_USERID;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.tokenIdToUidMap_[DEFAULT_NUM] = DEFAULT_NUM;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(appIndex, appInfo.appIndex);
    appInfo.dlpFileAccess = DLPFileAccess::CONTENT_EDIT;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(appIndex, -1);
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.bundleName = "";
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(appIndex, -1);
    appInfo.userId = 0;
    appInfo.bundleName = DLP_BUNDLENAME;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(appIndex, -1);
    observer.sandboxInfo_.clear();
}

/**
 * @tc.name: GetOpeningReadOnlyBindSandbox001
 * @tc.desc: GetOpeningReadOnlyBindSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningReadOnlyBindSandbox001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningReadOnlySandbox001");
    AppStateObserver observer;
    int32_t bindAppIndex = -1;
    int32_t appIndex = -1;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    ASSERT_EQ(bindAppIndex, -1);
 
    DlpSandboxInfo appInfo;
    appInfo.bundleName = DLP_BUNDLENAME;
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.uid = DEFAULT_NUM;
    appInfo.appIndex = DEFAULT_NUM;
    appInfo.bindAppIndex = DEFAULT_NUM;
    appInfo.tokenId = DEFAULT_NUM;
    appInfo.userId = DEFAULT_USERID;
    appInfo.isReadOnce = false;
    observer.AddSandboxInfo(appInfo);
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    observer.EraseSandboxInfo(appInfo.uid);
    ASSERT_EQ(bindAppIndex, appInfo.bindAppIndex);
    appInfo.dlpFileAccess = DLPFileAccess::CONTENT_EDIT;
    observer.AddSandboxInfo(appInfo);
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    observer.EraseSandboxInfo(appInfo.uid);
    ASSERT_EQ(bindAppIndex, -1);
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.bundleName = "";
    observer.AddSandboxInfo(appInfo);
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    observer.EraseSandboxInfo(appInfo.uid);
    ASSERT_EQ(bindAppIndex, -1);
    appInfo.userId = 0;
    appInfo.bundleName = DLP_BUNDLENAME;
    observer.AddSandboxInfo(appInfo);
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex, bindAppIndex);
    observer.EraseSandboxInfo(appInfo.uid);
    ASSERT_EQ(bindAppIndex, -1);
    observer.sandboxInfo_.clear();
}
/**
 * @tc.name: AddSandboxInfo001
 * @tc.desc: AddSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddSandboxInfo001");
    AppStateObserver observer;
    int32_t uid = 1;

    DlpSandboxInfo appInfo;
    observer.AddSandboxInfo(appInfo);
    observer.UpdatReadFlag(uid);
    ASSERT_FALSE(observer.sandboxInfo_[appInfo.uid].hasRead);

    appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
    observer.UpdatReadFlag(uid);
    ASSERT_TRUE(observer.sandboxInfo_[appInfo.uid].hasRead);
}

/**
 * @tc.name: AddSandboxInfo002
 * @tc.desc: AddSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddSandboxInfo002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddSandboxInfo002");
    AppStateObserver observer;

    DlpSandboxInfo appInfo1 = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    DlpSandboxInfo appInfo2 = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo1);
    observer.AddSandboxInfo(appInfo2);
    ASSERT_FALSE(observer.sandboxInfo_[appInfo1.uid].hasRead);
}

/**
 * @tc.name: ExitSaAfterAllDlpManagerDie001
 * @tc.desc: AppStateObserver test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, ExitSaAfterAllDlpManagerDie001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ExitSaAfterAllDlpManagerDie001");
    AppStateObserver observer;
    observer.ExitSaAfterAllDlpManagerDie();
    int32_t uid = 1;
    DlpSandboxInfo appInfo;
    observer.AddSandboxInfo(appInfo);
    observer.UpdatReadFlag(uid);
    ASSERT_FALSE(observer.sandboxInfo_[appInfo.uid].hasRead);
    observer.ExitSaAfterAllDlpManagerDie();
}

/**
 * @tc.name: ExitSaAfterAllDlpManagerDie002
 * @tc.desc: AppStateObserver test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, ExitSaAfterAllDlpManagerDie002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ExitSaAfterAllDlpManagerDie002");
    AppStateObserver observer;
    observer.ExitSaAfterAllDlpManagerDie();
    int32_t uid = 1;
    DlpSandboxInfo appInfo;
    observer.AddSandboxInfo(appInfo);
    observer.UpdatReadFlag(uid);
    ASSERT_FALSE(observer.sandboxInfo_[appInfo.uid].hasRead);
    observer.ExitSaAfterAllDlpManagerDie();
    observer.AddCallbackListener(uid);
    observer.ExitSaAfterAllDlpManagerDie();
    observer.UninstallAllDlpSandbox();
    observer.ExitSaAfterAllDlpManagerDie();
}

/**
 * @tc.name: EraseUserId001
 * @tc.desc: AppStateObserver test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, EraseUserId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "EraseUserId001");
    AppStateObserver observer;
    int32_t uid = 1;
    observer.EraseUserId(uid);
    observer.AddUserId(uid);
    observer.EraseUserId(uid);
    observer.AddUserId(uid);
    ASSERT_TRUE(observer.CallbackListenerEmpty());
}

/**
 * @tc.name: AddUidWithTokenId001
 * @tc.desc: AddUidWithTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddUidWithTokenId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddUidWithTokenId001");
    AppStateObserver observer;
    int32_t uid = 1;
    observer.EraseUidTokenIdMap(100);
    observer.AddUidWithTokenId(100, uid);
    observer.EraseUidTokenIdMap(100);
    ASSERT_TRUE(observer.CallbackListenerEmpty());
}

/**
 * @tc.name: AddUidWithTokenId002
 * @tc.desc: AddUidWithTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddUidWithTokenId002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddUidWithTokenId002");
    AppStateObserver observer;
    int32_t uid = 1;
    observer.AddUidWithTokenId(100, uid);
    observer.AddUidWithTokenId(100, uid);
    observer.EraseUidTokenIdMap(100);
    ASSERT_TRUE(observer.CallbackListenerEmpty());
}

/**
 * @tc.name: GetUidByTokenId002
 * @tc.desc: GetUidByTokenId test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetUidByTokenId002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetUidByTokenId002");
    AppStateObserver observer;
    int32_t uid = 1;
    int32_t uid_t = 0;
    observer.AddUidWithTokenId(100, uid);
    observer.GetUidByTokenId(100, uid_t);
    ASSERT_TRUE(uid_t == uid);
}

/**
 * @tc.name: GetOpeningReadOnlySandbox002
 * @tc.desc: GetOpeningReadOnlySandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningReadOnlySandbox002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningReadOnlySandbox002");
    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .dlpFileAccess = DLPFileAccess::READ_ONLY,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);

    std::string bundleName = "testbundle1";
    int32_t userId = 123;
    int32_t appIndex = 0;
    int32_t bindAppIndex = -1;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    userId = 123;

    observer.EraseSandboxInfo(1);

    appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .dlpFileAccess = DLPFileAccess::NO_PERMISSION,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);

    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, bindAppIndex);
    ASSERT_TRUE(observer.CallbackListenerEmpty());
}

/**
 * @tc.name: GetOpeningReadOnlyBindSandbox002
 * @tc.desc: GetOpeningReadOnlyBindSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningReadOnlyBindSandbox002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningReadOnlyBindSandbox002");
    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .bindAppIndex = 0,
        .dlpFileAccess = DLPFileAccess::READ_ONLY,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
 
    std::string bundleName = "testbundle1";
    int32_t userId = 123;
    int32_t appIndex = 0;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    userId = 123;
 
    observer.EraseSandboxInfo(1);
 
    appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 0,
        .bindAppIndex = 0,
        .dlpFileAccess = DLPFileAccess::NO_PERMISSION,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
 
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex, appIndex);
    ASSERT_TRUE(observer.CallbackListenerEmpty());
}

/**
 * @tc.name: GetRunningProcessesInfo001
 * @tc.desc: GetRunningProcessesInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetRunningProcessesInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetRunningProcessesInfo001");
    AppStateObserver observer;
    vector<RunningProcessInfo> infoVec;
    observer.GetRunningProcessesInfo(infoVec);
    ASSERT_TRUE(infoVec.empty());
}

/**
 * @tc.name: GetOpeningSandboxInfo001
 * @tc.desc: GetOpeningSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningSandboxInfo001");
    AppStateObserver observer;
    SandboxInfo SandboxInfo;
    string bundleName = "testbundle1";
    int32_t userId = 123;
    string uri = "123";
    string fileId = "123";
    DlpSandboxInfo appInfo1 = {
        .uid = 1,
        .userId = 1231,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .uri = "123",
        .fileId = "123"
    };
    observer.AddSandboxInfo(appInfo1);
    DlpSandboxInfo appInfo2 = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .uri = "123",
        .fileId = "123"
    };
    observer.AddSandboxInfo(appInfo2);
    ASSERT_FALSE(observer.GetOpeningSandboxInfo(bundleName, uri, userId, SandboxInfo, fileId));
}

/**
 * @tc.name: GetOpeningSandboxInfo002
 * @tc.desc: GetOpeningSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningSandboxInfo002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningSandboxInfo002");
    AppStateObserver observer;
    SandboxInfo SandboxInfo;
    int32_t userId = 100;
    string bundleName = "testbundle1";
    string uri = "123";
    string fileId = "123";
    DlpSandboxInfo appInfo1 = {
        .userId = 100
    };
    observer.AddSandboxInfo(appInfo1);
    DlpSandboxInfo appInfo2 = {
        .userId = 100,
        .bundleName = "testbundle1"
    };
    observer.AddSandboxInfo(appInfo2);
    DlpSandboxInfo appInfo3 = {
        .userId = 100,
        .bundleName = "testbundle1",
        .uri = "123"
    };
    observer.AddSandboxInfo(appInfo3);
    DlpSandboxInfo appInfo4 = {
        .userId = 100,
        .bundleName = "testbundle1",
        .uri = "123",
        .fileId = "123"
    };
    observer.AddSandboxInfo(appInfo4);
    ASSERT_FALSE(observer.GetOpeningSandboxInfo(bundleName, uri, userId, SandboxInfo, fileId));
}


/**
 * @tc.name: RemoveCallbackListener001
 * @tc.desc: RemoveCallbackListener test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, RemoveCallbackListener001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RemoveCallbackListener001");
    AppStateObserver observer;
    observer.callbackList_[1] = 1;
    ASSERT_TRUE(observer.RemoveCallbackListener(1));
    ASSERT_FALSE(observer.RemoveCallbackListener(1));
}

/**
 * @tc.name: IsInDlpSandbox001
 * @tc.desc: IsInDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, IsInDlpSandbox, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsInDlpSandbox");
    AppStateObserver observer;
    bool isSandbox;
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    observer.AddSandboxInfo(appInfo);
    int32_t ret = observer.IsInDlpSandbox(isSandbox, 1);

    observer.DumpSandbox(1);

    DlpEventSubSubscriber dlpEventSubSubscriber;
    dlpEventSubSubscriber.subscriber_ = nullptr;

    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: AddUriAndFileInfo001
 * @tc.desc: AddUriAndFileInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddUriAndFileInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddUriAndFileInfo001");
    AppStateObserver observer;
    FileInfo fileInfo;
    std::string uri1 = "uri";
    std::string uri2 = "";
    fileInfo.isNotOwnerAndReadOnce = true;
    ASSERT_TRUE(observer.AddUriAndFileInfo(uri1, fileInfo));
    fileInfo.isNotOwnerAndReadOnce = false;
    ASSERT_FALSE(observer.AddUriAndFileInfo(uri2, fileInfo));
    FileInfo fileInfo2;
    ASSERT_TRUE(observer.GetFileInfoByUri(uri1, fileInfo2));
    ASSERT_FALSE(observer.GetFileInfoByUri(uri2, fileInfo2));
    observer.EraseFileInfoByUri(uri1);
    observer.EraseFileInfoByUri(uri2);
    ASSERT_FALSE(observer.GetFileInfoByUri(uri1, fileInfo2));
    ASSERT_FALSE(observer.GetFileInfoByUri(uri2, fileInfo2));
}

/**
 * @tc.name: AddUriAndEnterpriseInfo001
 * @tc.desc: AddUriAndEnterpriseInfo and GetEnterpriseInfoByUri test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddUriAndEnterpriseInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddUriAndEnterpriseInfo001");
    AppStateObserver observer;

    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.classificationLabel = "L1";
    enterpriseInfo.fileId = "f1";
    enterpriseInfo.appIdentifier = "app1";

    ASSERT_FALSE(observer.AddUriAndEnterpriseInfo("", enterpriseInfo));
    ASSERT_TRUE(observer.AddUriAndEnterpriseInfo("uri1", enterpriseInfo));

    EnterpriseInfo queryInfo;
    ASSERT_TRUE(observer.GetEnterpriseInfoByUri("uri1", queryInfo));
    ASSERT_EQ(queryInfo.classificationLabel, "L1");
    ASSERT_EQ(queryInfo.fileId, "f1");
    ASSERT_EQ(queryInfo.appIdentifier, "app1");
    ASSERT_FALSE(observer.GetEnterpriseInfoByUri("uri_not_exist", queryInfo));
}

/**
 * @tc.name: EnterpriseUriMapQuery001
 * @tc.desc: enterprise uri query and erase flow test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, EnterpriseUriMapQuery001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "EnterpriseUriMapQuery001");
    AppStateObserver observer;

    EnterpriseInfo info1;
    info1.classificationLabel = "L1";
    info1.fileId = "f1";
    info1.appIdentifier = "appA";
    info1.uid = -1;

    EnterpriseInfo info2 = info1;
    info2.classificationLabel = "L2";
    info2.fileId = "f2";

    EnterpriseInfo info3 = info1;
    info3.fileId = "f3";
    info3.appIdentifier = "appB";

    ASSERT_TRUE(observer.AddUriAndEnterpriseInfo("uri1", info1));
    ASSERT_TRUE(observer.AddUriAndEnterpriseInfo("uri2", info2));
    ASSERT_TRUE(observer.AddUriAndEnterpriseInfo("uri3", info3));

    // FileId mismatch should not update uid.
    observer.UpdateEnterpriseUidByUri("uri1", "f_not_match", 101);
    std::vector<std::string> resultUris;
    observer.GetSandboxInfosByClassificationLabel("L1", "appA", resultUris);
    ASSERT_TRUE(resultUris.empty());

    observer.UpdateEnterpriseUidByUri("uri1", "f1", 101);
    observer.UpdateEnterpriseUidByUri("uri2", "f2", 102);
    observer.UpdateEnterpriseUidByUri("uri3", "f3", 103);

    observer.GetSandboxInfosByClassificationLabel("L1", "appA", resultUris);
    ASSERT_EQ(resultUris.size(), 1);
    ASSERT_TRUE(VectorContainsUri(resultUris, "uri1"));

    observer.GetSandboxInfosByClassificationLabel("", "appA", resultUris);
    ASSERT_EQ(resultUris.size(), 2);
    ASSERT_TRUE(VectorContainsUri(resultUris, "uri1"));
    ASSERT_TRUE(VectorContainsUri(resultUris, "uri2"));

    observer.EraseEnterpriseInfoByUri("uri1", "f_not_match");
    EnterpriseInfo queryInfo;
    ASSERT_TRUE(observer.GetEnterpriseInfoByUri("uri1", queryInfo));

    observer.EraseEnterpriseInfoByUri("uri1", "f1");
    ASSERT_FALSE(observer.GetEnterpriseInfoByUri("uri1", queryInfo));
}

/**
 * @tc.name: GetNeededDelEnterpriseSandbox001
 * @tc.desc: get and erase enterprise sandbox info by label and appIdentifier
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetNeededDelEnterpriseSandbox001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetNeededDelEnterpriseSandbox001");
    AppStateObserver observer;

    DlpSandboxInfo sandboxInfo1;
    sandboxInfo1.uid = UID_DEAD_PROC;
    sandboxInfo1.classificationLabel = "L1";
    sandboxInfo1.appIdentifier = "appA";
    observer.sandboxInfo_[sandboxInfo1.uid] = sandboxInfo1;

    DlpSandboxInfo sandboxInfo2;
    sandboxInfo2.uid = UID_RUNNING_PROC;
    sandboxInfo2.classificationLabel = "L2";
    sandboxInfo2.appIdentifier = "appA";
    observer.sandboxInfo_[sandboxInfo2.uid] = sandboxInfo2;

    EnterpriseInfo enterpriseInfo1;
    enterpriseInfo1.uid = UID_DEAD_PROC;
    enterpriseInfo1.fileId = "f1";
    enterpriseInfo1.classificationLabel = "L1";
    enterpriseInfo1.appIdentifier = "appA";
    observer.enterpriseUriMap_["uri1"] = enterpriseInfo1;

    EnterpriseInfo enterpriseInfo2;
    enterpriseInfo2.uid = UID_RUNNING_PROC;
    enterpriseInfo2.fileId = "f2";
    enterpriseInfo2.classificationLabel = "L2";
    enterpriseInfo2.appIdentifier = "appA";
    observer.enterpriseUriMap_["uri2"] = enterpriseInfo2;

    std::vector<DlpSandboxInfo> appInfos;
    observer.GetNeededDelEnterpriseSandbox("L1", "appA", appInfos);
    ASSERT_EQ(appInfos.size(), 1);
    ASSERT_EQ(appInfos[0].uid, UID_DEAD_PROC);
    ASSERT_TRUE(observer.enterpriseUriMap_.find("uri1") == observer.enterpriseUriMap_.end());
    ASSERT_TRUE(observer.enterpriseUriMap_.find("uri2") != observer.enterpriseUriMap_.end());
}

/**
 * @tc.name: PostDelayUnloadTask001
 * @tc.desc: PostDelayUnloadTask test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, PostDelayUnloadTask001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "PostDelayUnloadTask001");
    AppStateObserver observer;
    observer.GetTerminalMutex();
    observer.PostDelayUnloadTask(CurrentTaskState::IDLE);
    ASSERT_EQ(observer.taskState_, CurrentTaskState::IDLE);
    observer.PostDelayUnloadTask(CurrentTaskState::LONG_TASK);
    observer.PostDelayUnloadTask(CurrentTaskState::SHORT_TASK);
}

/**
 * @tc.name: CheckHasBackgroundTask001
 * @tc.desc: CheckHasBackgroundTask test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, CheckHasBackgroundTask001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CheckHasBackgroundTask001");
    AppStateObserver observer;
    observer.CheckHasBackgroundTask();
    ASSERT_EQ(observer.InitUnloadHandler(), true);
}

/**
 * @tc.name: InitUnloadHandler001
 * @tc.desc: InitUnloadHandler test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, InitUnloadHandler001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "InitUnloadHandler001");
    AppStateObserver observer;
    ASSERT_EQ(observer.InitUnloadHandler(), true);
    OHOS::AppExecFwk::ProcessData processData1;
    processData1.bundleName = "com.ohos.dlpmanager";
    processData1.processName = "com.ohos.dlpmanager";
    processData1.uid = DEFAULT_USERID;
    observer.OnDlpmanagerDied(processData1);
}

/**
 * @tc.name: AddMaskInfoCnt001
 * @tc.desc: AddMaskInfoCnt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddMaskInfoCnt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddMaskInfoCnt001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    observer.AddMaskInfoCnt(appInfo);
    appInfo.bundleName = "DlpTest";
    appInfo.isWatermark = true;
    appInfo.tokenId = 100;
    appInfo.appIndex = 100;
    appInfo.maskInfo = "name1";
    observer.AddMaskInfoCnt(appInfo);
    observer.AddMaskInfoCnt(appInfo);
    ASSERT_EQ(1, observer.maskInfoMap_.size());
    ASSERT_EQ(2, observer.maskInfoMap_[appInfo.maskInfo]);
    appInfo.maskInfo = "name2";
    observer.AddMaskInfoCnt(appInfo);
    ASSERT_EQ(2, observer.maskInfoMap_.size());
}

/**
 * @tc.name: DecMaskInfoCnt001
 * @tc.desc: DecMaskInfoCnt test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, DecMaskInfoCnt001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DecMaskInfoCnt001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    appInfo.isWatermark = false;
    observer.DecMaskInfoCnt(appInfo);

    appInfo.isWatermark = true;
    observer.DecMaskInfoCnt(appInfo);

    appInfo.accountAndUserId = "";
    appInfo.userId = 0;
    observer.DecMaskInfoCnt(appInfo);
    ASSERT_EQ(0, observer.maskInfoMap_.size());
    appInfo.bundleName = "DlpTest";
    appInfo.tokenId = 100;
    appInfo.appIndex = 100;
    appInfo.accountAndUserId = "name1";
    observer.AddMaskInfoCnt(appInfo);
    ASSERT_EQ(1, observer.maskInfoMap_.size());
    observer.DecMaskInfoCnt(appInfo);
}

/**
 * @tc.name: GetSandboxInfoByAppIndex001
 * @tc.desc: GetSandboxInfoByAppIndex test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetSandboxInfoByAppIndex001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxInfoByAppIndex001");
    AppStateObserver observer;
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bindAppIndex = 1001,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    std::string bundleName = "testbundle1";
    int32_t appIndex = 2;
    observer.AddSandboxInfo(appInfo);
    ASSERT_EQ(true, observer.GetSandboxInfoByAppIndex(bundleName, appIndex, appInfo));
    appIndex = -1;
    bundleName = "testbundle2";
    ASSERT_EQ(false, observer.GetSandboxInfoByAppIndex(bundleName, appIndex, appInfo));
    appIndex = 2;
    bundleName = "testbundle2";
    ASSERT_EQ(false, observer.GetSandboxInfoByAppIndex(bundleName, appIndex, appInfo));
    appIndex = -1;
    bundleName = "testbundle1";
    ASSERT_EQ(false, observer.GetSandboxInfoByAppIndex(bundleName, appIndex, appInfo));
}

/**
 * @tc.name: UpdatePidWhenSandboxExists001
 * @tc.desc: Test updating PID when sandbox already exists
 * @tc.type: FUNC
 * @tc.require: fix PID mismatch issue when DlpManager restarts
 */
HWTEST_F(AppStateObserverTest, UpdatePidWhenSandboxExists001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdatePidWhenSandboxExists001");
    AppStateObserver observer;

    // First add sandbox with PID=1001
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .pid = 1001
    };
    observer.AddSandboxInfo(appInfo);
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].pid, 1001);

    // Add sandbox again with new PID=2002 (simulating DlpManager restart)
    DlpSandboxInfo newAppInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .pid = 2002
    };
    observer.AddSandboxInfo(newAppInfo);

    // Verify PID is updated to new value
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].pid, 2002);
    DLP_LOG_INFO(LABEL, "PID updated from 1001 to 2002 successfully");
}

/**
 * @tc.name: UpdatePidWhenSandboxExists002
 * @tc.desc: Test PID update does not affect other sandbox info
 * @tc.type: FUNC
 * @tc.require: verify other fields remain unchanged when updating PID
 */
HWTEST_F(AppStateObserverTest, UpdatePidWhenSandboxExists002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdatePidWhenSandboxExists002");
    AppStateObserver observer;

    // First add sandbox with full info
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = true,
        .pid = 1001,
        .uri = "test_uri",
        .fileId = "test_file_id",
        .dlpFileAccess = DLPFileAccess::READ_ONLY
    };
    observer.AddSandboxInfo(appInfo);

    // Update with new PID only
    DlpSandboxInfo newAppInfo = {
        .uid = 1,
        .userId = 456,  // Different userId
        .appIndex = 3,  // Different appIndex
        .bundleName = "testbundle2",  // Different bundleName
        .hasRead = false,  // Different hasRead
        .pid = 2002  // New PID
    };
    observer.AddSandboxInfo(newAppInfo);

    // Verify only PID is updated, other fields remain unchanged
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].pid, 2002);
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].userId, 123);
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].appIndex, 2);
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].bundleName, "testbundle1");
    ASSERT_TRUE(observer.sandboxInfo_[appInfo.uid].hasRead);
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].uri, "test_uri");
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].fileId, "test_file_id");
    ASSERT_EQ(observer.sandboxInfo_[appInfo.uid].dlpFileAccess, DLPFileAccess::READ_ONLY);
    DLP_LOG_INFO(LABEL, "Other fields remain unchanged when updating PID");
}

/**
 * @tc.name: FillSandboxInfoIfProcessRunning001
 * @tc.desc: Cover all branches of FillSandboxInfoIfProcessRunning
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, FillSandboxInfoIfProcessRunning001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FillSandboxInfoIfProcessRunning001");
    AppStateObserver observer;

    DlpSandboxInfo appInfo;
    appInfo.uid = 100;
    appInfo.appIndex = 12;
    appInfo.bindAppIndex = 34;
    appInfo.tokenId = 56;

    SandboxInfo sandboxInfo;

    std::vector<RunningProcessInfo> infoVec1 = {
        MakeRunningProcessInfo(
            101, "other_process", AppExecFwk::AppProcessState::APP_STATE_FOREGROUND, 201),
        MakeRunningProcessInfo(100, "dead_process", AppExecFwk::AppProcessState::APP_STATE_END, 202),
    };
    SetMockAppProxy(observer, infoVec1);
    ASSERT_FALSE(observer.FillSandboxInfoIfProcessRunning(appInfo, sandboxInfo));
    ASSERT_EQ(-1, sandboxInfo.appIndex);
    ASSERT_EQ(-1, sandboxInfo.bindAppIndex);
    ASSERT_EQ(0, sandboxInfo.tokenId);

    std::vector<RunningProcessInfo> infoVec2 = {
        MakeRunningProcessInfo(
            101, "other_process", AppExecFwk::AppProcessState::APP_STATE_FOREGROUND, 201),
        MakeRunningProcessInfo(
            100, "running_process", AppExecFwk::AppProcessState::APP_STATE_FOREGROUND, 203),
    };
    SetMockAppProxy(observer, infoVec2);
    sandboxInfo = {};
    ASSERT_TRUE(observer.FillSandboxInfoIfProcessRunning(appInfo, sandboxInfo));
    ASSERT_EQ(appInfo.appIndex, sandboxInfo.appIndex);
    ASSERT_EQ(appInfo.bindAppIndex, sandboxInfo.bindAppIndex);
    ASSERT_EQ(appInfo.tokenId, sandboxInfo.tokenId);

    observer.SetAppProxy(nullptr);
    sandboxInfo = {};
    ASSERT_FALSE(observer.FillSandboxInfoIfProcessRunning(appInfo, sandboxInfo));
}

/**
 * @tc.name: GetOpeningEnterpriseSandboxInfo001
 * @tc.desc: Cover all branches of GetOpeningEnterpriseSandboxInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningEnterpriseSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningEnterpriseSandboxInfo001");
    AppStateObserver observer;
    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");

    SandboxInfo sandboxInfo;
    ASSERT_FALSE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, enterpriseInfo));
    InputSandboxInfo mismatchBundle = MakeInputSandboxInfo(
        "com.example.enterprise.other", 100, "uri://enterprise", "/data/test");
    ASSERT_FALSE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, mismatchBundle, enterpriseInfo));
    EnterpriseInfo mismatchFile = enterpriseInfo;
    mismatchFile.fileId = "file_other";
    ASSERT_FALSE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, mismatchFile));

    DlpSandboxInfo deadInfo = MakeEnterpriseSandboxInfo({
        UID_DEAD_PROC,
        100,
        10,
        20,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        enterpriseInfo.classificationLabel,
        DLPFileAccess::READ_ONLY,
        false,
    });
    observer.AddSandboxInfo(deadInfo);
    SetMockAppProxy(observer, {
        MakeRunningProcessInfo(UID_DEAD_PROC, "enterprise_dead", AppExecFwk::AppProcessState::APP_STATE_END, 301),
    });
    ASSERT_FALSE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, enterpriseInfo));
}

/**
 * @tc.name: GetOpeningEnterpriseSandboxInfo002
 * @tc.desc: Cover running and wrong-label branches for enterprise sandbox info
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningEnterpriseSandboxInfo002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningEnterpriseSandboxInfo002");
    AppStateObserver observer;
    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");
    SandboxInfo sandboxInfo;

    DlpSandboxInfo runningInfo = MakeEnterpriseSandboxInfo({
        UID_RUNNING_PROC,
        100,
        10,
        20,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        enterpriseInfo.classificationLabel,
        DLPFileAccess::READ_ONLY,
        false,
    });
    observer.AddSandboxInfo(runningInfo);
    SetMockAppProxy(observer, {
        MakeRunningProcessInfo(
            UID_RUNNING_PROC, "enterprise_running", AppExecFwk::AppProcessState::APP_STATE_FOREGROUND, 302),
    });
    sandboxInfo = {};
    ASSERT_TRUE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, enterpriseInfo));
    ASSERT_EQ(runningInfo.appIndex, sandboxInfo.appIndex);
    ASSERT_EQ(runningInfo.bindAppIndex, sandboxInfo.bindAppIndex);
    ASSERT_EQ(runningInfo.tokenId, sandboxInfo.tokenId);

    observer.EraseSandboxInfo(runningInfo.uid);
    DlpSandboxInfo wrongLabel = MakeEnterpriseSandboxInfo({
        UID_WRONG_LABEL,
        200,
        10,
        20,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        "L2",
        DLPFileAccess::READ_ONLY,
        false,
    });
    observer.AddSandboxInfo(wrongLabel);
    sandboxInfo = {};
    ASSERT_FALSE(observer.GetOpeningEnterpriseSandboxInfo(sandboxInfo, inputSandboxInfo, enterpriseInfo));
}

/**
 * @tc.name: VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch
 * @tc.desc: Verify no-match branches for enterprise read-only sandbox query
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch");
    AppStateObserver observer;
    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");
    DlpSandboxInfo dlpSandboxInfo;

    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);

    DlpSandboxInfo wrongAccessInfo = MakeEnterpriseSandboxInfo({
        300,
        inputSandboxInfo.userId,
        30,
        40,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        enterpriseInfo.classificationLabel,
        DLPFileAccess::CONTENT_EDIT,
        false,
    });
    observer.AddSandboxInfo(wrongAccessInfo);
    dlpSandboxInfo = {};
    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);

    observer.EraseSandboxInfo(wrongAccessInfo.uid);
    DlpSandboxInfo readOnceInfo = wrongAccessInfo;
    readOnceInfo.uid = UID_READ_ONCE;
    readOnceInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    readOnceInfo.isReadOnce = true;
    observer.AddSandboxInfo(readOnceInfo);
    dlpSandboxInfo = {};
    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);
}

/**
 * @tc.name: VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch002
 * @tc.desc: Verify label mismatch no-match branch for enterprise read-only sandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "VerifyGetOpeningEnterpriseReadOnlySandboxNoMatch002");
    AppStateObserver observer;
    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");
    DlpSandboxInfo dlpSandboxInfo;

    DlpSandboxInfo baseInfo = MakeEnterpriseSandboxInfo({
        300,
        inputSandboxInfo.userId,
        30,
        40,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        enterpriseInfo.classificationLabel,
        DLPFileAccess::READ_ONLY,
        false,
    });

    DlpSandboxInfo labelMismatchInfo = baseInfo;
    labelMismatchInfo.uid = UID_LABEL_MISMATCH;
    labelMismatchInfo.classificationLabel = "L2";
    observer.AddSandboxInfo(labelMismatchInfo);
    dlpSandboxInfo = {};
    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);
}

/**
 * @tc.name: VerifyGetOpeningEnterpriseReadOnlySandboxMatch
 * @tc.desc: Verify match branches for enterprise read-only sandbox query
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, VerifyGetOpeningEnterpriseReadOnlySandboxMatch, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "VerifyGetOpeningEnterpriseReadOnlySandboxMatch");
    AppStateObserver observer;
    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");
    enterpriseInfo.appIdentifier = "test";
    DlpSandboxInfo dlpSandboxInfo;

    DlpSandboxInfo matchInfo = MakeEnterpriseSandboxInfo({
        303,
        inputSandboxInfo.userId,
        30,
        40,
        inputSandboxInfo.bundleName,
        inputSandboxInfo.uri,
        enterpriseInfo.fileId,
        enterpriseInfo.classificationLabel,
        DLPFileAccess::READ_ONLY,
        false,
    });
    matchInfo.appIdentifier = "test";
    observer.AddSandboxInfo(matchInfo);
    dlpSandboxInfo = {};
    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(matchInfo.appIndex, dlpSandboxInfo.appIndex);
    ASSERT_EQ(matchInfo.bindAppIndex, dlpSandboxInfo.bindAppIndex);

    InputSandboxInfo mismatchBundleInput = MakeInputSandboxInfo(
        "com.example.enterprise.other", inputSandboxInfo.userId, inputSandboxInfo.uri, inputSandboxInfo.path);
    dlpSandboxInfo = {};
    observer.GetOpeningEnterpriseReadOnlySandbox(mismatchBundleInput, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);
}

/**
 * @tc.name: GetOpeningEnterpriseReadOnlySandbox001
 * @tc.desc: Cover all branches of GetOpeningEnterpriseReadOnlySandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, GetOpeningEnterpriseReadOnlySandbox001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetOpeningEnterpriseReadOnlySandbox001");
    AppStateObserver observer;

    InputSandboxInfo inputSandboxInfo = MakeInputSandboxInfo(
        "com.example.enterprise", 100, "uri://enterprise", "/data/test");
    EnterpriseInfo enterpriseInfo = MakeEnterpriseInfo("L1", "file_1", "app_1");

    DlpSandboxInfo dlpSandboxInfo;
    observer.GetOpeningEnterpriseReadOnlySandbox(inputSandboxInfo, enterpriseInfo, dlpSandboxInfo);
    ASSERT_EQ(-1, dlpSandboxInfo.appIndex);
    ASSERT_EQ(-1, dlpSandboxInfo.bindAppIndex);
}