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
static const int32_t DEFAULT_NUM = 1;
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
    bool res = observer.GetOpeningSandboxInfo(appInfo.bundleName, appInfo.uri, appInfo.userId, sandboxInfo);
    ASSERT_EQ(res, false);
    appInfo.uid = INCORRECT_UID;

    observer.AddDlpSandboxInfo(appInfo);
    res = observer.GetOpeningSandboxInfo(appInfo.bundleName, appInfo.uri, appInfo.userId, sandboxInfo);
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
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex);
    ASSERT_EQ(appIndex, -1);

    DlpSandboxInfo appInfo;
    appInfo.bundleName = DLP_BUNDLENAME;
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.uid = DEFAULT_NUM;
    appInfo.appIndex = DEFAULT_NUM;
    appInfo.tokenId = DEFAULT_NUM;
    appInfo.userId = DEFAULT_USERID;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.tokenIdToUidMap_[DEFAULT_NUM] = DEFAULT_NUM;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex);
    ASSERT_EQ(appIndex, appInfo.appIndex);
    appInfo.dlpFileAccess = DLPFileAccess::CONTENT_EDIT;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex);
    ASSERT_EQ(appIndex, -1);
    appInfo.dlpFileAccess = DLPFileAccess::READ_ONLY;
    appInfo.bundleName = "";
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex);
    ASSERT_EQ(appIndex, -1);
    appInfo.userId = 0;
    appInfo.bundleName = DLP_BUNDLENAME;
    observer.sandboxInfo_[DEFAULT_NUM] = appInfo;
    observer.GetOpeningReadOnlySandbox(DLP_BUNDLENAME, DEFAULT_USERID, appIndex);
    ASSERT_EQ(appIndex, -1);
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
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
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

    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
    bundleName = "testbundle2";
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
    bundleName = "testbundle1";
    userId = 124;
    observer.GetOpeningReadOnlySandbox(bundleName, userId, appIndex);
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
    DlpSandboxInfo appInfo1 = {
        .uid = 1,
        .userId = 1231,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .uri = "123"
    };
    observer.AddSandboxInfo(appInfo1);
    DlpSandboxInfo appInfo2 = {
        .uid = 1,
        .userId = 123,
        .appIndex = 2,
        .bundleName = "testbundle1",
        .hasRead = false,
        .uri = "123"
    };
    observer.AddSandboxInfo(appInfo2);
    ASSERT_FALSE(observer.GetOpeningSandboxInfo(bundleName, uri, userId, SandboxInfo));
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
 * @tc.name: AddWatermarkName001
 * @tc.desc: AddWatermarkName test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, AddWatermarkName001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddWatermarkName001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    observer.AddWatermarkName(appInfo);
    appInfo.bundleName = "DlpTest";
    appInfo.tokenId = 100;
    appInfo.appIndex = 100;
    appInfo.watermarkName = "name1";
    observer.AddWatermarkName(appInfo);
    observer.AddWatermarkName(appInfo);
    ASSERT_EQ(1, observer.watermarkMap_.size());
    ASSERT_EQ(2, observer.watermarkMap_[appInfo.watermarkName]);
    appInfo.watermarkName = "name2";
    observer.AddWatermarkName(appInfo);
    ASSERT_EQ(2, observer.watermarkMap_.size());
}

/**
 * @tc.name: DecWatermarkName001
 * @tc.desc: DecWatermarkName test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, DecWatermarkName001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DecWatermarkName001");

    AppStateObserver observer;
    DlpSandboxInfo appInfo;
    appInfo.isWatermark = false;
    observer.DecWatermarkName(appInfo);

    appInfo.isWatermark = true;
    observer.DecWatermarkName(appInfo);

    appInfo.watermarkName = "";
    appInfo.userId = 0;
    observer.DecWatermarkName(appInfo);
    ASSERT_EQ(0, observer.watermarkMap_.size());
    appInfo.bundleName = "DlpTest";
    appInfo.tokenId = 100;
    appInfo.appIndex = 100;
    appInfo.watermarkName = "name1";
    observer.AddWatermarkName(appInfo);
    ASSERT_EQ(1, observer.watermarkMap_.size());
    observer.DecWatermarkName(appInfo);
}