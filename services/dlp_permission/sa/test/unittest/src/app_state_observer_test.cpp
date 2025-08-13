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

#include "app_state_observer_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#define private public
#include "app_state_observer.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppStateObserverTest"};
static const int32_t DEFAULT_USERID = 100;
static const std::string DLP_BUNDLENAME = "com.ohos.dlpmanager";
static const int32_t DEFAULT_NUM = 1;
}

void AppStateObserverTest::SetUpTestCase() {}

void AppStateObserverTest::TearDownTestCase() {}

void AppStateObserverTest::SetUp() {}

void AppStateObserverTest::TearDown() {}

/**
 * @tc.name: OnProcessDied001
 * @tc.desc: OnProcessDied test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AppStateObserverTest, OnProcessDied001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnProcessDied001");

    AppStateObserver observer;
    OHOS::AppExecFwk::ProcessData processData;
    processData.bundleName = "com.ohos.dlpmanager";
    processData.uid = 0;

    observer.OnProcessDied(processData);
    ASSERT_EQ(0, processData.uid);
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

    observer.AddDlpSandboxInfo(appInfo);
    ASSERT_EQ(-1, appInfo.uid);
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