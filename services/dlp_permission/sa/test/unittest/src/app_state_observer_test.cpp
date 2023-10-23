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

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AppStateObserverTest"};
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
    appInfo.appIndex = 0;
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
