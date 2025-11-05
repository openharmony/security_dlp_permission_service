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

#include "dlp_permission_client_test.h"
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
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionClientTest"};
}

void DlpPermissionClientTest::SetUpTestCase() {}

void DlpPermissionClientTest::TearDownTestCase() {}

void DlpPermissionClientTest::SetUp() {}

void DlpPermissionClientTest::TearDown() {}

/**
 * @tc.name: RegisterOpenDlpFileCallback001
 * @tc.desc: RegisterOpenDlpFileCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, RegisterOpenDlpFileCallback001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "RegisterOpenDlpFileCallback001");

    std::shared_ptr<OpenDlpFileCallbackCustomize> callback = nullptr;

    int32_t ret = DlpPermissionClient::GetInstance().RegisterOpenDlpFileCallback(callback);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: UnRegisterOpenDlpFileCallback001
 * @tc.desc: UnRegisterOpenDlpFileCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, UnRegisterOpenDlpFileCallback001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "UnRegisterOpenDlpFileCallback001");

    std::shared_ptr<OpenDlpFileCallbackCustomize> callback;

    int32_t ret = DlpPermissionClient::GetInstance().UnRegisterOpenDlpFileCallback(callback);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: GetRetentionSandboxList001
 * @tc.desc: GetRetentionSandboxList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, GetRetentionSandboxList001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetRetentionSandboxList001");

    std::string bundleName = "";
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;

    int32_t ret = DlpPermissionClient::GetInstance().GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: GetDLPFileVisitRecord001
 * @tc.desc: GetDLPFileVisitRecord test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, GetDLPFileVisitRecord001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetDLPFileVisitRecord001");

    std::vector<VisitedDLPFileInfo> infoVec;

    int32_t ret = DlpPermissionClient::GetInstance().GetDLPFileVisitRecord(infoVec);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name: GetProxy001
 * @tc.desc: GetProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, GetProxy001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetProxy001");

    bool doLoadSa = false;

    sptr<IDlpPermissionService> service_ = DlpPermissionClient::GetInstance().GetProxy(doLoadSa);
    ASSERT_EQ(DlpPermissionClient::GetInstance().proxy_, service_);
    DlpPermissionClient::GetInstance().OnRemoteDiedHandle();
}

/**
 * @tc.name: GetProxyFromRemoteObject001
 * @tc.desc: GetProxyFromRemoteObject test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, GetProxyFromRemoteObject001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetProxyFromRemoteObject001");

    sptr<IRemoteObject> remoteObject;
    DlpPermissionClient::GetInstance().GetProxyFromRemoteObject(remoteObject);
    ASSERT_EQ(nullptr, remoteObject);
}

/**
 * @tc.name: SetReadFlag001
 * @tc.desc: SetReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, SetReadFlag001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetReadFlag001");

    sptr<IRemoteObject> remoteObject;
    uint32_t uid = 0;
    int32_t ret = DlpPermissionClient::GetInstance().SetReadFlag(uid);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/**
 * @tc.name: SetDlpFeature001
 * @tc.desc: SetDlpFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, SetDlpFeature001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetDlpFeature001");
    uint32_t dlpFeatureInfo = 0;
    bool statusSetInfo;
    int32_t ret = DlpPermissionClient::GetInstance().SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/**
 * @tc.name: SetDlpFeature002
 * @tc.desc: SetDlpFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, SetDlpFeature002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "SetDlpFeature002");
    uint32_t dlpFeatureInfo = 1;
    bool statusSetInfo;
    int32_t ret = DlpPermissionClient::GetInstance().SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/* *
 * @tc.name: SetEnterprisePolicy001
 * @tc.desc: SetEnterprisePolicy.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, SetEnterprisePolicy001, TestSize.Level0)
{
    DLP_LOG_DEBUG(LABEL, "SetEnterprisePolicy001");
    std::string policy = "policy";
    int32_t ret = DlpPermissionClient::GetInstance().SetEnterprisePolicy(policy);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/* *
 * @tc.name: SetNotOwnerAndReadOnce001
 * @tc.desc: SetNotOwnerAndReadOnce.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionClientTest, SetNotOwnerAndReadOnce001, TestSize.Level0)
{
    DLP_LOG_DEBUG(LABEL, "SetNotOwnerAndReadOnce001");
    std::string uri = "";
    int32_t ret = DlpPermissionClient::GetInstance().SetNotOwnerAndReadOnce(uri, true);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_PERMISSION_DENY);
    uri = "uri";
    ret = DlpPermissionClient::GetInstance().SetNotOwnerAndReadOnce(uri, false);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_PERMISSION_DENY);
}