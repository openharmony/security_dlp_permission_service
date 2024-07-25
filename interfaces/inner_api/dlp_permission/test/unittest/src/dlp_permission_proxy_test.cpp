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

#include "dlp_permission_proxy_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "iremote_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionProxyTest"};
}

void DlpPermissionProxyTest::SetUpTestCase() {}

void DlpPermissionProxyTest::TearDownTestCase() {}

void DlpPermissionProxyTest::SetUp() {}

void DlpPermissionProxyTest::TearDown() {}

class DlpTestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.test");

    DlpTestRemoteObj() = default;
    virtual ~DlpTestRemoteObj() noexcept = default;
};

/**
 * @tc.name: SetReadFlag001
 * @tc.desc: SetReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionProxyTest, SetReadFlag001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetReadFlag001");

    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    auto proxy = std::make_shared<DlpPermissionProxy>(callback->AsObject());
    uint32_t uid = 0;
    int32_t ret = proxy->SetReadFlag(uid);
    ASSERT_NE(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL, ret);
}
