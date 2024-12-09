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
#include "dlp_parcel_test.h"
#include <string>
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpParcelTest"};
}

void DlpParcelTest::SetUpTestCase() {}

void DlpParcelTest::TearDownTestCase() {}

void DlpParcelTest::SetUp() {}

void DlpParcelTest::TearDown() {}

/**
 * @tc.name: DlpParcelTest001
 * @tc.desc: AuthUserInfoParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, AuthUserInfoParcel001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AuthUserInfoParcel001");
    AuthUserInfoParcel info;
    info.authUserInfo_.authAccount = "abc";
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result =  AuthUserInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(0, result->authUserInfo_.authAccount.compare("abc"));
    delete result;
    result = nullptr;
}

/**
 * @tc.name: DlpParcelTest002
 * @tc.desc: DlpPolicyParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, DlpParcelTest002, TestSize.Level1)
{
    DlpPolicyParcel info;
    info.policyParams_.ownerAccount_ = "abc";
    info.policyParams_.ownerAccountId_ = "abc";
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = DlpPolicyParcel::Unmarshalling(out);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DlpParcelTest003
 * @tc.desc: DlpSandboxCallbackInfoParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, DlpParcelTest003, TestSize.Level1)
{
    DlpSandboxCallbackInfoParcel info;
    info.changeInfo.appIndex = 0;
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = DlpSandboxCallbackInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(0, result->changeInfo.appIndex);
    delete result;
    result = nullptr;
}

/**
 * @tc.name: DlpParcelTest004
 * @tc.desc: OpenDlpFileCallbackInfoParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, DlpParcelTest004, TestSize.Level1)
{
    OpenDlpFileCallbackInfoParcel info;
    info.fileInfo.uri = "test";
    info.fileInfo.timeStamp = 1;
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = OpenDlpFileCallbackInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ("test", result->fileInfo.uri);
    EXPECT_EQ(1, result->fileInfo.timeStamp);
    delete result;
    result = nullptr;
}

/**
 * @tc.name: RetentionSandBoxInfo001
 * @tc.desc: RetentionSandBoxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, RetentionSandBoxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RetentionSandBoxInfo001");
    RetentionSandBoxInfo info;
    info.bundleName_ = "abc";
    info.appIndex_ = 1;
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = RetentionSandBoxInfo::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(0, result->bundleName_.compare("abc"));
    delete result;
    result = nullptr;
}

/**
 * @tc.name: VisitedDLPFileInfo001
 * @tc.desc: VisitedDLPFileInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpParcelTest, VisitedDLPFileInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "VisitedDLPFileInfo001");
    VisitedDLPFileInfo info;
    info.docUri = "abc";
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = VisitedDLPFileInfo::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(0, result->docUri.compare("abc"));
    delete result;
    result = nullptr;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS