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
#include "dlp_cert_parcel_test.h"
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
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpCertParcelTest"};
}

void DlpCertParcelTest::SetUpTestCase() {}

void DlpCertParcelTest::TearDownTestCase() {}

void DlpCertParcelTest::SetUp() {}

void DlpCertParcelTest::TearDown() {}

/**
 * @tc.name: DlpCertParcelTest001
 * @tc.desc: CertParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCertParcelTest, CertParcel001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CertParcel001");
    CertParcel info;
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result =  CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: DlpCertParcelTest002
 * @tc.desc: DlpPolicyParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCertParcelTest, DlpCertParcelTest002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CertParcel002");
    CertParcel info;
    info.cert = {1, 2, 3};
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result =  CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.name: DlpCertParcelTest003
 * @tc.desc: DlpSandboxCallbackInfoParcel test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCertParcelTest, DlpCertParcelTest003, TestSize.Level1)
{
    CertParcel info;
    info.cert = {1, 2, 3};
    info.offlineCert = {1, 2, 3};
    Parcel out;

    EXPECT_EQ(true, info.Marshalling(out));
    auto result = CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
