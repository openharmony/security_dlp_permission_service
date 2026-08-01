/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>
#include <cstring>
#include <string>
#include <vector>
#include "cert_parcel.h"
#include "dlp_permission.h"
#include "dlp_policy_parcel.h"
#include "auth_user_info_parcel.h"
#include "dlp_permission_info_parcel.h"
#include "permission_policy.h"
#include "parcel.h"
#include "sandbox_json_manager.h"
#include "visit_record_json_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static const uint32_t MAX_CERT_SIZE = 1024 * 1024 * 40 * 2;
}

class DlpSecurityFixTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DlpSecurityFixTest::SetUpTestCase() {}
void DlpSecurityFixTest::TearDownTestCase() {}
void DlpSecurityFixTest::SetUp() {}
void DlpSecurityFixTest::TearDown() {}

// ==================== Enum range validation: AuthUserInfoParcel ====================

HWTEST_F(DlpSecurityFixTest, AuthUserInfoParcel_InvalidPerm, TestSize.Level1)
{
    Parcel fakeOut;
    fakeOut.WriteString("test");
    fakeOut.WriteUint32(255);
    fakeOut.WriteUint64(0);
    fakeOut.WriteUint32(0);

    auto result = AuthUserInfoParcel::Unmarshalling(fakeOut);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(DlpSecurityFixTest, AuthUserInfoParcel_InvalidAccountType, TestSize.Level1)
{
    Parcel fakeOut;
    fakeOut.WriteString("test");
    fakeOut.WriteUint32(1);
    fakeOut.WriteUint64(0);
    fakeOut.WriteUint32(255);

    auto result = AuthUserInfoParcel::Unmarshalling(fakeOut);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(DlpSecurityFixTest, AuthUserInfoParcel_RoundTrip, TestSize.Level1)
{
    AuthUserInfoParcel info;
    info.authUserInfo_.authAccount = "testuser";
    info.authUserInfo_.authPerm = DLPFileAccess::FULL_CONTROL;
    info.authUserInfo_.permExpiryTime = 12345;
    info.authUserInfo_.authAccountType = DlpAccountType::ENTERPRISE_ACCOUNT;
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = AuthUserInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->authUserInfo_.authPerm, DLPFileAccess::FULL_CONTROL);
    EXPECT_EQ(result->authUserInfo_.authAccountType, DlpAccountType::ENTERPRISE_ACCOUNT);
    delete result;
}

HWTEST_F(DlpSecurityFixTest, AuthUserInfoParcel_BoundaryPerm, TestSize.Level1)
{
    Parcel fakeOut;
    fakeOut.WriteString("test");
    fakeOut.WriteUint32(4);
    fakeOut.WriteUint64(0);
    fakeOut.WriteUint32(0);

    auto result = AuthUserInfoParcel::Unmarshalling(fakeOut);
    EXPECT_EQ(result, nullptr);
}

// ==================== Enum range validation: DLPPermissionInfoParcel ====================

HWTEST_F(DlpSecurityFixTest, DLPPermissionInfoParcel_InvalidFileAccess, TestSize.Level1)
{
    Parcel fakeOut;
    fakeOut.WriteUint32(255);
    fakeOut.WriteUint32(0);

    auto result = DLPPermissionInfoParcel::Unmarshalling(fakeOut);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(DlpSecurityFixTest, DLPPermissionInfoParcel_InvalidFlags, TestSize.Level1)
{
    Parcel fakeOut;
    fakeOut.WriteUint32(1);
    fakeOut.WriteUint32(0xFFFFFFFF);

    auto result = DLPPermissionInfoParcel::Unmarshalling(fakeOut);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(DlpSecurityFixTest, DLPPermissionInfoParcel_ValidData, TestSize.Level1)
{
    DLPPermissionInfoParcel info;
    info.permInfo_.dlpFileAccess = DLPFileAccess::READ_ONLY;
    info.permInfo_.flags = ACTION_VIEW;
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = DLPPermissionInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->permInfo_.dlpFileAccess, DLPFileAccess::READ_ONLY);
    delete result;
}

HWTEST_F(DlpSecurityFixTest, DLPPermissionInfoParcel_RoundTrip, TestSize.Level1)
{
    DLPPermissionInfoParcel info;
    info.permInfo_.dlpFileAccess = DLPFileAccess::CONTENT_EDIT;
    info.permInfo_.flags = static_cast<ActionFlags>(ACTION_VIEW | ACTION_EDIT);
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = DLPPermissionInfoParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->permInfo_.dlpFileAccess, DLPFileAccess::CONTENT_EDIT);
    delete result;
}

// ==================== Enum range validation: DlpPolicyParcel ====================

HWTEST_F(DlpSecurityFixTest, DlpPolicyParcel_ValidRoundTrip, TestSize.Level1)
{
    DlpPolicyParcel info;
    info.policyParams_.ownerAccount_ = "owner";
    info.policyParams_.ownerAccountId_ = "ownerId";
    info.policyParams_.ownerAccountType_ = DlpAccountType::ENTERPRISE_ACCOUNT;
    info.policyParams_.everyonePerm_ = DLPFileAccess::NO_PERMISSION;
    uint8_t key[16] = {0};
    info.policyParams_.SetAeskey(key, sizeof(key));
    info.policyParams_.SetIv(key, sizeof(key));
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = DlpPolicyParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->policyParams_.ownerAccountType_, DlpAccountType::ENTERPRISE_ACCOUNT);
    delete result;
}

// ==================== DlpAccountType all valid values ====================

HWTEST_F(DlpSecurityFixTest, DlpAccountType_AllValidValues, TestSize.Level1)
{
    DlpAccountType validTypes[] = {
        DlpAccountType::INVALID_ACCOUNT,
        DlpAccountType::CLOUD_ACCOUNT,
        DlpAccountType::DOMAIN_ACCOUNT,
        DlpAccountType::APPLICATION_ACCOUNT,
        DlpAccountType::ENTERPRISE_ACCOUNT
    };

    for (auto type : validTypes) {
        AuthUserInfoParcel info;
        info.authUserInfo_.authAccount = "test";
        info.authUserInfo_.authPerm = DLPFileAccess::READ_ONLY;
        info.authUserInfo_.authAccountType = type;
        Parcel out;
        ASSERT_TRUE(info.Marshalling(out));

        auto result = AuthUserInfoParcel::Unmarshalling(out);
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result->authUserInfo_.authAccountType, type);
        delete result;
    }
}

// ==================== DLPFileAccess all valid values ====================

HWTEST_F(DlpSecurityFixTest, DLPFileAccess_AllValidValues, TestSize.Level1)
{
    DLPFileAccess validPerms[] = {
        DLPFileAccess::NO_PERMISSION,
        DLPFileAccess::READ_ONLY,
        DLPFileAccess::CONTENT_EDIT,
        DLPFileAccess::FULL_CONTROL
    };

    for (auto perm : validPerms) {
        AuthUserInfoParcel info;
        info.authUserInfo_.authAccount = "test";
        info.authUserInfo_.authPerm = perm;
        info.authUserInfo_.authAccountType = DlpAccountType::CLOUD_ACCOUNT;
        Parcel out;
        ASSERT_TRUE(info.Marshalling(out));

        auto result = AuthUserInfoParcel::Unmarshalling(out);
        ASSERT_NE(result, nullptr);
        EXPECT_EQ(result->authUserInfo_.authPerm, perm);
        delete result;
    }
}

// ==================== CertParcel size validation ====================

HWTEST_F(DlpSecurityFixTest, CertParcel_NormalCert, TestSize.Level1)
{
    CertParcel info;
    info.cert = {0x01, 0x02, 0x03};
    info.offlineCert = {0x04, 0x05};
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->cert.size(), 3u);
    EXPECT_EQ(result->offlineCert.size(), 2u);
    delete result;
}

HWTEST_F(DlpSecurityFixTest, CertParcel_OversizedCert, TestSize.Level1)
{
    CertParcel info;
    info.cert = std::vector<uint8_t>(MAX_CERT_SIZE + 1, 0x00);
    info.offlineCert = {};
    Parcel out;
    EXPECT_FALSE(info.Marshalling(out));
}

HWTEST_F(DlpSecurityFixTest, CertParcel_OversizedOfflineCert, TestSize.Level1)
{
    CertParcel info;
    info.cert = {0x01};
    info.offlineCert = std::vector<uint8_t>(MAX_CERT_SIZE + 1, 0x00);
    Parcel out;
    EXPECT_FALSE(info.Marshalling(out));
}

HWTEST_F(DlpSecurityFixTest, CertParcel_EmptyCert, TestSize.Level1)
{
    CertParcel info;
    info.cert = {};
    info.offlineCert = {};
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->cert.size(), 0u);
    EXPECT_EQ(result->offlineCert.size(), 0u);
    delete result;
}

HWTEST_F(DlpSecurityFixTest, CertParcel_CertAtLimit, TestSize.Level1)
{
    CertParcel info;
    info.cert = std::vector<uint8_t>(10, 0x41);
    info.offlineCert = {};
    Parcel out;
    ASSERT_TRUE(info.Marshalling(out));

    auto result = CertParcel::Unmarshalling(out);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->cert.size(), 10u);
    delete result;
}

// ==================== SandboxJsonManager ToString lock-free ====================

HWTEST_F(DlpSecurityFixTest, SandboxJsonManager_ToStringEmpty, TestSize.Level1)
{
    SandboxJsonManager manager;
    std::string result = manager.ToString();
    EXPECT_EQ(result, "");
}

HWTEST_F(DlpSecurityFixTest, VisitRecordJsonManager_ToStringEmpty, TestSize.Level1)
{
    VisitRecordJsonManager manager;
    std::string result = manager.ToString();
    EXPECT_EQ(result, "");
}
