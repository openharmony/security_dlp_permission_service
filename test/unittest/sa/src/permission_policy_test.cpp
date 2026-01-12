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
#include "permission_policy_test.h"

#include <list>
#include <string>
#include "dlp_parcel.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std::chrono;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "PermissionPolicyTest"};
const uint32_t MAX_ACCOUNT_SIZE = 1024;
const uint32_t MAX_ACCOUNT_NUM = 100;
const uint32_t AES_KEY_LEN = 16;
const uint32_t IV_LEN = 16;
const uint64_t EXPIRY_TEN_MINUTE = 60 * 10;

uint64_t GetCurrentTimeSec(void)
{
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

void NewUserSample(AuthUserInfo& user)
{
    user.authAccount = "allowAccountA";
    user.authPerm = DLPFileAccess::FULL_CONTROL;
    user.permExpiryTime = GetCurrentTimeSec() + EXPIRY_TEN_MINUTE;
    user.authAccountType = CLOUD_ACCOUNT;
}

void InitNormalPolicy(std::shared_ptr<PermissionPolicy>& policy)
{
    policy->ownerAccount_ = "testAccount";
    policy->ownerAccountId_ = "testAccountId";
    policy->ownerAccountType_ = CLOUD_ACCOUNT;
    policy->aeskey_ = new (std::nothrow) uint8_t[16];
    policy->aeskeyLen_ = AES_KEY_LEN;
    policy->iv_ = new (std::nothrow) uint8_t[16];
    policy->ivLen_ = IV_LEN;

    AuthUserInfo user;
    NewUserSample(user);
    policy->authUsers_.emplace_back(user);
}
}

void PermissionPolicyTest::SetUpTestCase() {}

void PermissionPolicyTest::TearDownTestCase() {}

void PermissionPolicyTest::SetUp() {}

void PermissionPolicyTest::TearDown() {}

/**
 * @tc.name: PermissionPolicy001
 * @tc.desc: PermissionPolicy construct test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, PermissionPolicyConstruct001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "PermissionPolicyConstruct001");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);
    policy = nullptr;
}

/**
,* @tc.name: IsValid001
 * @tc.desc: IsValid normal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid001");

    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    ASSERT_TRUE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: IsValid002
 * @tc.desc: IsValid owner abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid002");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // empty ownerAccount
    policy->ownerAccount_ = "";
    ASSERT_FALSE(policy->IsValid());

    // ownerAccount name len > MAX_ACCOUNT_SIZE
    std::string invalidPerm(MAX_ACCOUNT_SIZE + 1, 'a');
    policy->ownerAccount_ = invalidPerm;
    ASSERT_FALSE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: IsValid003
 * @tc.desc: IsValid account type abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid003");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // account INVALID_ACCOUNT
    policy->ownerAccountType_ = INVALID_ACCOUNT;
    ASSERT_FALSE(policy->IsValid());

    // account APPLICATION_ACCOUNT + APPLICATION_ACCOUNT
    policy->ownerAccountType_ = static_cast<DlpAccountType>(APPLICATION_ACCOUNT + APPLICATION_ACCOUNT);
    ASSERT_FALSE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: IsValid004
 * @tc.desc: IsValid aes key abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid004");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // aeskey len is 0
    policy->aeskeyLen_ = 0;
    ASSERT_FALSE(policy->IsValid());

    // aeskey is null
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = AES_KEY_LEN;
    ASSERT_FALSE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
}

/**
 * @tc.name: IsValid005
 * @tc.desc: IsValid iv key abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid005, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid005");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // iv len is 0
    policy->ivLen_ = 0;
    ASSERT_FALSE(policy->IsValid());

    // iv is null
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = AES_KEY_LEN;
    ASSERT_FALSE(policy->IsValid());
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: IsValid006
 * @tc.desc: IsValid auth info key abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid006, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid006");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // 1. test user account
    // auth user account empty
    policy->authUsers_[0].authAccount = "";
    EXPECT_FALSE(policy->IsValid());

    // restore
    policy->authUsers_[0].authAccount = "test";

    // 2. test auth perm
    // auth perm DEFAULT
    policy->authUsers_[0].authPerm = DLPFileAccess::NO_PERMISSION;
    EXPECT_FALSE(policy->IsValid());

    // restore
    policy->authUsers_[0].authPerm = DLPFileAccess::FULL_CONTROL;

    // 3. test expiryTime
    // expiryTime 0
    policy->authUsers_[0].permExpiryTime = 0;
    EXPECT_FALSE(policy->IsValid());

    // restore
    policy->authUsers_[0].permExpiryTime = GetCurrentTimeSec() + 1000;

    // 4. test auth account type
    policy->authUsers_[0].authAccountType = INVALID_ACCOUNT;
    EXPECT_FALSE(policy->IsValid());

    // restore
    policy->authUsers_[0].authAccountType = APPLICATION_ACCOUNT;

    // 5. max + 1 user size
    for (unsigned int i = 0; i < MAX_ACCOUNT_NUM; i++) {
        AuthUserInfo user;
        NewUserSample(user);
        policy->authUsers_.emplace_back(user);
    }
    EXPECT_FALSE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: IsValid007
 * @tc.desc: IsValid owner abnormal test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, IsValid007, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "IsValid002");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // empty ownerAccount
    policy->ownerAccountId_ = "";
    ASSERT_FALSE(policy->IsValid());

    // ownerAccount name len > MAX_ACCOUNT_SIZE
    std::string invalidPerm(MAX_ACCOUNT_SIZE + 1, 'a');
    policy->ownerAccountId_ = invalidPerm;
    ASSERT_FALSE(policy->IsValid());
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: SetAesKey001
 * @tc.desc: SetAesKey test
 * @tc.type: FUNC
 * @tc.require:
 */

HWTEST_F(PermissionPolicyTest, SetAesKey001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetAesKey001");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // set aes key len invalid
    uint8_t tmpAeskey[AES_KEY_LEN] = {0};
    policy->SetAeskey(tmpAeskey, AES_KEY_LEN + 1);
    ASSERT_NE(policy->aeskeyLen_, AES_KEY_LEN + 1);

    // set aes key null
    policy->SetAeskey(nullptr, AES_KEY_LEN);
    ASSERT_EQ(policy->aeskey_, nullptr);
    delete[] policy->iv_;
    policy->iv_ = nullptr;
    policy->ivLen_ = 0;
}

/**
 * @tc.name: SetIv001
 * @tc.desc: SetIv test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, SetIv001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SetIv001");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    InitNormalPolicy(policy);

    // set iv len invalid
    uint8_t tmpIvkey[IV_LEN] = {0};
    policy->SetIv(tmpIvkey, IV_LEN + 1);
    ASSERT_NE(policy->ivLen_, AES_KEY_LEN + 1);

    // set iv null
    policy->SetIv(nullptr, IV_LEN);
    ASSERT_EQ(policy->iv_, nullptr);
    delete[] policy->aeskey_;
    policy->aeskey_ = nullptr;
    policy->aeskeyLen_ = 0;
}

/**
 * @tc.name: GetAllowedOpenCount
 * @tc.desc: GetAllowedOpenCount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, GetAllowedOpenCount001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetAllowedOpenCount001");
    std::shared_ptr<PermissionPolicy> policy = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policy, nullptr);

    policy->allowedOpenCount_ = 1;
    ASSERT_EQ(policy->allowedOpenCount_, 1);
}

/**
 * @tc.name: CopyPermissionPolicy001
 * @tc.desc: SetIv test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, CopyPermissionPolicy001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CopyPermissionPolicy001");
    std::shared_ptr<PermissionPolicy> policySrc = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policySrc, nullptr);
    InitNormalPolicy(policySrc);

    std::shared_ptr<PermissionPolicy> policyDest = std::make_shared<PermissionPolicy>();
    ASSERT_NE(policyDest, nullptr);

    // 1. make policySrc invalid
    policySrc->ownerAccount_ = "";
    policyDest->CopyPermissionPolicy(*policySrc);
    ASSERT_EQ(policyDest->aeskey_, nullptr);

    // 2. make policySrc valid
    policySrc->ownerAccount_ = "testAccount";
    policyDest->CopyPermissionPolicy(*policySrc);
    ASSERT_NE(policyDest->aeskey_, nullptr);
    delete[] policySrc->iv_;
    policySrc->iv_ = nullptr;
    policySrc->ivLen_ = 0;
    delete[] policySrc->aeskey_;
    policySrc->aeskey_ = nullptr;
    policySrc->aeskeyLen_ = 0;
    delete[] policyDest->iv_;
    policyDest->iv_ = nullptr;
    policyDest->ivLen_ = 0;
    delete[] policyDest->aeskey_;
    policyDest->aeskey_ = nullptr;
    policyDest->aeskeyLen_ = 0;
}

/**
 * @tc.name: FileInfo001
 * @tc.desc: FileInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionPolicyTest, FileInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "FileInfo001");
    FIleInfo info;
    Parcel parcel;
    std::list<bool> writeBoolList;
    writeBoolList.push_back(false);
    MockWriteBool(true, &writeBoolList);
    ASSERT_FALSE(info.Marshalling(parcel));
    ResetParcelState();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS