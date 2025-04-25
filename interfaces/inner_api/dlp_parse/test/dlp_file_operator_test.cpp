/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "dlp_file_operator_test.h"
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <openssl/rand.h>
#include "c_mock_common.h"
#include "nlohmann/json.hpp"
#define private public
#include "dlp_file_operator.h"
#undef private
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace std;
using json = nlohmann::json;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileOperatorTest"};
static const std::string DLP_TEST_DIR = "/data/dlpOperatorTest/";

static const std::string ACCOUNT_INDEX = "account";
static const std::string ACCOUNT_TYPE = "accountType";
static const std::string EDIT_INDEX = "edit";
static const std::string ENC_ACCOUNT_TYPE = "accountType";
static const std::string EVERYONE_INDEX = "everyone";
static const std::string FC_INDEX = "fullCtrl";
static const std::string NEED_ONLINE = "needOnline";
static const std::string OWNER_ACCOUNT_NAME = "ownerAccountName";
static const std::string OWNER_ACCOUNT = "ownerAccount";
static const std::string OWNER_ACCOUNT_ID = "ownerAccountId";
static const std::string OWNER_ACCOUNT_TYPE = "ownerAccountType";
static const std::string AUTHUSER_LIST = "authUserList";
static const std::string CONTACT_ACCOUNT = "contactAccount";
static const std::string OFFLINE_ACCESS = "offlineAccess";
static const std::string EVERYONE_ACCESS_LIST = "everyoneAccessList";
static const std::string PERM_EXPIRY_TIME = "expireTime";
static const std::string ACTION_UPON_EXPIRY = "actionUponExpiry";
static const std::string POLICY_INDEX = "policy";
static const std::string READ_INDEX = "read";
static const std::string RIGHT_INDEX = "right";
static const std::string CUSTOM_PROPERTY = "customProperty";

static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const std::string DEFAULT_CUSTOM_PROPERTY = "customProperty";
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int32_t RAND_STR_SIZE = 16;
static int g_plainFileFd = -1;
static int g_dlpFileFd = -1;
static int g_recoverFileFd = -1;

static const char TEST_FILE[] = "/data/dlpOperatorTest/file_test.txt";
static const char TEST_FILE_1[] = "/data/dlpOperatorTest/file_test_1.txt";
static const char DLP_FILE[] = "/data/dlpOperatorTest/file_test.txt.dlp";
}

void DlpFileOperatorTest::SetUpTestCase()
{
    struct stat fstat;
    if (stat(DLP_TEST_DIR.c_str(), &fstat) != 0) {
        if (errno == ENOENT) {
            int32_t ret = mkdir(DLP_TEST_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
            if (ret < 0) {
                DLP_LOG_ERROR(LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "get mount point failed errno %{public}d", errno);
            return;
        }
    }
}

void DlpFileOperatorTest::TearDownTestCase()
{
    rmdir(DLP_TEST_DIR.c_str());
}

void DlpFileOperatorTest::SetUp() {}

void DlpFileOperatorTest::TearDown() {}

namespace {
static uint8_t GetRandNum()
{
    uint8_t rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

static void GenerateRandStr(uint32_t len, std::string& res)
{
    for (uint32_t i = 0; i < len; i++) {
        uint32_t index = GetRandNum() % ARRAY_CHAR_SIZE;
        DLP_LOG_INFO(LABEL, "%{public}u", index);
        res.push_back(CHAR_ARRAY[index]);
    }
    DLP_LOG_INFO(LABEL, "%{public}s", res.c_str());
}

static void SerializePermInfo(DLPFileAccess perm, json& rightInfoJson)
{
    bool read = false;
    bool edit = false;
    bool fullCtrl = false;

    switch (perm) {
        case DLPFileAccess::READ_ONLY: {
            read = true;
            break;
        }
        case DLPFileAccess::CONTENT_EDIT: {
            edit = true;
            break;
        }
        case DLPFileAccess::FULL_CONTROL: {
            read = true;
            edit = true;
            fullCtrl = true;
            break;
        }
        default:
            break;
    }
    rightInfoJson[READ_INDEX] = read;
    rightInfoJson[EDIT_INDEX] = edit;
    rightInfoJson[FC_INDEX] = fullCtrl;
}

static void SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers, json& authUsersJson)
{
    for (const AuthUserInfo& info : authUsers) {
        json rightInfoJson;
        SerializePermInfo(info.authPerm, rightInfoJson);
        authUsersJson[info.authAccount.c_str()][RIGHT_INDEX] = rightInfoJson;
    }
}

static void SerializeEveryoneInfo(const PermissionPolicy& policy, json& permInfoJson)
{
    if (policy.supportEveryone_) {
        json rightInfoJson;
        SerializePermInfo(policy.everyonePerm_, rightInfoJson);
        permInfoJson[EVERYONE_INDEX][RIGHT_INDEX] = rightInfoJson;
        return;
    }
}

static int32_t SerializePermissionPolicy(const PermissionPolicy& policy, std::string& policyString)
{
    json policyJson;
    json authUsersJson;
    SerializeAuthUserList(policy.authUsers_, authUsersJson);
    policyJson[OWNER_ACCOUNT_NAME] = policy.ownerAccount_;
    policyJson[OWNER_ACCOUNT_ID] = policy.ownerAccountId_;
    policyJson[ACCOUNT_INDEX] = authUsersJson;
    policyJson[ACCOUNT_TYPE] = policy.acountType_;
    policyJson[PERM_EXPIRY_TIME] = policy.expireTime_;
    policyJson[NEED_ONLINE] = policy.needOnline_;
    policyJson[CUSTOM_PROPERTY] = policy.customProperty_;
    SerializeEveryoneInfo(policy, policyJson);
    policyString = policyJson.dump();
    return DLP_OK;
}
}


/**
* @tc.name: EnterpriseSpaceEncryptDlpFile001
* @tc.desc: test dlp file generate in Enterprise space
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, EnterpriseSpaceEncryptDlpFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "EnterpriseSpaceEncryptDlpFile001");

    g_plainFileFd = open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open(DLP_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    std::string accountName;
    GenerateRandStr(RAND_STR_SIZE, accountName);

    DlpProperty property = {
        .ownerAccount = DEFAULT_CURRENT_ACCOUNT,
        .ownerAccountId = DEFAULT_CURRENT_ACCOUNT,
        .contactAccount = accountName,
        .ownerAccountType = CLOUD_ACCOUNT,
        .offlineAccess = false,
        .supportEveryone = false,
        .everyonePerm = DLPFileAccess::NO_PERMISSION,
        .expireTime = 0,
        .actionUponExpiry = ActionType::NOTOPEN
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_plainFileFd);
    close(g_dlpFileFd);
}

/**
* @tc.name: EnterpriseSpaceDecryptDlpFile001
* @tc.desc: test decrypt dlp file in Enterprise space
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, EnterpriseSpaceDecryptDlpFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "EnterpriseSpaceDecryptDlpFile001");

    g_plainFileFd = open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open(DLP_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    std::string accountName;
    GenerateRandStr(RAND_STR_SIZE, accountName);

    DlpProperty property = {
        .ownerAccount = DEFAULT_CURRENT_ACCOUNT,
        .ownerAccountId = DEFAULT_CURRENT_ACCOUNT,
        .contactAccount = accountName,
        .ownerAccountType = CLOUD_ACCOUNT,
        .offlineAccess = false,
        .supportEveryone = false,
        .everyonePerm = DLPFileAccess::NO_PERMISSION,
        .expireTime = 0,
        .actionUponExpiry = ActionType::NOTOPEN
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_plainFileFd);

    g_plainFileFd = open(TEST_FILE_1, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->DecryptDlpFile(-1, g_dlpFileFd);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->DecryptDlpFile(g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_PARSE_ERROR_FILE_READ_ONLY, result);

}

/**
* @tc.name: EnterpriseSpaceQueryDlpProperty001
* @tc.desc: test dlp file generate in Enterprise space
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, EnterpriseSpaceQueryDlpProperty001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "EnterpriseSpaceQueryDlpProperty001");

    g_plainFileFd = open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open(DLP_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    std::string accountName;
    GenerateRandStr(RAND_STR_SIZE, accountName);

    DlpProperty property = {
        .ownerAccount = DEFAULT_CURRENT_ACCOUNT,
        .ownerAccountId = DEFAULT_CURRENT_ACCOUNT,
        .contactAccount = accountName,
        .ownerAccountType = CLOUD_ACCOUNT,
        .offlineAccess = false,
        .supportEveryone = false,
        .everyonePerm = DLPFileAccess::NO_PERMISSION,
        .expireTime = 0,
        .actionUponExpiry = ActionType::NOTOPEN
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_plainFileFd);
    close(g_dlpFileFd);
    g_dlpFileFd = open(DLP_FILE, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_dlpFileFd, 0);

    std::string queryResult;
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->QueryDlpFileProperty(g_dlpFileFd, queryResult);
    EXPECT_EQ(DLP_OK, result);
    close(g_dlpFileFd);
}

/**
* @tc.name: EnterpriseSpaceQueryDlpProperty002
* @tc.desc: test dlp file generate in Enterprise space
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, EnterpriseSpaceQueryDlpProperty002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "EnterpriseSpaceQueryDlpProperty002");

    g_plainFileFd = open(TEST_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    g_dlpFileFd = open(DLP_FILE, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_plainFileFd, 0);
    ASSERT_GE(g_dlpFileFd, 0);

    char buffer[] = "123456";
    ASSERT_NE(write(g_plainFileFd, buffer, sizeof(buffer)), -1);
    std::string accountName;
    GenerateRandStr(RAND_STR_SIZE, accountName);

    DlpProperty property = {
        .ownerAccount = DEFAULT_CURRENT_ACCOUNT,
        .ownerAccountId = DEFAULT_CURRENT_ACCOUNT,
        .contactAccount = accountName,
        .ownerAccountType = CLOUD_ACCOUNT,
        .offlineAccess = false,
        .supportEveryone = false,
        .everyonePerm = DLPFileAccess::NO_PERMISSION,
        .expireTime = 0,
        .actionUponExpiry = ActionType::NOTOPEN
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_plainFileFd);
    close(g_dlpFileFd);
    g_dlpFileFd = open(DLP_FILE, O_RDONLY, S_IRWXU | S_IRWXG | S_IRWXO);
    ASSERT_GE(g_dlpFileFd, 0);

    std::string queryResult;
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->QueryDlpFileProperty(-1, queryResult);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->QueryDlpFileProperty(g_dlpFileFd, queryResult);
    EXPECT_EQ(DLP_OK, result);
    close(g_dlpFileFd);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS