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
#include "dlp_file_operator.cpp"
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
static constexpr OHOS::HiviewDFX::HiLogLabel UNIT_TEST_LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileOperatorTest"};
static const std::string DLP_TEST_DIR = "/data/dlpOperatorTest/";

static const std::string DEFAULT_CURRENT_ACCOUNT = "ohosAnonymousName";
static const std::string DEFAULT_CUSTOM_PROPERTY = "customProperty";
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const int32_t RAND_STR_SIZE = 16;
static int g_plainFileFd = -1;
static int g_dlpFileFd = -1;
static int g_recoverFileFd = -1;
static const int INVALID_FD = -1;
constexpr uint64_t  VALID_TIME_STAMP = 2147483647;

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
                DLP_LOG_ERROR(UNIT_TEST_LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(UNIT_TEST_LABEL, "get mount point failed errno %{public}d", errno);
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
        DLP_LOG_INFO(UNIT_TEST_LABEL, "%{public}u", index);
        res.push_back(CHAR_ARRAY[index]);
    }
    DLP_LOG_INFO(UNIT_TEST_LABEL, "%{public}s", res.c_str());
}

static bool DeserializeEveryoneInfo(const json& policyJson, PermissionPolicy& policy)
{
    if (policyJson.find(EVERYONE_INDEX) == policyJson.end() || !policyJson.at(EVERYONE_INDEX).is_object()) {
        return false;
    }

    policy.supportEveryone_ = true;
    json everyoneInfoJson;
    policyJson.at(EVERYONE_INDEX).get_to(everyoneInfoJson);

    json rightInfoJson;
    if (everyoneInfoJson.find(RIGHT_INDEX) == everyoneInfoJson.end() ||
        !everyoneInfoJson.at(RIGHT_INDEX).is_object()) {
        return false;
    }
    everyoneInfoJson.at(RIGHT_INDEX).get_to(rightInfoJson);

    bool edit = false;
    bool fullCtrl = false;

    if (rightInfoJson.find(EDIT_INDEX) != rightInfoJson.end() && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }

    if (rightInfoJson.find(FC_INDEX) != rightInfoJson.end() && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }

    if (fullCtrl) {
        policy.everyonePerm_ = DLPFileAccess::FULL_CONTROL;
    } else if (edit) {
        policy.everyonePerm_ = DLPFileAccess::CONTENT_EDIT;
    } else {
        policy.everyonePerm_ = DLPFileAccess::READ_ONLY;
    }
    return true;
}

static int32_t DeserializeAuthUserInfo(const json& accountInfoJson, AuthUserInfo& userInfo)
{
    json rightInfoJson;
    if (accountInfoJson.find(RIGHT_INDEX) != accountInfoJson.end() && accountInfoJson.at(RIGHT_INDEX).is_object()) {
        accountInfoJson.at(RIGHT_INDEX).get_to(rightInfoJson);
    }

    bool edit = false;
    bool fullCtrl = false;

    if (rightInfoJson.find(EDIT_INDEX) != rightInfoJson.end() && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }

    if (rightInfoJson.find(FC_INDEX) != rightInfoJson.end() && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }

    if (fullCtrl) {
        userInfo.authPerm = DLPFileAccess::FULL_CONTROL;
    } else if (edit) {
        userInfo.authPerm = DLPFileAccess::CONTENT_EDIT;
    } else {
        userInfo.authPerm = DLPFileAccess::READ_ONLY;
    }

    userInfo.permExpiryTime = VALID_TIME_STAMP;
    userInfo.authAccountType = CLOUD_ACCOUNT;

    return DLP_OK;
}

static int32_t DeserializeAuthUserList(const json& authUsersJson, std::vector<AuthUserInfo>& userList)
{
    for (auto iter = authUsersJson.begin(); iter != authUsersJson.end(); ++iter) {
        AuthUserInfo authInfo;
        std::string name = iter.key();
        authInfo.authAccount = name;
        json accountInfo = iter.value();
        int32_t res = DeserializeAuthUserInfo(accountInfo, authInfo);
        if (res == DLP_OK) {
            userList.emplace_back(authInfo);
        } else {
            userList.clear();
            return res;
        }
    }
    return DLP_OK;
}

static void InitPermissionPolicy(PermissionPolicy& policy, json policyJson)
{
    if (policyJson.find(OWNER_ACCOUNT_NAME) != policyJson.end() && policyJson.at(OWNER_ACCOUNT_NAME).is_string()) {
        policyJson.at(OWNER_ACCOUNT_NAME).get_to(policy.ownerAccount_);
    }
    if (policyJson.find(OWNER_ACCOUNT_ID) != policyJson.end() && policyJson.at(OWNER_ACCOUNT_ID).is_string()) {
        policyJson.at(OWNER_ACCOUNT_ID).get_to(policy.ownerAccountId_);
    }
    if (policyJson.find(PERM_EXPIRY_TIME) != policyJson.end() && policyJson.at(PERM_EXPIRY_TIME).is_number()) {
        policyJson.at(PERM_EXPIRY_TIME).get_to(policy.expireTime_);
    }
    if (policyJson.find(ACTION_UPON_EXPIRY) != policyJson.end() && policyJson.at(ACTION_UPON_EXPIRY).is_number()) {
        policyJson.at(ACTION_UPON_EXPIRY).get_to(policy.actionUponExpiry_);
    }
    if (policyJson.find(NEED_ONLINE) != policyJson.end() && policyJson.at(NEED_ONLINE).is_number()) {
        policyJson.at(NEED_ONLINE).get_to(policy.needOnline_);
    }
    if (policyJson.find(CUSTOM_PROPERTY) != policyJson.end() && policyJson.at(CUSTOM_PROPERTY).is_string()) {
        policyJson.at(CUSTOM_PROPERTY).get_to(policy.customProperty_);
    }
    if (policyJson.find(FILEID) != policyJson.end() && policyJson.at(FILEID).is_string()) {
        policyJson.at(FILEID).get_to(policy.fileId);
    }
    if (policyJson.find(ALLOWED_OPEN_COUNT) != policyJson.end() && policyJson.at(ALLOWED_OPEN_COUNT).is_number()) {
        policyJson.at(ALLOWED_OPEN_COUNT).get_to(policy.allowedOpenCount_);
    }
    if (policyJson.find(COUNTDOWN) != policyJson.end() && policyJson.at(COUNTDOWN).is_number()) {
        policyJson.at(COUNTDOWN).get_to(policy.countdown_);
    }
}

static uint32_t DeserializeDlpPermission(const std::string& queryResult, PermissionPolicy& policy)
{
    if (!json::accept(queryResult)) {
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    json policyJson = json::parse(queryResult);
    InitPermissionPolicy(policy, policyJson);
    json accountListJson;
    if (policyJson.find(ACCOUNT_INDEX) != policyJson.end() && policyJson.at(ACCOUNT_INDEX).is_object()) {
        policyJson.at(ACCOUNT_INDEX).get_to(accountListJson);
    }
    DeserializeEveryoneInfo(policyJson, policy);

    std::vector<AuthUserInfo> userList;
    if (DeserializeAuthUserList(accountListJson, userList) != DLP_OK) {
        return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
    }
    policy.authUsers_ = userList;
    return DLP_OK;
}

static bool IsSameAuthInfo(const std::vector<AuthUserInfo>& info1, const std::vector<AuthUserInfo>& info2)
{
    if (info1.size() != info2.size()) {
        return false;
    }
    for (auto auth1 : info1) {
        for (auto auth2 : info2) {
            if (auth1.authAccount != auth2.authAccount) {
                continue;
            }
            if (auth1.authPerm != auth2.authPerm) {
                return false;
            }
            break;
        }
    }
    return true;
}

static bool IsSameProperty(const PermissionPolicy& property, const PermissionPolicy& queryProperty)
{
    return property.ownerAccount_ == queryProperty.ownerAccount_ &&
        property.ownerAccountId_ == queryProperty.ownerAccountId_ &&
        property.expireTime_ == queryProperty.expireTime_ &&
        property.needOnline_ == queryProperty.needOnline_ &&
        property.actionUponExpiry_ == queryProperty.actionUponExpiry_ &&
        property.allowedOpenCount_ == queryProperty.allowedOpenCount_ &&
        property.countdown_ == queryProperty.countdown_ &&
        IsSameAuthInfo(property.authUsers_, queryProperty.authUsers_);
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
    DLP_LOG_INFO(UNIT_TEST_LABEL, "EnterpriseSpaceEncryptDlpFile001");

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
        .actionUponExpiry = ActionType::NOTOPEN,
        .fileId = "111",
        .allowedOpenCount = 1,
        .countdown = 1,
        .waterMarkConfig = false,
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, INVALID_FD, g_dlpFileFd);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, INVALID_FD);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    customProperty.enterprise = "";
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
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
    DLP_LOG_INFO(UNIT_TEST_LABEL, "EnterpriseSpaceDecryptDlpFile001");

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
        .actionUponExpiry = ActionType::NOTOPEN,
        .fileId = "111",
        .allowedOpenCount = 1,
        .countdown = 1,
        .waterMarkConfig = false,
    };
    CustomProperty customProperty = {
        .enterprise = DEFAULT_CUSTOM_PROPERTY
    };

    int32_t result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EncryptDlpFile(property,
        customProperty, g_plainFileFd, g_dlpFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_plainFileFd);

    g_plainFileFd = open(TEST_FILE_1, O_CREAT | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG | S_IRWXO);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->DecryptDlpFile(INVALID_FD, g_dlpFileFd);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->DecryptDlpFile(g_plainFileFd, INVALID_FD);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);

    std::shared_ptr<DlpFile> filePtr = nullptr;
    std::string workDir;
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()
        ->EnterpriseSpacePrepareWorkDir(g_dlpFileFd, filePtr, workDir);
    EXPECT_EQ(DLP_OK, result);

    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->EnterpriseSpaceParseDlpFileFormat(filePtr, false);
    EXPECT_EQ(DLP_OK, result);

    filePtr->authPerm_ = DLPFileAccess::FULL_CONTROL;
    result = DlpFileManager::GetInstance().RecoverDlpFile(filePtr, g_plainFileFd);
    EXPECT_EQ(DLP_OK, result);
    close(g_dlpFileFd);
    close(g_plainFileFd);
}

/**
* @tc.name: EnterpriseSpaceQueryDlpProperty001
* @tc.desc: test dlp file generate in Enterprise space
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, EnterpriseSpaceQueryDlpProperty001, TestSize.Level0)
{
    DLP_LOG_INFO(UNIT_TEST_LABEL, "EnterpriseSpaceQueryDlpProperty001");

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
        .actionUponExpiry = ActionType::NOTOPEN,
        .fileId = "111",
        .allowedOpenCount = 1,
        .countdown = 1,
        .waterMarkConfig = true,
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
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->QueryDlpFileProperty(INVALID_FD, queryResult);
    EXPECT_EQ(DLP_PARSE_ERROR_FD_ERROR, result);
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
    DLP_LOG_INFO(UNIT_TEST_LABEL, "EnterpriseSpaceQueryDlpProperty002");

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
        .actionUponExpiry = ActionType::NOTOPEN,
        .fileId = "111",
        .allowedOpenCount = 1,
        .countdown = 1,
        .waterMarkConfig = true,
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

    std::string resultStr;
    result = EnterpriseSpaceDlpPermissionKit::GetInstance()->QueryDlpFileProperty(g_dlpFileFd, resultStr);
    EXPECT_EQ(DLP_OK, result);
    PermissionPolicy resultPolicy;
    result = DeserializeDlpPermission(resultStr, resultPolicy);
    EXPECT_EQ(DLP_OK, result);
    PermissionPolicy inputPolicy(property);
    bool res = IsSameProperty(inputPolicy, resultPolicy);
    EXPECT_EQ(res, true);
    close(g_dlpFileFd);
}
/**
* @tc.name: GetFileSuffix001
* @tc.desc: test GetFileSuffix
* @tc.type: FUNC
* @tc.require:
*/
HWTEST_F(DlpFileOperatorTest, GetFileSuffix001, TestSize.Level0)
{
    DLP_LOG_INFO(UNIT_TEST_LABEL, "GetFileSuffix001");

    std::string validFileName = "test.txt";
    EXPECT_EQ(GetFileSuffix(validFileName), "txt");
    std::string invalidFileName = "test";
    EXPECT_EQ(GetFileSuffix(invalidFileName), DEFAULT_STRING);
    std::string cert = "test";
    EXPECT_EQ(GetAccountTypeFromCert(cert), INVALID_ACCOUNT);
}

}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS