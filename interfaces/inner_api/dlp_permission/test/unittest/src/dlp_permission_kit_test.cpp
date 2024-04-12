/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dlp_permission_kit_test.h"
#include <chrono>
#include <openssl/rand.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "gtest/gtest.h"
#include "accesstoken_kit.h"
#include "cert_parcel.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_callback_info.h"
#include "dlp_sandbox_change_callback_customize.h"
#define private public
#include "dlp_sandbox_change_callback.h"
#include "hex_string.h"
#include "open_dlp_file_callback.h"
#undef private
#include "parameters.h"
#include "param_wrapper.h"
#include "permission_policy.h"
#include "securec.h"
#include "token_setproc.h"
#include "visited_dlp_file_info.h"
#include "want.h"
#include "bundle_mgr_client.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKitTest"};

const uint32_t ACCOUNT_LENGTH = 20;
const uint32_t AESKEY_LEN = 32;
const uint32_t IV_LEN = 32;
const uint32_t USER_NUM = 10;
const int AUTH_PERM = 1;
const int64_t DELTA_EXPIRY_TIME = 200;

const uint32_t INVALID_ACCOUNT_LENGTH_UPPER = 2048;
const uint32_t INVALID_ACCOUNT_LENGTH_LOWER = 0;
const uint32_t INVALID_AESKEY_LEN_UPPER = 256;
const uint32_t INVALID_AESKEY_LEN_LOWER = 0;
const uint32_t INVALID_IV_LEN_UPPER = 256;
const uint32_t INVALID_IV_LEN_LOWER = 0;
const uint32_t INVALID_USER_NUM_UPPER = 200;
const uint32_t INVALID_AUTH_PERM_UPPER = 5;
const uint32_t INVALID_AUTH_PERM_LOWER = 0;
const int64_t INVALID_DELTA_EXPIRY_TIME = -100;

const int32_t DEFAULT_USERID = 100;
const int32_t ACTION_SET_EDIT = 0xff;
const int32_t ACTION_SET_FC = 0x7ff;
static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_dlpManagerTokenId = 0;
static int32_t g_selfUid = 0;
const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
const std::string TEST_URI = "datashare:///media/file/8";
const std::string TEST_UNEXIST_URI = "datashare:///media/file/1";
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const std::string DLP_ENABEL = "const.dlp.dlp_enable";
}  // namespace

static uint8_t GetRandNum()
{
    uint8_t rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

static void TestRecordProcessInfo()
{
    g_selfTokenId = GetSelfTokenID();
    DLP_LOG_INFO(LABEL, "get self tokenId is %{public}d", g_selfTokenId);
    g_dlpManagerTokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, DLP_MANAGER_APP, 0);
    DLP_LOG_INFO(LABEL, "get dlp manager tokenId is %{public}d", g_dlpManagerTokenId);
    g_selfUid = getuid();
    DLP_LOG_INFO(LABEL, "get self uid is %{public}d", g_selfUid);
}

static bool TestSetSelfTokenId(AccessTokenID tokenId)
{
    // set tokenId can only be called by native process
    int32_t uid = getuid();
    if (setuid(g_selfUid) != 0) {
        DLP_LOG_ERROR(LABEL, "setuid fail, %s", strerror(errno));
        return false;
    }

    DLP_LOG_INFO(LABEL, "set self tokenId from %{public}u to %{public}d",
        static_cast<unsigned int>(GetSelfTokenID()), tokenId);
    if (SetSelfTokenID(tokenId) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set self tokenId fail");
        if (setuid(uid) != 0) {
            DLP_LOG_ERROR(LABEL, "setuid fail, %s", strerror(errno));
        }
        return false;
    }

    if (setuid(uid) != 0) {
        DLP_LOG_ERROR(LABEL, "setuid fail, %s", strerror(errno));
        return false;
    }
    return true;
}

static bool TestGetTokenId(int userID, const std::string& bundleName, int instIndex, AccessTokenID& tokenId)
{
    AccessTokenID tmpTokenId = GetSelfTokenID();
    if (!TestSetSelfTokenId(g_selfTokenId)) {
        return false;
    }
    int32_t uid = getuid();
    setuid(g_selfUid);
    tokenId = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    setuid(uid);
    DLP_LOG_INFO(LABEL, "get app tokenId is %{public}d", tokenId);
    if (!TestSetSelfTokenId(tmpTokenId)) {
        return false;
    }
    return true;
}

static bool TestGetAppUid(const std::string& bundleName, int32_t appIndex, int32_t userId, int32_t& uid)
{
    AccessTokenID tmpTokenId = GetSelfTokenID();
    if (!TestSetSelfTokenId(g_selfTokenId)) {
        return false;
    }
    OHOS::AppExecFwk::BundleInfo info;
    OHOS::AppExecFwk::BundleMgrClient bundleMgrClient;
    if (appIndex > 0) {
        if (bundleMgrClient.GetSandboxBundleInfo(bundleName, appIndex, userId, info) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "get sandbox app info fail");
            return false;
        }
    } else {
        if (!bundleMgrClient.GetBundleInfo(bundleName, OHOS::AppExecFwk::GET_BUNDLE_DEFAULT, info, userId)) {
            DLP_LOG_ERROR(LABEL, "get app info fail");
            return false;
        }
    }
    DLP_LOG_INFO(LABEL, "get app uid: %{public}d", info.uid);
    if (!TestSetSelfTokenId(tmpTokenId)) {
        return false;
    }
    uid = info.uid;
    return true;
}

static void TestInstallDlpSandbox(
    const std::string& bundleName, DLPFileAccess dlpFileAccess, int32_t userId, SandboxInfo& sandboxInfo)
{
    // install sandbox need permission ACCESS_DLP_FILE, dlpmanager has this permission
    AccessTokenID tokenId = GetSelfTokenID();
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));

    ASSERT_EQ(DLP_OK, DlpPermissionKit::InstallDlpSandbox(bundleName, dlpFileAccess, userId, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);

    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
}

static void TestUninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    // uninstall sandbox need permission ACCESS_DLP_FILE, dlpmanager has this permission
    AccessTokenID tokenId = GetSelfTokenID();
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));

    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(bundleName, appIndex, userId));

    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
}

static void TestMockApp(const std::string& bundleName, int32_t appIndex, int32_t userId)
{
    AccessTokenID tokenId;
    ASSERT_TRUE(TestGetTokenId(userId, bundleName, appIndex, tokenId));
    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
    int32_t uid;
    ASSERT_TRUE(TestGetAppUid(bundleName, appIndex, userId, uid));
    ASSERT_EQ(DLP_OK, setuid(uid));
}

static void TestRecoverProcessInfo(int32_t uid, AccessTokenID tokenId)
{
    ASSERT_EQ(DLP_OK, setuid((uid)));
    ASSERT_TRUE(TestSetSelfTokenId((tokenId)));
}

void DlpPermissionKitTest::SetUpTestCase()
{
    // make test case clean
    DLP_LOG_INFO(LABEL, "SetUpTestCase.");
    TestRecordProcessInfo();
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
}

void DlpPermissionKitTest::TearDownTestCase()
{
    DLP_LOG_INFO(LABEL, "TearDownTestCase.");
    ASSERT_TRUE(TestSetSelfTokenId(g_selfTokenId));
}

void DlpPermissionKitTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "SetUp ok.");
}

void DlpPermissionKitTest::TearDown()
{
    DLP_LOG_INFO(LABEL, "TearDown.");
}

static uint8_t* GenerateRandArray(uint32_t len)
{
    if (len < 1) {
        DLP_LOG_ERROR(LABEL, "len error");
        return nullptr;
    }
    uint8_t* str = new (std::nothrow) uint8_t[len];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }
    for (uint32_t i = 0; i < len; i++) {
        str[i] = GetRandNum() % 255;  // uint8_t range 0 ~ 255
    }
    return str;
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

struct GeneratePolicyParam {
    uint32_t ownerAccountLen;
    uint32_t aeskeyLen;
    uint32_t ivLen;
    uint32_t userNum;
    uint32_t authAccountLen;
    uint32_t authPerm;
    int64_t deltaTime;
};

static void GeneratePolicy(PermissionPolicy& encPolicy, GeneratePolicyParam param)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    GenerateRandStr(param.ownerAccountLen, encPolicy.ownerAccount_);
    encPolicy.ownerAccountId_ = encPolicy.ownerAccount_;
    encPolicy.ownerAccountType_ = DOMAIN_ACCOUNT;
    uint8_t* key = GenerateRandArray(param.aeskeyLen);
    encPolicy.SetAeskey(key, param.aeskeyLen);
    if (key != nullptr) {
        delete[] key;
        key = nullptr;
    }
    uint8_t* iv = GenerateRandArray(param.ivLen);
    encPolicy.SetIv(iv, param.ivLen);
    if (iv != nullptr) {
        delete[] iv;
        iv = nullptr;
    }
    for (uint32_t user = 0; user < param.userNum; ++user) {
        std::string accountName;
        GenerateRandStr(param.authAccountLen, accountName);
        AuthUserInfo perminfo = {.authAccount = strdup(const_cast<char *>(accountName.c_str())),
            .authPerm = static_cast<DLPFileAccess>(param.authPerm),
            .permExpiryTime = curTime + param.deltaTime,
            .authAccountType = DOMAIN_ACCOUNT};
        encPolicy.authUsers_.emplace_back(perminfo);
    }
}

static int32_t TestGenerateDlpCertWithInvalidParam(GeneratePolicyParam param)
{
    PermissionPolicy encPolicy;
    GeneratePolicy(encPolicy, param);
    std::vector<uint8_t> cert;
    int32_t res = DlpPermissionKit::GenerateDlpCertificate(encPolicy, cert);
    return res;
}

/**
 * @tc.name: SetRetentionState01
 * @tc.desc: SetRetentionState abnormal input test.
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionKitTest, SetRetentionState01, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID selfTokenId = GetSelfTokenID();
    std::vector<std::string> docUriVec;
    docUriVec.push_back(TEST_URI);
    SandboxInfo sandboxInfo;

    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, DLP_MANAGER_APP, sandboxInfo.appIndex);
    AccessTokenID normalTokenId = AccessTokenKit::GetHapTokenID(100, DLP_MANAGER_APP, 0);
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(0 == retentionSandBoxInfoVec.size());
    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
    retentionSandBoxInfoVec.clear();
    ASSERT_EQ(DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR,
        DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(TestSetSelfTokenId(normalTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(0 == retentionSandBoxInfoVec.size());
    ASSERT_EQ(DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR, DlpPermissionKit::SetRetentionState(docUriVec));
    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::SetRetentionState(docUriVec));
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);
    ASSERT_TRUE(TestSetSelfTokenId(normalTokenId));
    retentionSandBoxInfoVec.clear();
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(0 != retentionSandBoxInfoVec.size());
    retentionSandBoxInfoVec.clear();
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(0 != retentionSandBoxInfoVec.size());
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
    TestRecoverProcessInfo(uid, selfTokenId);
}

/**
 * @tc.name: SetRetentionState02
 * @tc.desc: SetRetentionState abnormal input test.
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionKitTest, SetRetentionState02, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    DLP_LOG_INFO(LABEL, "SetRetentionState02  tokenId from %{public}u", static_cast<unsigned int>(GetSelfTokenID()));
    std::vector<std::string> docUriVec;
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    docUriVec.clear();
    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::CancelRetentionState(docUriVec));
    docUriVec.push_back(TEST_UNEXIST_URI);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::CancelRetentionState(docUriVec));
    docUriVec.clear();
    docUriVec.push_back(TEST_URI);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::CancelRetentionState(docUriVec));
    retentionSandBoxInfoVec.clear();
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetRetentionSandboxList(DLP_MANAGER_APP, retentionSandBoxInfoVec));
    ASSERT_TRUE(0 == retentionSandBoxInfoVec.size());
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
    TestRecoverProcessInfo(uid, tokenId);
}

/* *
 * @tc.name: SetRetentionState03
 * @tc.desc: SetRetentionState abnormal input test.
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionKitTest, SetRetentionState03, TestSize.Level1)
{
    int32_t uid = getuid();
    SandboxInfo sandboxInfo;
    AccessTokenID tokenId = GetSelfTokenID();
    DLP_LOG_INFO(LABEL, "SetRetentionState03  tokenId from %{public}u", static_cast<unsigned int>(GetSelfTokenID()));

    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    AccessTokenID sandboxTokenId = AccessTokenKit::GetHapTokenID(DEFAULT_USERID, DLP_MANAGER_APP, sandboxInfo.appIndex);
    DLP_LOG_INFO(LABEL, "SetRetentionState03 sandboxTokenId  tokenId from %{public}d ", sandboxTokenId);
    ASSERT_TRUE(TestSetSelfTokenId(sandboxTokenId));
    std::vector<std::string> docUriVec;
    int32_t res = DlpPermissionKit::SetRetentionState(docUriVec);
    DLP_LOG_INFO(LABEL, "SetRetentionState03 res %{public}d", res);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    docUriVec.push_back(TEST_URI);
    res = DlpPermissionKit::SetRetentionState(docUriVec);
    DLP_LOG_INFO(LABEL, "SetRetentionState03 res %{public}d", res);
    ASSERT_EQ(DLP_OK, res);
    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/* *
 * @tc.name: OnGenerateDlpCertificate001
 * @tc.desc: OnGenerateDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, OnGenerateDlpCertificate001, TestSize.Level1)
{
    auto generateDlpCertificateCallback = std::make_shared<ClientGenerateDlpCertificateCallback>();
    std::vector<uint8_t> cert;
    cert = { 1, 2, 3 };
    generateDlpCertificateCallback->OnGenerateDlpCertificate(-1, cert);
    ASSERT_EQ(-1, generateDlpCertificateCallback->result_);
    ASSERT_TRUE(generateDlpCertificateCallback->isCallBack_);
}

/**
 * @tc.name: OnParseDlpCertificate001
 * @tc.desc: OnParseDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, OnParseDlpCertificate001, TestSize.Level1)
{
    auto parseDlpCertificateCallback = std::make_shared<ClientParseDlpCertificateCallback>();
    PermissionPolicy policy;
    parseDlpCertificateCallback->OnParseDlpCertificate(-1, policy, {});
    ASSERT_EQ(-1, parseDlpCertificateCallback->result_);
    ASSERT_TRUE(parseDlpCertificateCallback->isCallBack_);
}

/* *
 * @tc.name: GenerateDlpCertificate001
 * @tc.desc: GenerateDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, GenerateDlpCertificate001, TestSize.Level1)
{
    GeneratePolicyParam param = {INVALID_ACCOUNT_LENGTH_UPPER, AESKEY_LEN,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param.ownerAccountLen = INVALID_ACCOUNT_LENGTH_LOWER;
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, INVALID_AESKEY_LEN_UPPER,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, INVALID_AESKEY_LEN_LOWER,
                                             IV_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_UPPER, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, INVALID_IV_LEN_LOWER, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             INVALID_USER_NUM_UPPER, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, INVALID_ACCOUNT_LENGTH_UPPER, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, INVALID_ACCOUNT_LENGTH_LOWER, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, ACCOUNT_LENGTH, INVALID_AUTH_PERM_UPPER, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                             USER_NUM, ACCOUNT_LENGTH, INVALID_AUTH_PERM_LOWER, DELTA_EXPIRY_TIME};
    EXPECT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN, IV_LEN,
                                                   USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, INVALID_DELTA_EXPIRY_TIME};
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, TestGenerateDlpCertWithInvalidParam(param));
    param = {ACCOUNT_LENGTH, AESKEY_LEN,
        AESKEY_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM, DELTA_EXPIRY_TIME};
    EXPECT_NE(DLP_OK, TestGenerateDlpCertWithInvalidParam(param));
}

/**
 * @tc.name: ParseDlpCertificate001
 * @tc.desc: ParseDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, ParseDlpCertificate001, TestSize.Level1)
{
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    PermissionPolicy policy;
    certParcel->contactAccount = "test";
    std::string appId = "test_appId_passed";
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::ParseDlpCertificate(certParcel, policy, appId, true));
    certParcel->cert = {1, 2, 3};
    ASSERT_NE(DLP_OK, DlpPermissionKit::ParseDlpCertificate(certParcel, policy, appId, true));
}

/**
 * @tc.name: InstallDlpSandbox001
 * @tc.desc: InstallDlpSandbox test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG8
 */
HWTEST_F(DlpPermissionKitTest, InstallDlpSandbox001, TestSize.Level1)
{
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: InstallDlpSandbox002
 * @tc.desc: InstallDlpSandbox invalid input.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG8
 */
HWTEST_F(DlpPermissionKitTest, InstallDlpSandbox002, TestSize.Level1)
{
    SandboxInfo sandboxInfo;
    ASSERT_NE(
        DLP_OK, DlpPermissionKit::InstallDlpSandbox("test.test", READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        DlpPermissionKit::InstallDlpSandbox("", READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP,
                                             static_cast<DLPFileAccess>(100), DEFAULT_USERID, sandboxInfo, TEST_URI));
}

/**
 * @tc.name: UninstallDlpSandbox001
 * @tc.desc: UninstallDlpSandbox test.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGF AR000GVIGG
 */
HWTEST_F(DlpPermissionKitTest, UninstallDlpSandbox001, TestSize.Level1)
{
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
}

/* *
 * @tc.name: UninstallDlpSandbox002
 * @tc.desc: UninstallDlpSandbox invalid input.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGF AR000GVIGG
 */
HWTEST_F(DlpPermissionKitTest, UninstallDlpSandbox002, TestSize.Level1)
{
    int32_t appIndex = 1;
    ASSERT_NE(DLP_OK, DlpPermissionKit::UninstallDlpSandbox("test.test", appIndex, DEFAULT_USERID));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::UninstallDlpSandbox("", appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: GetSandboxExternalAuthorization001
 * @tc.desc: GetSandboxExternalAuthorization test.
 * @tc.type: FUNC
 * @tc.require: SR000GVIR0 AR000GVIR1
 */
HWTEST_F(DlpPermissionKitTest, GetSandboxExternalAuthorization001, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID selfTokenId = GetSelfTokenID();
    // sandboxUid is invalid
    OHOS::AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    ASSERT_NE(DLP_OK, DlpPermissionKit::GetSandboxExternalAuthorization(-1, want, authType));

    // sandboxUid is ok
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    int sandboxUid;
    ASSERT_TRUE(TestGetAppUid(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID, sandboxUid));
    ASSERT_EQ(DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR,
        DlpPermissionKit::GetSandboxExternalAuthorization(sandboxUid, want, authType));
    ASSERT_EQ(DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR,
        DlpPermissionKit::GetSandboxExternalAuthorization(sandboxUid, want, authType));
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    ASSERT_TRUE(authType == DENY_START_ABILITY);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));

    // uid is not sandbox
    ASSERT_EQ(DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL,
        DlpPermissionKit::GetSandboxExternalAuthorization(1000, want, authType));
    ASSERT_TRUE(authType == DENY_START_ABILITY);
    TestRecoverProcessInfo(uid, selfTokenId);
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId001
 * @tc.desc: QueryDlpFileCopyableByTokenId with read only sandbox app tokenId.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGL AR000GVIGM
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileCopyableByTokenId001, TestSize.Level1)
{
    // query dlp file access with read only sandbox app tokenId
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    AccessTokenID sandboxTokenId;
    ASSERT_TRUE(TestGetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, sandboxInfo.appIndex, sandboxTokenId));
    bool copyable = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, sandboxTokenId));
    ASSERT_EQ(copyable, false);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId002
 * @tc.desc: QueryDlpFileCopyableByTokenId with full control sandbox app tokenId.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGL AR000GVIGM
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileCopyableByTokenId002, TestSize.Level1)
{
    // query dlp file access with full control sandbox app tokenId
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    AccessTokenID sandboxTokenId;
    ASSERT_TRUE(TestGetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, sandboxInfo.appIndex, sandboxTokenId));
    bool copyable = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, sandboxTokenId));
    ASSERT_EQ(copyable, true);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId003
 * @tc.desc: QueryDlpFileCopyableByTokenId with normal app tokenId.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGL AR000GVIGM
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileCopyableByTokenId003, TestSize.Level1)
{
    // query dlp file access with normal app tokenId
    bool copyable = false;
    AccessTokenID normalTokenId;
    ASSERT_TRUE(TestGetTokenId(DEFAULT_USERID, DLP_MANAGER_APP, 0, normalTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, normalTokenId));
    ASSERT_EQ(copyable, true);
}

/**
 * @tc.name: QueryDlpFileCopyableByTokenId004
 * @tc.desc: QueryDlpFileCopyableByTokenId invalid input.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGL AR000GVIGM
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileCopyableByTokenId004, TestSize.Level1)
{
    // query dlp file access with invalid tokenId
    bool copyable = false;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, 0));
    ASSERT_EQ(copyable, false);
}

/**
 * @tc.name: QueryDlpFileAccess001
 * @tc.desc: QueryDlpFileAccess in normal app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccess001, TestSize.Level1)
{
    // query dlp file access in normal app
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    DLPPermissionInfo permInfo;
    ASSERT_EQ(DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR, DlpPermissionKit::QueryDlpFileAccess(permInfo));

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: QueryDlpFileAccess002
 * @tc.desc: QueryDlpFileAccess in read only sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccess002, TestSize.Level1)
{
    // query dlp file access in read only sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    DLPPermissionInfo permInfo;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permInfo));
    ASSERT_EQ(permInfo.dlpFileAccess, READ_ONLY);
    ASSERT_EQ(permInfo.flags, ACTION_VIEW);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: QueryDlpFileAccess003
 * @tc.desc: QueryDlpFileAccess in content edit sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccess003, TestSize.Level1)
{
    // query dlp file access in content edit sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, CONTENT_EDIT, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    DLPPermissionInfo permInfo;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permInfo));
    ASSERT_EQ(permInfo.dlpFileAccess, CONTENT_EDIT);
    ASSERT_EQ(permInfo.flags, ACTION_SET_EDIT);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: QueryDlpFileAccess004
 * @tc.desc: QueryDlpFileAccess in full control sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, QueryDlpFileAccess004, TestSize.Level1)
{
    // query dlp file access in full control sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    DLPPermissionInfo permInfo;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::QueryDlpFileAccess(permInfo));
    ASSERT_EQ(permInfo.dlpFileAccess, FULL_CONTROL);
    ASSERT_EQ(permInfo.flags, ACTION_SET_FC);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: IsInDlpSandbox001
 * @tc.desc: IsInDlpSandbox in normal app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, IsInDlpSandbox001, TestSize.Level1)
{
    // query whether in sandbox in normal app
    bool inSandbox = false;

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, false);

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: IsInDlpSandbox002
 * @tc.desc: IsInDlpSandbox in read only sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, IsInDlpSandbox002, TestSize.Level1)
{
    // query whether in sandbox in read only sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    bool inSandbox = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, true);
    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: IsInDlpSandbox003
 * @tc.desc: IsInDlpSandbox in full control sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, IsInDlpSandbox003, TestSize.Level1)
{
    // query whether in sandbox in full control sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    bool inSandbox = false;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsInDlpSandbox(inSandbox));
    ASSERT_EQ(inSandbox, true);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: GetDlpSupportFileType001
 * @tc.desc: GetDlpSupportFileType in normal app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, GetDlpSupportFileType001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "enter GetDlpSupportFileType001");
    // query support dlp file types in normal app
    std::vector<std::string> supportFileType;
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: GetDlpSupportFileType002
 * @tc.desc: GetDlpSupportFileType in read only sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, GetDlpSupportFileType002, TestSize.Level1)
{
    // query support dlp file types in read only sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, READ_ONLY, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    std::vector<std::string> supportFileType;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: GetDlpSupportFileType003
 * @tc.desc: GetDlpSupportFileType in context edit sandbox app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, GetDlpSupportFileType003, TestSize.Level1)
{
    // query support dlp file types in context edit sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, CONTENT_EDIT, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    std::vector<std::string> supportFileType;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: GetDlpSupportFileType004
 * @tc.desc: GetDlpSupportFileType in full control sandbox app.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGN AR000GVIGO
 */
HWTEST_F(DlpPermissionKitTest, GetDlpSupportFileType004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "enter GetDlpSupportFileType004");
    // query support dlp file types in full control sandbox app
    SandboxInfo sandboxInfo;
    TestInstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo);

    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);

    std::vector<std::string> supportFileType;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpSupportFileType(supportFileType));
    ASSERT_EQ(supportFileType.empty(), false);

    TestUninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID);
    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: GetDlpGatheringPolicy001
 * @tc.desc: GetDlpGatheringPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, GetDlpGatheringPolicy001, TestSize.Level1)
{
    // query gathering policy on this device
    bool isGathering = false;

    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDlpGatheringPolicy(isGathering));
    ASSERT_EQ(isGathering, false);
}

/**
 * @tc.name: ClearUnreservedSandbox001
 * @tc.desc: ClearUnreservedSandbox.
 * @tc.type: FUNC
 * @tc.require: SR000I38N7
 */
HWTEST_F(DlpPermissionKitTest, ClearUnreservedSandbox001, TestSize.Level1)
{
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, DlpPermissionKit::ClearUnreservedSandbox());
}

class CbCustomizeTest : public DlpSandboxChangeCallbackCustomize {
public:
    explicit CbCustomizeTest() {}
    ~CbCustomizeTest() {}

    virtual void DlpSandboxChangeCallback(DlpSandboxCallbackInfo& result) {}
};

class TestOpenDlpFileCallbackCustomize : public OpenDlpFileCallbackCustomize {
public:
    explicit TestOpenDlpFileCallbackCustomize() {}
    ~TestOpenDlpFileCallbackCustomize() {}

    void OnOpenDlpFile(OpenDlpFileCallbackInfo &result)
    {
        called = true;
    }
    bool called = false;
};

/**
 * @tc.name: RegisterDlpSandboxChangeCallback001
 * @tc.desc: RegisterDlpSandboxChangeCallback.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, RegisterDlpSandboxChangeCallback001, TestSize.Level1)
{
    const std::shared_ptr<DlpSandboxChangeCallbackCustomize> callbackPtr = std::make_shared<CbCustomizeTest>();
    int32_t res = DlpPermissionKit::RegisterDlpSandboxChangeCallback(callbackPtr);
    ASSERT_EQ(DLP_OK, res);
    res = DlpPermissionKit::RegisterDlpSandboxChangeCallback(callbackPtr);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    bool result;
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
    res = DlpPermissionKit::UnregisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_OK, res);
}

/**
 * @tc.name: RegisterDlpSandboxChangeCallback002
 * @tc.desc: RegisterDlpSandboxChangeCallback.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, RegisterDlpSandboxChangeCallback002, TestSize.Level1)
{
    int32_t res = DlpPermissionKit::RegisterDlpSandboxChangeCallback(nullptr);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    bool result;
    res = DlpPermissionKit::UnregisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
}

/**
 * @tc.name: RegisterDlpSandboxChangeCallback003
 * @tc.desc: RegisterDlpSandboxChangeCallback.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, RegisterDlpSandboxChangeCallback003, TestSize.Level1)
{
    bool result;
    int32_t res = DlpPermissionKit::UnregisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
}

/**
 * @tc.name: DlpSandboxChangeCallback001
 * @tc.desc: DlpSandboxChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, DlpSandboxChangeCallback001, TestSize.Level1)
{
    std::shared_ptr<CbCustomizeTest> callbackPtr = nullptr;
    std::shared_ptr<DlpSandboxChangeCallback> callback = std::make_shared<DlpSandboxChangeCallback>(
        callbackPtr);
    ASSERT_NE(callback, nullptr);
    DlpSandboxCallbackInfo result;
    callback->DlpSandboxStateChangeCallback(result);
    ASSERT_EQ(callback->customizedCallback_, nullptr);
}

/**
 * @tc.name: DlpSandboxChangeCallback002
 * @tc.desc: DlpSandboxChangeCallback function test.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, DlpSandboxChangeCallback002, TestSize.Level1)
{
    std::shared_ptr<CbCustomizeTest> callbackPtr = std::make_shared<CbCustomizeTest>();
    std::shared_ptr<DlpSandboxChangeCallback> callback = std::make_shared<DlpSandboxChangeCallback>(callbackPtr);
    ASSERT_NE(callback, nullptr);
    DlpSandboxCallbackInfo result;
    callback->DlpSandboxStateChangeCallback(result);
    ASSERT_NE(callback->customizedCallback_, nullptr);
    callback->Stop();
}

/**
 * @tc.name: RegisterOpenDlpFileCallback001
 * @tc.desc: RegisterOpenDlpFileCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, RegisterOpenDlpFileCallback001, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    const std::shared_ptr<TestOpenDlpFileCallbackCustomize> callbackPtr =
        std::make_shared<TestOpenDlpFileCallbackCustomize>();
    ASSERT_NE(callbackPtr, nullptr);
    EXPECT_EQ(DLP_OK, DlpPermissionKit::RegisterOpenDlpFileCallback(callbackPtr));
    SandboxInfo sandboxInfo;
    EXPECT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    usleep(50000); // sleep 50ms
    EXPECT_EQ(true, callbackPtr->called);
    EXPECT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));
    EXPECT_EQ(DLP_OK, DlpPermissionKit::UnRegisterOpenDlpFileCallback(callbackPtr));

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: RegisterOpenDlpFileCallback002
 * @tc.desc: RegisterOpenDlpFileCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, RegisterOpenDlpFileCallback002, TestSize.Level1)
{
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::RegisterOpenDlpFileCallback(nullptr));
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::UnRegisterOpenDlpFileCallback(nullptr));
}

/**
 * @tc.name: RegisterOpenDlpFileCallback003
 * @tc.desc: RegisterOpenDlpFileCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, RegisterOpenDlpFileCallback003, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    const std::shared_ptr<TestOpenDlpFileCallbackCustomize> callbackPtr =
        std::make_shared<TestOpenDlpFileCallbackCustomize>();
    ASSERT_NE(callbackPtr, nullptr);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::UnRegisterOpenDlpFileCallback(callbackPtr));

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: RegisterOpenDlpFileCallback004
 * @tc.desc: RegisterOpenDlpFileCallback.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, RegisterOpenDlpFileCallback004, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);

    std::vector<std::shared_ptr<TestOpenDlpFileCallbackCustomize>> ptrList;
    const std::shared_ptr<TestOpenDlpFileCallbackCustomize> callbackPtr =
        std::make_shared<TestOpenDlpFileCallbackCustomize>();
    ASSERT_NE(callbackPtr, nullptr);
    EXPECT_EQ(DLP_OK, DlpPermissionKit::RegisterOpenDlpFileCallback(callbackPtr));
    ptrList.emplace_back(callbackPtr);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::RegisterOpenDlpFileCallback(callbackPtr));
    for (int32_t i = 0; i < 99; i++) {
        const std::shared_ptr<TestOpenDlpFileCallbackCustomize> callback =
            std::make_shared<TestOpenDlpFileCallbackCustomize>();
        ASSERT_NE(callback, nullptr);
        EXPECT_EQ(DLP_OK, DlpPermissionKit::RegisterOpenDlpFileCallback(callback));
        ptrList.emplace_back(callback);
    }
    const std::shared_ptr<TestOpenDlpFileCallbackCustomize> callback =
        std::make_shared<TestOpenDlpFileCallbackCustomize>();
    ASSERT_NE(callback, nullptr);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::RegisterOpenDlpFileCallback(callback));
    ptrList.emplace_back(callback);
    for (auto& iter : ptrList) {
        DlpPermissionKit::UnRegisterOpenDlpFileCallback(iter);
    }

    TestRecoverProcessInfo(uid, tokenId);
}

/**
 * @tc.name: OpenDlpFileCallback001
 * @tc.desc: OpenDlpFileCallback function test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, OpenDlpFileCallback001, TestSize.Level1)
{
    std::shared_ptr<TestOpenDlpFileCallbackCustomize> callbackPtr = nullptr;
    std::shared_ptr<OpenDlpFileCallback> callback = std::make_shared<OpenDlpFileCallback>(callbackPtr);
    ASSERT_NE(callback, nullptr);
    OpenDlpFileCallbackInfo result;
    callback->OnOpenDlpFile(result);
    ASSERT_EQ(callback->customizedCallback_, nullptr);
}

/**
 * @tc.name: OpenDlpFileCallback002
 * @tc.desc: OpenDlpFileCallback function test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, OpenDlpFileCallback002, TestSize.Level1)
{
    std::shared_ptr<TestOpenDlpFileCallbackCustomize> callbackPtr =
        std::make_shared<TestOpenDlpFileCallbackCustomize>();
    std::shared_ptr<OpenDlpFileCallback> callback = std::make_shared<OpenDlpFileCallback>(callbackPtr);
    ASSERT_NE(callback, nullptr);
    OpenDlpFileCallbackInfo result;
    callback->OnOpenDlpFile(result);
    EXPECT_EQ(true, callbackPtr->called);
    ASSERT_NE(callback->customizedCallback_, nullptr);
}

/**
 * @tc.name: OnGenerateDlpCertificate002
 * @tc.desc: OnGenerateDlpCertificate function test.
 * @tc.type: FUNC
 * @tc.require: DTS2023040302317
 */
HWTEST_F(DlpPermissionKitTest, OnGenerateDlpCertificate002, TestSize.Level1)
{
    std::vector<uint8_t> cert;
    auto generateDlpCertificateCallback = std::make_shared<ClientGenerateDlpCertificateCallback>();
    generateDlpCertificateCallback->OnGenerateDlpCertificate(0, cert);
    ASSERT_EQ(0, generateDlpCertificateCallback->result_);
    PermissionPolicy policy;
    auto parseDlpCertificateCallback = std::make_shared<ClientParseDlpCertificateCallback>();
    parseDlpCertificateCallback->OnParseDlpCertificate(0, policy, {});
    ASSERT_EQ(0, generateDlpCertificateCallback->result_);
}

/**
 * @tc.name: ParseDlpCertificate002
 * @tc.desc: ParseDlpCertificate abnormal input test.
 * @tc.type: FUNC
 * @tc.require:AR000GVIG0
 */
HWTEST_F(DlpPermissionKitTest, ParseDlpCertificate002, TestSize.Level1)
{
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    certParcel->offlineCert.push_back(1);
    PermissionPolicy policy;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        DlpPermissionKit::ParseDlpCertificate(certParcel, policy, "", true));

    policy.ownerAccount_ = "test";
    policy.ownerAccountId_ = "test";
    policy.ownerAccountType_ = CLOUD_ACCOUNT;
    std::vector<AuthUserInfo> authUsers_;
    AuthUserInfo info;
    info.authAccount = "test";
    info.authPerm = FULL_CONTROL;
    info.permExpiryTime = 1784986283;
    info.authAccountType = CLOUD_ACCOUNT;
    authUsers_.push_back(info);
    uint8_t* iv = new (std::nothrow) uint8_t[16];
    uint8_t* aseKey = new (std::nothrow) uint8_t[16];
    policy.SetIv(iv, 16);
    policy.SetAeskey(aseKey, 16);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        DlpPermissionKit::ParseDlpCertificate(certParcel, policy, "", true));
    delete[] iv;
    delete[] aseKey;
}

/**
 * @tc.name: GetDLPFileVisitRecord001
 * @tc.desc: GetDLPFileVisitRecord.
 * @tc.type: FUNC
 * @tc.require: AR000I38MV
 */
HWTEST_F(DlpPermissionKitTest, GetDLPFileVisitRecord001, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID selfTokenId = GetSelfTokenID();
    std::vector<VisitedDLPFileInfo> infoVec;
    SandboxInfo sandboxInfo;
    ASSERT_EQ(DLP_OK,
        DlpPermissionKit::InstallDlpSandbox(DLP_MANAGER_APP, FULL_CONTROL, DEFAULT_USERID, sandboxInfo, TEST_URI));
    ASSERT_TRUE(sandboxInfo.appIndex != 0);
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDLPFileVisitRecord(infoVec));
    DLP_LOG_INFO(LABEL, "GetDLPFileVisitRecord size:%{public}zu", infoVec.size());
    ASSERT_TRUE(1 == infoVec.size());
    setuid(g_selfUid);
    infoVec.clear();
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetDLPFileVisitRecord(infoVec));
    ASSERT_TRUE(0 == infoVec.size());
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, DLP_MANAGER_APP, sandboxInfo.appIndex);
    ASSERT_TRUE(TestSetSelfTokenId(tokenId));
    ASSERT_EQ(DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR, DlpPermissionKit::GetDLPFileVisitRecord(infoVec));
    ASSERT_TRUE(TestSetSelfTokenId(g_dlpManagerTokenId));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::UninstallDlpSandbox(DLP_MANAGER_APP, sandboxInfo.appIndex, DEFAULT_USERID));

    TestRecoverProcessInfo(uid, selfTokenId);
}

/* *
 * @tc.name: SetSandboxAppConfig001
 * @tc.desc: SetSandboxAppConfig001  test.
 * @tc.type: FUNC
 * @tc.require: SR000IEUH3
 */
HWTEST_F(DlpPermissionKitTest, SetSandboxAppConfig001, TestSize.Level1)
{
    int32_t uid = getuid();
    AccessTokenID tokenId = GetSelfTokenID();
    TestMockApp(DLP_MANAGER_APP, 0, DEFAULT_USERID);
    std::string config = "test";
    ASSERT_EQ(DLP_OK, DlpPermissionKit::SetSandboxAppConfig(config));
    std::string configGet;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetSandboxAppConfig(configGet));
    ASSERT_EQ(DLP_OK, DlpPermissionKit::CleanSandboxAppConfig());
    TestRecoverProcessInfo(uid, tokenId);
}

/* *
 * @tc.name: SetMDMPolicy001
 * @tc.desc: SetMDMPolicy001 abnormal input test.
 * @tc.type: FUNC
 * @tc.require: SR000IEUHS
 */
HWTEST_F(DlpPermissionKitTest, SetMDMPolicy001, TestSize.Level1)
{
    seteuid(1000);
    std::vector<std::string> appIdList;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::SetMDMPolicy(appIdList));
    appIdList.push_back("@ohos.test.bundleName1_QG9ob3MudGVzdC5idW5kbGVOYW1lMQ==");
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, DlpPermissionKit::SetMDMPolicy(appIdList));
    seteuid(3057);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::SetMDMPolicy(appIdList));
    appIdList.push_back("");
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::SetMDMPolicy(appIdList));
    appIdList.pop_back();
    appIdList.push_back("@ohos.test.bundleName2_QG9ob3MudGVzdC5idW5kbGVOYW1lMg==");
    appIdList.push_back("@ohos.test.bundleName3_QG9ob3MudGVzdC5idW5kbGVOYW1lMw==");
    appIdList.push_back(
        "@ohos.test.bundleNameWhichIsLongerThanThe200digitsLengthLimit\
        123456789123456789123456789_QG9ob3MudGVzdC5idW5kbGVOYW1lV2hpY2hJc0xvbmdlclRoYW5UaGUyMDBkaWdpdHNMZW5nd\
        GhMaW1pdDEyMzQ1Njc4OTEyMzQ1Njc4OTEyMzQ1Njc4OQ==");
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::SetMDMPolicy(appIdList));
    appIdList.pop_back();
    for (int i = 0; i < 250; i++) {
        appIdList.push_back("@ohos.test.bundleName1_QG9ob3MudGVzdC5idW5kbGVOYW1lMQ==");
    }
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpPermissionKit::SetMDMPolicy(appIdList));
    appIdList.clear();
}

/* *
 * @tc.name: GetMDMPolicy001
 * @tc.desc: GetMDMPolicy001S abnormal input test.
 * @tc.type: FUNC
 * @tc.require: SR000IEUHS
 */
HWTEST_F(DlpPermissionKitTest, GetMDMPolicy001, TestSize.Level1)
{
    seteuid(1000);
    std::vector<std::string> appIdList;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, DlpPermissionKit::GetMDMPolicy(appIdList));
    seteuid(3057);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::GetMDMPolicy(appIdList));
    appIdList.clear();
}

/* *
 * @tc.name: RemoveMDMPolicy001
 * @tc.desc: RemoveMDMPolicy001 abnormal input test.
 * @tc.type: FUNC
 * @tc.require: SR000IEUHS
 */
HWTEST_F(DlpPermissionKitTest, RemoveMDMPolicy001, TestSize.Level1)
{
    seteuid(1000);
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, DlpPermissionKit::RemoveMDMPolicy());
    seteuid(3057);
    ASSERT_EQ(DLP_OK, DlpPermissionKit::RemoveMDMPolicy());
}

/* *
 * @tc.name: IsDLPFeatureProvided001
 * @tc.desc: IsDLPFeatureProvided.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionKitTest, IsDLPFeatureProvided001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "Start IsDLPFeatureProvided001.");
    bool isProvided;
    ASSERT_EQ(DLP_OK, DlpPermissionKit::IsDLPFeatureProvided(isProvided));
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
