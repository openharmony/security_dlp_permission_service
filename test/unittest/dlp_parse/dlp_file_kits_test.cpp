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

#include "dlp_file_kits_test.h"
#include <cstdio>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>
#include "ability_info.h"
#include "accesstoken_kit.h"
#include "base_obj.h"
#include "dlp_file.h"
#include "c_mock_common.h"
#include "dlp_file_kits.h"
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_utils.h"
#include "int_wrapper.h"
#include "permission_policy.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using namespace std;

using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
using WantParamWrapper = OHOS::AAFwk::WantParamWrapper;
using String = OHOS::AAFwk::String;
using Integer = OHOS::AAFwk::Integer;

namespace OHOS {
namespace Security {
namespace DlpPermissionUnitTest {
void SetMockGetAuthPolicyWithType(const std::vector<bool>& retSeq,
    const std::vector<std::vector<std::string>>& valueSeq);
void SetMockGetFileTypeBySuffix(const std::string& fileType);
void SetMockGetRealTypeWithFd(const std::string& realType);
void SetMockGetRawFileAllowedOpenCount(int32_t ret, int32_t allowedOpenCount, bool waterMarkConfig);
void ResetDlpUtilsMockState();

void SetMockGetAbilityInfos(int32_t ret, const std::vector<AppExecFwk::AbilityInfo>& abilityInfos);
void ResetDlpPermissionKitMockState();
void SetForegroundOsAccountLocalIdRet(int32_t ret);
} // namespace DlpPermissionUnitTest
} // namespace Security
} // namespace OHOS

namespace OHOS {
namespace AppFileService {
namespace ModuleFileUri {
namespace {
static const std::string DLP_FILE_NAME = "/data/test/fuse_test.txt.dlp";
static int32_t g_fileUriReturnCount = 1;
static std::string g_fileUriPath = DLP_FILE_NAME;
}
std::string FileUri::GetRealPath()
{
    if (g_fileUriReturnCount != 0) {
        if (g_fileUriReturnCount > 0) {
            g_fileUriReturnCount--;
        }
        return g_fileUriPath;
    }
    return "";
}

void SetMockGetRealPathCount(int32_t count)
{
    g_fileUriReturnCount = count;
}

void SetMockGetRealPath(const std::string& path)
{
    g_fileUriPath = path;
}
}
}
}
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileKitsTest"};

static int g_dlpFileFd = -1;
static const std::string PLAIN_FILE_NAME = "/data/test/fuse_test.txt";
static const std::string DLP_FILE_NAME = "/data/test/fuse_test.txt.dlp";
static const std::string DLP_FILE_NAME_2 = "/data/test/fuse_test2.txt.dlp";
static const std::string DLP_FILE_URI = "file://data/test/fuse_test.txt.dlp";
static const std::string DLP_FILE_URI_2 = "file://data/test/fuse_test2.txt.dlp";
static const std::string PLAIN_FILE_URI = "file://data/test/fuse_test.txt";
static const std::string DLP_FILE_ERR_SUFFIX_URI = "file://data/test/fuse_test..txt";
static const std::string DLP_FILE_ERR_SUFFIX_URI_2 = "file://data/test/fuse_test.aaa.txt";
static const std::string DLP_TEST_DIR = "/data/test/dlpTest/";
static const int DLP_FILE_PERMISSION = 0777;
static const uint32_t DLPHEADER_SIZE = sizeof(struct DlpHeader);
static const uint32_t ADDHEADER_SIZE = 8;
static const uint32_t CURRENT_VERSION = 3;
static constexpr int FIRST_COUNT = 1;
static constexpr int SECOND_COUNT = 2;
static constexpr int THIRD_COUNT = 3;

void ResetMockState()
{
    OHOS::Security::DlpPermissionUnitTest::ResetDlpUtilsMockState();
    OHOS::Security::DlpPermissionUnitTest::ResetDlpPermissionKitMockState();
    OHOS::Security::DlpPermissionUnitTest::SetForegroundOsAccountLocalIdRet(0);
    OHOS::AppFileService::ModuleFileUri::SetMockGetRealPath(DLP_FILE_NAME);
    OHOS::AppFileService::ModuleFileUri::SetMockGetRealPathCount(1);
}

static off_t LseekReplyMock(int fd, off_t offset, int whence)
{
    (void)fd;
    return 0;
}

static ssize_t ReadReplyMock(int fd, void *dest, size_t maxCount)
{
    (void)fd;
    static int callCount = 0;
    callCount++;
    if (callCount == FIRST_COUNT) {
        *(static_cast<uint32_t*>(dest)) = CURRENT_VERSION;
        return sizeof(uint32_t);
    } else if (callCount == SECOND_COUNT) {
        *(static_cast<uint32_t*>(dest)) = DLPHEADER_SIZE;
        return sizeof(uint32_t);
    } else if (callCount == THIRD_COUNT) {
        DlpHeader mockHeader = {
            .magic = 0x87f4922,
            .fileType = 1,
            .offlineAccess = 0,
            .algType = 2,
            .certSize = 128,
            .hmacSize = 32 * 2,
            .contactAccountOffset = DLPHEADER_SIZE + 8,
            .contactAccountSize = 1,
            .offlineCertSize = 0,
            .txtOffset = DLPHEADER_SIZE + 8 + 1,
            .txtSize = 200,
            .certOffset = DLPHEADER_SIZE + 8 + 1,
            .hmacOffset = DLPHEADER_SIZE + 8 + 1 + 200,
            .offlineCertOffset = 500
        };
        *(static_cast<DlpHeader*>(dest)) = mockHeader;
        return DLPHEADER_SIZE;
    }

    return -1;
}

static ssize_t ReadReplyMockEnterprise(int fd, void *dest, size_t maxCount)
{
    static int callCount = 0;
    callCount++;
    if (callCount == FIRST_COUNT) {
        *(static_cast<uint32_t*>(dest)) = CURRENT_VERSION;
        return sizeof(uint32_t);
    } else if (callCount == SECOND_COUNT) {
        *(static_cast<uint32_t*>(dest)) = DLPHEADER_SIZE + ADDHEADER_SIZE;
        return sizeof(uint32_t);
    } else if (callCount == THIRD_COUNT) {
        DlpHeader mockHeader = {
            .magic = 0x87f4922,
            .fileType = 1,
            .offlineAccess = 0,
            .algType = 2,
            .certSize = 128,
            .hmacSize = 32 * 2,
            .contactAccountOffset = DLPHEADER_SIZE + 8 + 8,
            .contactAccountSize = 0,
            .offlineCertSize = 0,
            .txtOffset = DLPHEADER_SIZE + 8 + 8,
            .txtSize = 200,
            .certOffset = DLPHEADER_SIZE + 8 + 8,
            .hmacOffset = DLPHEADER_SIZE + 8 + 8 + 200,
            .offlineCertOffset = 500
        };
        *(static_cast<DlpHeader*>(dest)) = mockHeader;
        return DLPHEADER_SIZE;
    }

    return -1;
}

void CreateDlpFileFd()
{
    int plainFileFd = open(PLAIN_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    if (plainFileFd < 0) {
        cout << "create dlpFile fd failed" << endl;
        return;
    }
    int fileFd = open(DLP_FILE_NAME_2.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    if (fileFd < 0) {
        close(plainFileFd);
        cout << "create dlpFile fd failed" << endl;
        return;
    }
    g_dlpFileFd = open(DLP_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    if (g_dlpFileFd < 0) {
        close(plainFileFd);
        close(fileFd);
        cout << "create dlpFile fd failed" << endl;
        return;
    }

    struct DlpProperty prop;
    prop.ownerAccount = "ohosAnonymousName";
    prop.ownerAccountId = "ohosAnonymousName";
    prop.ownerAccountType = CLOUD_ACCOUNT;
    prop.contactAccount = "test@test.com";

    std::shared_ptr<DlpFile> filePtr;
    int ret = DlpFileManager::GetInstance().GenerateDlpFile(plainFileFd,
        g_dlpFileFd, prop, filePtr, DLP_TEST_DIR);
    close(plainFileFd);
    close(fileFd);
    if (ret != DLP_OK) {
        cout << "create dlpFile object failed" << endl;
        return;
    }
    DlpFileManager::GetInstance().CloseDlpFile(filePtr);
}
}

void DlpFileKitsTest::SetUpTestCase()
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
    CreateDlpFileFd();
}

void DlpFileKitsTest::TearDownTestCase()
{
    if (g_dlpFileFd != -1) {
        close(g_dlpFileFd);
        g_dlpFileFd = -1;
    }
    rmdir(DLP_TEST_DIR.c_str());
}

void DlpFileKitsTest::SetUp()
{
    ResetMockState();
}

void DlpFileKitsTest::TearDown()
{
    ResetMockState();
}

/**
 * @tc.name: GetSandboxFlag001
 * @tc.desc: Get Sandbox flag, want valid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag001");
    OHOS::AAFwk::Want want;

    want.SetAction(TAG_ACTION_VIEW);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    want.SetAction(TAG_ACTION_EDIT);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
}

/**
 * @tc.name: GetSandboxFlag002
 * @tc.desc: Get Sandbox flag, action inValid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag002");
    OHOS::AAFwk::Want want;
    want.SetAction("ohos.want.action.home");

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag003
 * @tc.desc: Get Sandbox flag, no fileName param
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag003");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag004
 * @tc.desc: Get Sandbox flag, file name is not dlp
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag004");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(DLP_FILE_URI);

    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
}

/**
 * @tc.name: GetSandboxFlag005
 * @tc.desc: Get Sandbox flag, file name is .dlp
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag005");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box(".dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag006
 * @tc.desc: Get Sandbox flag, file name is less than ".dlp"
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag006");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("lp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag008
 * @tc.desc: Get Sandbox flag, no keyFd
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag008, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag008");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag009
 * @tc.desc: Get Sandbox flag, keyFd type is not FD
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag009, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag009");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box("FD1"));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(g_dlpFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag010
 * @tc.desc: Get Sandbox flag, fileFd has no value key
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag010, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag009");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag011
 * @tc.desc: Get Sandbox flag, fileFd fd = -1
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag011, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag011");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(-1));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag012
 * @tc.desc: Get Sandbox flag, fileFd fd is real, but is not dlpfile fd
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag012, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag012");
    int plainFileFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(plainFileFd, 0);

    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);

    WantParams TopParam;
    WantParams fileNameParam;
    fileNameParam.SetParam(TAG_FILE_NAME_VALUE, String::Box("test.txt.dlp"));
    TopParam.SetParam(TAG_FILE_NAME, WantParamWrapper::Box(fileNameParam));

    WantParams fileFdParam;
    fileFdParam.SetParam(TAG_KEY_FD_TYPE, String::Box(VALUE_KEY_FD_TYPE));
    fileFdParam.SetParam(TAG_KEY_FD_VALUE, Integer::Box(plainFileFd));
    TopParam.SetParam(TAG_KEY_FD, WantParamWrapper::Box(fileFdParam));
    want.SetParams(TopParam);

    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    ASSERT_FALSE((want.GetType() == "text/plain"));
}

/**
 * @tc.name: GetSandboxFlag013
 * @tc.desc: Get Sandbox flag, want valid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag013, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag004");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(PLAIN_FILE_URI);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    want.SetUri(DLP_FILE_URI_2);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
}

/**
 * @tc.name: IsDlpFile001
 * @tc.desc: test param whether dlpFd is valid.
 * @tc.type: FUNC
 * @tc.require:issue：IAIFTY
 */
HWTEST_F(DlpFileKitsTest, IsDlpFile001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "IsDlpFile001");

    int32_t dlpFd = -1;
    ASSERT_FALSE(DlpFileKits::IsDlpFile(dlpFd));

    dlpFd = 1;
    ASSERT_FALSE(DlpFileKits::IsDlpFile(dlpFd));

    dlpFd = open("/data/fuse_test.txt", O_CREAT | O_RDWR | O_TRUNC, 0777);
    ASSERT_GE(dlpFd, 0);
    ASSERT_FALSE(DlpFileKits::IsDlpFile(dlpFd));
    ASSERT_EQ(close(dlpFd), 0);
}

/**
 * @tc.name: IsDlpFile002
 * @tc.desc: IsDlpFile test IsValidDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileKitsTest, IsDlpFile002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "IsDlpFile002");

    int32_t dlpFd = 1;

    DlpCMockCondition condition;
    condition.mockSequence = {true, true, true};
    SetMockConditions("lseek", condition);
    SetMockCallback("lseek", reinterpret_cast<CommonMockFuncT>(LseekReplyMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = {true, true, true};
    SetMockConditions("read", condition1);
    SetMockCallback("read", reinterpret_cast<CommonMockFuncT>(ReadReplyMock));

    EXPECT_EQ(true, DlpFileKits::IsDlpFile(dlpFd));
    CleanMockConditions();
}

/**
 * @tc.name: IsDlpFile003
 * @tc.desc: IsDlpFile test IsValidEnterpriseDlpHeader
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpFileKitsTest, IsDlpFile003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "IsDlpFile003");

    int32_t dlpFd = 1;

    DlpCMockCondition condition;
    condition.mockSequence = {true, true, true};
    SetMockConditions("lseek", condition);
    SetMockCallback("lseek", reinterpret_cast<CommonMockFuncT>(LseekReplyMock));

    DlpCMockCondition condition1;
    condition1.mockSequence = {true, true, true};
    SetMockConditions("read", condition1);
    SetMockCallback("read", reinterpret_cast<CommonMockFuncT>(ReadReplyMockEnterprise));

    EXPECT_EQ(true, DlpFileKits::IsDlpFile(dlpFd));
    CleanMockConditions();
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp
 * @tc.desc: test ConvertAbilityInfoWithSupportDlp param.
 * @tc.type: FUNC
 * @tc.require:issue：IAIFTY
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp001, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp001");

    OHOS::AAFwk::Want want;
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);

    std::vector<std::string> authPolicy;
    std::string fileType = DlpUtils::GetFileTypeBySuffix("txt", true);
    fileType = DlpUtils::GetFileTypeBySuffix("txt", false);
    DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy);
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    for (const string& bundleName : authPolicy) {
        abilityInfo.bundleName = bundleName;
        abilityInfos.push_back(abilityInfo);
    }

    want.SetUri(PLAIN_FILE_URI);
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    
    want.SetUri(DLP_FILE_ERR_SUFFIX_URI);
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);

    want.SetUri(DLP_FILE_ERR_SUFFIX_URI_2);
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);

    want.SetUri(DLP_FILE_URI);
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    EXPECT_NE(abilityInfos.size(), -1);
}

/**
 * @tc.name: GetSandboxFlag014
 * @tc.desc: cover GetRawFileAllowedOpenCount error branch in SetWantType
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag014, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag014");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRealTypeWithFd("txt");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRawFileAllowedOpenCount(DLP_PARSE_ERROR_FD_ERROR, 0, false);

    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(DLP_FILE_URI);
    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
    EXPECT_EQ(want.GetType(), "text/plain");
}

/**
 * @tc.name: GetSandboxFlag015
 * @tc.desc: cover allowedOpenCount > 0 branch in SetWantType
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag015, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag015");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRealTypeWithFd("txt");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRawFileAllowedOpenCount(DLP_OK, 1, false);

    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(DLP_FILE_URI);
    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
    EXPECT_EQ(want.GetType(), "image/jpeg");
}

/**
 * @tc.name: GetSandboxFlag016
 * @tc.desc: cover waterMarkConfig true branch in SetWantType
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag016, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag016");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRealTypeWithFd("txt");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetRawFileAllowedOpenCount(DLP_OK, 0, true);

    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(DLP_FILE_URI);
    ASSERT_TRUE(DlpFileKits::GetSandboxFlag(want));
    EXPECT_EQ(want.GetType(), "image/jpeg");
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp002
 * @tc.desc: cover fileType empty and auth policy query fail branches
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp002, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp002");
    OHOS::AAFwk::Want want;
    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.bundleName = "bundle.keep";
    abilityInfos.push_back(abilityInfo);

    want.SetUri(PLAIN_FILE_URI);
    want.SetType("text/plain");
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 1);

    want.SetUri(DLP_FILE_URI);
    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType({false}, {{}});
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 1);
    EXPECT_EQ(want.GetType(), "text/plain");
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp003
 * @tc.desc: cover IsSupportDlp true/false and abilityInfos not empty return branch
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp003, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp003");
    OHOS::AAFwk::Want want;
    want.SetUri(DLP_FILE_URI);
    want.SetType("text/plain");

    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo keepInfo;
    keepInfo.bundleName = "bundle.keep";
    abilityInfos.push_back(keepInfo);
    OHOS::AppExecFwk::AbilityInfo dropInfo;
    dropInfo.bundleName = "bundle.drop";
    abilityInfos.push_back(dropInfo);

    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType({true}, {{"bundle.keep"}});
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);

    ASSERT_EQ(abilityInfos.size(), 1);
    EXPECT_EQ(abilityInfos[0].bundleName, "bundle.keep");
    EXPECT_EQ(want.GetType(), "dlp");
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp004
 * @tc.desc: cover default policy size <= 1 return branch
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp004, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp004");
    OHOS::AAFwk::Want want;
    want.SetUri(DLP_FILE_URI);
    want.SetType("text/plain");

    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo dropInfo;
    dropInfo.bundleName = "bundle.drop";
    abilityInfos.push_back(dropInfo);

    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType({true, true}, {{"bundle.keep"}, {"only.one"}});
    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);

    EXPECT_EQ(abilityInfos.size(), 0);
    EXPECT_EQ(want.GetType(), "dlp");
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp005
 * @tc.desc: cover ConvertAbilityInfoWithBundleName success branch
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp005, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp005");
    OHOS::AAFwk::Want want;
    want.SetUri(DLP_FILE_URI);
    want.SetType("text/plain");

    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo dropInfo;
    dropInfo.bundleName = "bundle.drop";
    abilityInfos.push_back(dropInfo);

    OHOS::AppExecFwk::AbilityInfo fillInfo;
    fillInfo.bundleName = "bundle.default";
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAbilityInfos(DLP_OK, {fillInfo});
    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType(
        {true, true}, {{"bundle.keep"}, {"defaultAbility", "defaultBundle"}});

    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    ASSERT_EQ(abilityInfos.size(), 1);
    EXPECT_EQ(abilityInfos[0].bundleName, "bundle.default");
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp006
 * @tc.desc: cover ConvertAbilityInfoWithBundleName GetAbilityInfos fail branch
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp006, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp006");
    OHOS::AAFwk::Want want;
    want.SetUri(DLP_FILE_URI);
    want.SetType("text/plain");

    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo dropInfo;
    dropInfo.bundleName = "bundle.drop";
    abilityInfos.push_back(dropInfo);

    OHOS::Security::DlpPermissionUnitTest::SetMockGetAbilityInfos(DLP_PARSE_ERROR_GET_ACCOUNT_FAIL, {});
    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType(
        {true, true}, {{"bundle.keep"}, {"defaultAbility", "defaultBundle"}});

    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 0);
}

/**
 * @tc.name: ConvertAbilityInfoWithSupportDlp007
 * @tc.desc: cover ConvertAbilityInfoWithBundleName GetForegroundOsAccountLocalId fail branch
 * @tc.type: FUNC
 */
HWTEST_F(DlpFileKitsTest, ConvertAbilityInfoWithSupportDlp007, TestSize.Level0)
{
    DLP_LOG_INFO(LABEL, "ConvertAbilityInfoWithSupportDlp007");
    OHOS::AAFwk::Want want;
    want.SetUri(DLP_FILE_URI);
    want.SetType("text/plain");

    std::vector<OHOS::AppExecFwk::AbilityInfo> abilityInfos;
    OHOS::AppExecFwk::AbilityInfo dropInfo;
    dropInfo.bundleName = "bundle.drop";
    abilityInfos.push_back(dropInfo);

    OHOS::Security::DlpPermissionUnitTest::SetForegroundOsAccountLocalIdRet(-1);
    OHOS::Security::DlpPermissionUnitTest::SetMockGetFileTypeBySuffix("text");
    OHOS::Security::DlpPermissionUnitTest::SetMockGetAuthPolicyWithType(
        {true, true}, {{"bundle.keep"}, {"defaultAbility", "defaultBundle"}});

    DlpFileKits::ConvertAbilityInfoWithSupportDlp(want, abilityInfos);
    EXPECT_EQ(abilityInfos.size(), 0);
}