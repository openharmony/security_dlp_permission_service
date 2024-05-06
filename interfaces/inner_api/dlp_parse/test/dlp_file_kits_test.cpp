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
#include "accesstoken_kit.h"
#include "base_object.h"
#include "dlp_file_kits.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "int_wrapper.h"
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
namespace AppFileService {
namespace ModuleFileUri {
namespace {
static const std::string DLP_FILE_NAME = "/data/test/fuse_test.txt.dlp";
}
std::string FileUri::GetRealPath()
{
    static int32_t gCount = 1;
    if (gCount == 1) {
        gCount++;
        return DLP_FILE_NAME;
    }
    return "";
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
static const std::string DLP_TEST_DIR = "/data/test/dlpTest/";
static const int DLP_FILE_PERMISSION = 0777;

void CreateDlpFileFd()
{
    int plainFileFd = open(PLAIN_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    int fileFd = open(DLP_FILE_NAME_2.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    g_dlpFileFd = open(DLP_FILE_NAME.c_str(), O_CREAT | O_RDWR | O_TRUNC, DLP_FILE_PERMISSION);
    if (plainFileFd < 0 || g_dlpFileFd < 0) {
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

void DlpFileKitsTest::SetUp() {}

void DlpFileKitsTest::TearDown() {}

/**
 * @tc.name: GetSandboxFlag001
 * @tc.desc: Get Sandbox flag, want valid
 * @tc.type: FUNC
 * @tc.require:AR000H7BOC
 */
HWTEST_F(DlpFileKitsTest, GetSandboxFlag001, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag002, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag003, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag004, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag005, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag006, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag008, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag009, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag010, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag011, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag012, TestSize.Level1)
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
HWTEST_F(DlpFileKitsTest, GetSandboxFlag013, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetSandboxFlag004");
    OHOS::AAFwk::Want want;
    want.SetAction(TAG_ACTION_VIEW);
    want.SetUri(PLAIN_FILE_URI);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
    want.SetUri(DLP_FILE_URI_2);
    ASSERT_FALSE(DlpFileKits::GetSandboxFlag(want));
}
