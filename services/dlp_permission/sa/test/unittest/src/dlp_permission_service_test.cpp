/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dlp_permission_service_test.h"
#include <string>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "app_uninstall_observer.h"
#define private public
#include "dlp_sandbox_change_callback_manager.h"
#include "open_dlp_file_callback_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy.h"
#include "dlp_sandbox_change_callback_proxy.h"
#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "open_dlp_file_callback_proxy.h"
#include "open_dlp_file_callback_stub.h"
#include "open_dlp_file_callback_death_recipient.h"
#include "file_operator.h"
#include "retention_file_manager.h"
#include "sandbox_json_manager.h"
#include "visited_dlp_file_info.h"
#define private public
#include "visit_record_file_manager.h"
#include "visit_record_json_manager.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using namespace std::chrono;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionServiceTest"};
const std::string TEST_URI = "/data/service/el1/public/dlp_permission_service1/retention_sandbox_info_test.json";
static const int32_t DEFAULT_USERID = 100;
static const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
const uint32_t ACCOUNT_LENGTH = 20;
const uint32_t USER_NUM = 1;
const int AUTH_PERM = 1;
const int64_t DELTA_EXPIRY_TIME = 200;
const uint64_t EXPIRY_TEN_MINUTE = 60 * 10;
const uint32_t AESKEY_LEN = 32;
const std::string ENC_ACCOUNT_TYPE = "accountType";

static const std::string POLICY_CIPHER = "8B6696A5DD160005C9DCAF43025CB240958D1E53D8E54D70DBED8C191411FA60C9B5D491B"
    "AE3F34F124DBA805736FCBBC175D881818A93A0E07C844E9DF9503641BF2A98EC49BE0BB2"
    "E75397187D6A3DC9DEED05A341BFBB761C39C906A9E1344E2CB25432B9C190E1948334A3E"
    "CDB49C4340A7A8977685E4FDB6EB9E329AB5EEB1EEEBAEF158B0442F98C342714553E50477"
    "040A52AD79068E6BC68A2F0E2E500DA721927EFF985BDDAF7BCF78FA3BEF2730B25EC05458"
    "0FDB5BB4EBE7294737E8BF53C6F69C93D00FF41581F80DEA67BB5EBD253BC43729CB8B560B"
    "893154240AC355CDF8381C84A093B39E5CD6CFF5746FD068F8AA1DEDF2C3C2A12AE2A5CDE9"
    "075C8AE86654AE4C696C7BE8EB4AB67E25008DE09A5218EFA13B59BAFDFB11FFBB6AD637B9"
    "B02F598FE511910A9C9F614AF0EA8312F62DAA6C2DA9DCAF973321C45139669E2482C2CB09"
    "4E60361ED2BA908A4C07443251DFD70762E2180FA5E92DA1CE6D9AAF70761382FC1591BF57"
    "554693AC55F7121757AA3A4827C9016E1FF5A84FB367047EA7BB28B8E19521BA72AE0BB7C3"
    "192F5B6D6887034C85A08659850DABD211CD18D5295DD60EEB98FB27C3161134D984665658"
    "3E29E7C166EB1475647889B62448145D146A8A7A777B346AB7476A10209ED8543965EF3ED3"
    "C3F96C1CBEDA994243E3064975C23F32F4412F42753668E2CC447E88D6D73534B9F8DD4221"
    "1074D2D819CA235343D012283F30368DE7C3FBC3A90128EF8CFA86C80C5D7167A3CA60B1F5"
    "93DDAD90BFF1987C9243ACD4463B11B61A87B9953A0CAE8FD93ACC1E0B0140410451E5CD3A"
    "E6BB61CF5B1004F46782D924D79CE5615084102A19604BF99D38BFA8B837210022B6AB21E4"
    "33B5D4E23E278C8CB5EC79DAFEF2A39E3175A0FC6921C37345CAF8D0976677924775A620C5"
    "E63418C6339525433182D8D127816B36B348B781E02DA65ACCBEAE950CFF8579586B18B77A"
    "9960ADF484881811D6044E3CC68577599194439E43263E4095CD5399679B548CDFD7430CFB"
    "F67A1AE23B4136931E10032E4CEACC278584B45337CF7C3E4FEA6D0F1424E3CBC490E4C1DF"
    "FC2927AA3BC5F57471EAA7D12C65064015A25A11D98E25AFCDB1A1DD876A03EADA9CDD015C"
    "1265A7FDFA9A766BA832F4B9A2B55B73A361D2A7BD68572EB2ABE1B1DC93904CB5ACD09807"
    "6FE5089AD8DB2F38DF7D0A76C2C87E36C6F6A5E8190EA76F1F8F0B2493F1FDF38B220BEBC5"
    "554B3038FE83FD7D10C35034CB3D9409AC9F8F762149A4B19CD0B18B87F4251722EFEFB601"
    "6DDFACBB8E6F9BAFD48FCFE5370B5661EC4218A65246337E1E24B14CE14EB82CE3B553B560"
    "8A9A94B1E2E7BAC7CC0B315228E870DF25DFBB8F77A916B8B08692A92D9CB5540DCF4AA4CF"
    "9B196026908";
}

void DlpPermissionServiceTest::SetUpTestCase()
{}

void DlpPermissionServiceTest::TearDownTestCase()
{}

void DlpPermissionServiceTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "setup");
    if (dlpPermissionService_ != nullptr) {
        return;
    }
    dlpPermissionService_ = std::make_shared<DlpPermissionService>(3521, true);
    ASSERT_NE(nullptr, dlpPermissionService_);
    dlpPermissionService_->appStateObserver_ = new (std::nothrow) AppStateObserver();
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_ != nullptr);
}

void DlpPermissionServiceTest::TearDown()
{
    if (dlpPermissionService_ != nullptr) {
        dlpPermissionService_->appStateObserver_ = nullptr;
    }
    dlpPermissionService_ = nullptr;
}

uint64_t GetCurrentTimeSec(void)
{
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

void NewUserSample(AuthUserInfo& user)
{
    user.authAccount = "allowAccountA";
    user.authPerm = FULL_CONTROL;
    user.permExpiryTime = GetCurrentTimeSec() + EXPIRY_TEN_MINUTE;
    user.authAccountType = OHOS::Security::DlpPermission::DlpAccountType::CLOUD_ACCOUNT;
}

static uint8_t* GenerateRandArray(uint32_t len)
{
    uint8_t* str = new (std::nothrow) uint8_t[len];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return nullptr;
    }
    for (uint32_t i = 0; i < len; i++) {
        str[i] = rand() % 255; // uint8_t range 0 ~ 255
    }
    return str;
}

static std::string GenerateRandStr(uint32_t len)
{
    char* str = new (std::nothrow) char[len + 1];
    if (str == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return "";
    }
    for (uint32_t i = 0; i < len; i++) {
        str[i] = 33 + rand() % (126 - 33); // Visible Character Range 33 - 126
    }
    str[len] = '\0';
    std::string res = str;
    delete[] str;
    return res;
}

void GeneratePolicy(PermissionPolicy& encPolicy, uint32_t ownerAccountLen, uint32_t aeskeyLen, uint32_t ivLen,
    uint32_t userNum, uint32_t authAccountLen, uint32_t authPerm, int64_t deltaTime)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto seed = std::time(nullptr);
    std::srand(seed);
    encPolicy.ownerAccount_ = GenerateRandStr(ownerAccountLen);
    encPolicy.ownerAccountId_ = encPolicy.ownerAccount_;
    encPolicy.ownerAccountType_ = OHOS::Security::DlpPermission::DlpAccountType::DOMAIN_ACCOUNT;
    uint8_t* key = GenerateRandArray(aeskeyLen);
    encPolicy.SetAeskey(key, aeskeyLen);
    if (key != nullptr) {
        delete[] key;
        key = nullptr;
    }
    uint8_t* iv = GenerateRandArray(ivLen);
    encPolicy.SetIv(iv, ivLen);
    if (iv != nullptr) {
        delete[] iv;
        iv = nullptr;
    }
    for (uint32_t user = 0; user < userNum; ++user) {
        AuthUserInfo perminfo = {
            .authAccount = GenerateRandStr(authAccountLen),
            .authPerm = static_cast<DLPFileAccess>(authPerm),
            .permExpiryTime = curTime + deltaTime,
            .authAccountType = OHOS::Security::DlpPermission::DlpAccountType::DOMAIN_ACCOUNT
        };
        encPolicy.authUsers_.emplace_back(perminfo);
    }
}

/**
 * @tc.name: DumpTest001
 * @tc.desc: dlp permission service dump test
 * @tc.type: FUNC
 * @tc.require:AR000HGIH9
 */
HWTEST_F(DlpPermissionServiceTest, DumpTest001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DumpTest001");
    int fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    EXPECT_EQ(ERR_INVALID_VALUE, dlpPermissionService_->Dump(fd, args));

    fd = 1;  // 1: std output

    // hidumper
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper -d
    args.emplace_back(Str8ToStr16("-d"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper with not exist param
    args.emplace_back(Str8ToStr16("-n"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper -d with observer null
    dlpPermissionService_->appStateObserver_ = nullptr;
    args.emplace_back(Str8ToStr16("-d"));
    EXPECT_EQ(ERR_INVALID_VALUE, dlpPermissionService_->Dump(fd, args));
}

class DlpSandboxChangeCallbackTest : public DlpSandboxChangeCallbackStub {
public:
    DlpSandboxChangeCallbackTest() = default;
    virtual ~DlpSandboxChangeCallbackTest() = default;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) override;
};

void DlpSandboxChangeCallbackTest::DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) {}

/**
 * @tc.name:DlpSandboxChangeCallbackDeathRecipient001
 * @tc.desc: DlpSandboxChangeCallbackDeathRecipient test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, DlpSandboxChangeCallbackDeathRecipient001, TestSize.Level1)
{
    auto recipient = std::make_shared<DlpSandboxChangeCallbackDeathRecipient>();
    ASSERT_NE(nullptr, recipient);

    recipient->OnRemoteDied(nullptr); // remote is nullptr

    // backup
    sptr<IRemoteObject> callback;
    wptr<IRemoteObject> remote = new (std::nothrow) DlpSandboxChangeCallbackTest();
    callback = remote.promote();
    dlpPermissionService_->RegisterDlpSandboxChangeCallback(callback);
    ASSERT_EQ(static_cast<uint32_t>(1), DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.size());
    recipient->OnRemoteDied(remote); // remote is not nullptr
    ASSERT_EQ(static_cast<uint32_t>(0), DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.size());
    bool result;
    int32_t res = dlpPermissionService_->UnRegisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
    recipient->OnRemoteDied(remote);
}

class TestOpenDlpFileCallback : public OpenDlpFileCallbackStub {
public:
    TestOpenDlpFileCallback() {}
    ~TestOpenDlpFileCallback() {}

    void OnOpenDlpFile(OpenDlpFileCallbackInfo& result) override
    {
        called_ = true;
    }
    bool called_ = false;
};

/**
 * @tc.name: OpenDlpFileCallbackDeathRecipient001
 * @tc.desc: OpenDlpFileCallbackDeathRecipient test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, OpenDlpFileCallbackDeathRecipient001, TestSize.Level1)
{
    auto recipient = std::make_shared<OpenDlpFileCallbackDeathRecipient>();
    ASSERT_NE(nullptr, recipient);

    recipient->OnRemoteDied(nullptr); // remote is nullptr

    // backup
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    wptr<IRemoteObject> remote = new (std::nothrow) TestOpenDlpFileCallback();
    sptr<IRemoteObject> callback = remote.promote();
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback);
    EXPECT_EQ(DLP_OK, res);
    EXPECT_EQ(static_cast<uint32_t>(1), OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.size());
    recipient->OnRemoteDied(remote); // remote is not nullptr
    EXPECT_EQ(static_cast<uint32_t>(0), OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.size());
    res = dlpPermissionService_->UnRegisterOpenDlpFileCallback(callback);
    EXPECT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
    recipient->OnRemoteDied(remote);
}

/**
 * @tc.name:FileOperator001
 * @tc.desc: FileOperator test
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionServiceTest, FileOperator001, TestSize.Level1)
{
    std::shared_ptr<FileOperator> fileOperator_ = std::make_shared<FileOperator>();
    bool result = fileOperator_->IsExistFile("");
    ASSERT_TRUE(!result);
    std::string content = "test";
    result = fileOperator_->IsExistDir("");
    ASSERT_TRUE(!result);
    int32_t res = fileOperator_->InputFileByPathAndContent(TEST_URI, content);
    ASSERT_EQ(DLP_RETENTION_COMMON_FILE_OPEN_FAILED, res);
    res = fileOperator_->GetFileContentByPath(TEST_URI, content);
    ASSERT_EQ(DLP_RETENTION_FILE_FIND_FILE_ERROR, res);
};

/**
 * @tc.name:SandboxJsonManager001
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager001, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 123456, "test.bundlName", 100);
    int32_t res = sandboxJsonManager_->AddSandboxInfo(1, 123456, "test.bundlName", 100);
    ASSERT_EQ(DLP_INSERT_FILE_ERROR, res);
    std::set<std::string> docUriSet;
    docUriSet.emplace("testUri");
    RetentionInfo info;
    info.bundleName = "";
    info.tokenId = 0;
    res = sandboxJsonManager_->UpdateRetentionState(docUriSet, info, false);
    ASSERT_EQ(DLP_RETENTION_UPDATE_ERROR, res);
}

/**
 * @tc.name:CallbackManager001
 * @tc.desc: DlpSandboxChangeCallbackManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, CallbackManager001, TestSize.Level1)
{
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpSandboxChangeCallbackManager::GetInstance().AddCallback(0, nullptr));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(nullptr));
    bool result;
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(0, result));
    sptr<IRemoteObject> callback;
    wptr<IRemoteObject> remote = new (std::nothrow) DlpSandboxChangeCallbackTest();
    callback = remote.promote();
    dlpPermissionService_->RegisterDlpSandboxChangeCallback(callback);
    for (int i = 10000; i < 11024; i++) {
        DlpSandboxChangeCallbackManager::GetInstance().AddCallback(i, callback);
    }
    ASSERT_EQ(
        DLP_SERVICE_ERROR_VALUE_INVALID, DlpSandboxChangeCallbackManager::GetInstance().AddCallback(11024, callback));
    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.pid = 1;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    dlpSandboxInfo.pid = 10010;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
}

/**
 * @tc.name:SandboxJsonManager002
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager002, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->FromJson(NULL);
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));
    int32_t uid = getuid();
    setuid(20010031);
    ASSERT_TRUE(sandboxJsonManager_->HasRetentionSandboxInfo("testbundle"));
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle1", 10000);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));

    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(8888));

    RetentionInfo info;
    info.tokenId = 827878;
    std::set<std::string> docUriSet;
    ASSERT_TRUE(!sandboxJsonManager_->UpdateDocUriSetByDifference(info, docUriSet));
    docUriSet.insert("testUri");
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, true);
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(827878));
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, false);
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->DelSandboxInfo(827878));
    setuid(uid);
}

/**
 * @tc.name:SandboxJsonManager003
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager003, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle1", 10000);
    int32_t uid = getuid();
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", 2));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", 1));
    setuid(uid);
}

/**
 * @tc.name:RetentionFileManager001
 * @tc.desc: RetentionFileManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, RetentionFileManager001, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    int32_t uid = getuid();
    setuid(10031);
    ASSERT_TRUE(!RetentionFileManager::GetInstance().HasRetentionSandboxInfo("testbundle1"));
    setuid(20010031);
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().AddSandboxInfo(1, 827878, "testbundle", 100));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, RetentionFileManager::GetInstance().DelSandboxInfo(8888));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_TRUE(RetentionFileManager::GetInstance().CanUninstall(8888));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        RetentionFileManager::GetInstance().RemoveRetentionState("testbundle1", -1));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().ClearUnreservedSandbox());
    RetentionFileManager::GetInstance().hasInit = false;
    std::vector<RetentionSandBoxInfo> vec;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().GetRetentionSandboxList("testbundle1", vec, false));

    setuid(uid);
}

/**
 * @tc.name:UninstallDlpSandbox001
 * @tc.desc:UninstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, UninstallDlpSandbox001, TestSize.Level1)
{
    SandboxInfo sandboxInfo;
    uint32_t dlpFileAccess = 5;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        "", static_cast<DLPFileAccess>(dlpFileAccess), 100, sandboxInfo, "testUri");
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->InstallDlpSandbox("testbundle",
        static_cast<DLPFileAccess>(dlpFileAccess), 100, sandboxInfo, "testUri"));
    dlpFileAccess = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->InstallDlpSandbox("testbundle",
        static_cast<DLPFileAccess>(dlpFileAccess), 100, sandboxInfo, "testUri"));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("", -1, -1));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("testbundle", -1, -1));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("testbundle", 1, -1));
}

/**
 * @tc.name:AppUninstallObserver001
 * @tc.desc:AppUninstallObserver test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, AppUninstallObserver001, TestSize.Level1)
{
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::shared_ptr<AppUninstallObserver> observer_ = std::make_shared<AppUninstallObserver>(subscribeInfo);
    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetBundle("testbundle1");
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle", 100);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    want.SetBundle("testbundle");
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
}

class DlpTestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.test");
    DlpTestRemoteObj() = default;
    virtual ~DlpTestRemoteObj() noexcept = default;
};

/**
 * @tc.name:SandboxJsonManager001
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionServiceTest, DlpPermissionStub001, TestSize.Level1)
{
    sptr<DlpPermissionStub> stub = new (std::nothrow) DlpPermissionService(0, 0);
    ASSERT_TRUE(!(stub == nullptr));

    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    ASSERT_TRUE(!(policyParcel == nullptr));

    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    int32_t res;
    MessageParcel data;
    MessageParcel reply;
    res = stub->GenerateDlpCertificateInner(data, reply);
    EXPECT_EQ(false, !res);

    res = data.WriteParcelable(policyParcel);
    EXPECT_EQ(false, !res);

    res = data.WriteRemoteObject(callback->AsObject());
    EXPECT_EQ(false, !res);

    res = stub->GenerateDlpCertificateInner(data, reply);
    EXPECT_EQ(false, !res);

    sptr<IDlpPermissionCallback> callback2 = nullptr;
    res = stub->GenerateDlpCertificate(policyParcel, callback2);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);

    sptr<IDlpPermissionCallback> callback3 = iface_cast<IDlpPermissionCallback>(callback->AsObject());
    res = stub->GenerateDlpCertificate(policyParcel, callback3);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
}

/**
 * @tc.name: VisitRecordJsonManager001
 * @tc.desc: VisitRecordJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38MU
 */
HWTEST_F(DlpPermissionServiceTest, VisitRecordJsonManager001, TestSize.Level1)
{
    std::shared_ptr<VisitRecordJsonManager> visitRecordJsonManager_ = std::make_shared<VisitRecordJsonManager>();
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t res = visitRecordJsonManager_->GetVisitRecordList("test.bundleName", 100, infoVec);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, res);
    res = visitRecordJsonManager_->AddVisitRecord("test.bundleName", 100, "testuri");
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->AddVisitRecord("test.bundleName", 100, "testuri");
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->AddVisitRecord("test.bundleName", 100, "testur");
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->AddVisitRecord("test.bundleName", 1001, "testuri");
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->AddVisitRecord("test.bundleName1", 100, "testuri");
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->GetVisitRecordList("test.bundleName", 100, infoVec);
    ASSERT_EQ(DLP_OK, res);
    res = visitRecordJsonManager_->GetVisitRecordList("test.bundleName1", 1001, infoVec);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, res);
    for (int32_t i = 1; i <= 1024; i++) {
        res = visitRecordJsonManager_->AddVisitRecord("test.bundleName1", 100 + i, "testuri");
    }
    ASSERT_EQ(DLP_JSON_UPDATE_ERROR, res);
    res = visitRecordJsonManager_->GetVisitRecordList("test.bundleName1", 2000, infoVec);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, res);
}

/**
 * @tc.name: VisitRecordJsonManager002
 * @tc.desc: VisitRecordJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38MU
 */
HWTEST_F(DlpPermissionServiceTest, VisitRecordJsonManager002, TestSize.Level1)
{
    std::shared_ptr<VisitRecordJsonManager> visitRecordJsonManager_ = std::make_shared<VisitRecordJsonManager>();
    std::string jsonStr = "{\"test\":[]}";
    Json callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"\",\"docUri\":\"file://media/file/12\",\"userId\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"\",\"userId\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr =
        "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/12\",\"userId\":-1}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100,\"timestamp\":-1}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100,\"timestamp\":1686844687}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 1);
}

/**
 * @tc.name: VisitRecordJsonManager003
 * @tc.desc: VisitRecordJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38MU
 */
HWTEST_F(DlpPermissionServiceTest, VisitRecordJsonManager003, TestSize.Level1)
{
    std::shared_ptr<VisitRecordJsonManager> visitRecordJsonManager_ = std::make_shared<VisitRecordJsonManager>();
    visitRecordJsonManager_->FromJson(NULL);
    std::string jsonStr = "{\"recordList\":[{\"bundleName1\":\"\"}]}";
    Json callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":1}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri1\":\"\",\"userId\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":1,\"userId\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"\",\"userId1\":100}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"\",\"userId\":\"100\"}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100,\"timestamp1\":1686844687}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100,\"timestamp\":\"1686844687\"}]}";
    callbackInfoJson = Json::parse(jsonStr, nullptr, false);
    visitRecordJsonManager_->FromJson(callbackInfoJson);
    visitRecordJsonManager_->infoList_.clear();
    ASSERT_EQ("", visitRecordJsonManager_->ToString());
}
/**
 * @tc.name: VisitRecordFileManager001
 * @tc.desc: VisitRecordFileManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38MU
 */
HWTEST_F(DlpPermissionServiceTest, VisitRecordFileManager001, TestSize.Level1)
{
    std::shared_ptr<VisitRecordFileManager> visitRecordFileManager = std::make_shared<VisitRecordFileManager>();
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t res = visitRecordFileManager->GetVisitRecordList("test.bundleName", 100, infoVec);
    ASSERT_EQ(DLP_OK, res);
    visitRecordFileManager->hasInit = true;
    ASSERT_EQ(true, visitRecordFileManager->Init());
    visitRecordFileManager->hasInit = false;
    ASSERT_EQ(true, visitRecordFileManager->Init());
    ASSERT_EQ(DLP_OK, visitRecordFileManager->UpdateFile(DLP_FILE_NO_NEED_UPDATE));
    ASSERT_EQ(DLP_JSON_UPDATE_ERROR, visitRecordFileManager->UpdateFile(DLP_JSON_UPDATE_ERROR));
    visitRecordFileManager->hasInit = false;
    ASSERT_EQ(DLP_OK, visitRecordFileManager->AddVisitRecord("test.bundleName", 100, "testuri"));
    visitRecordFileManager->hasInit = false;
    res = visitRecordFileManager->GetVisitRecordList("test.bundleName", 100, infoVec);
    ASSERT_EQ(DLP_OK, res);
}

/**
 * @tc.name: GetLocalAccountName001
 * @tc.desc: GetLocalAccountName test
 * @tc.type: FUNC
 * @tc.require:SR000I38MU
 */
HWTEST_F(DlpPermissionServiceTest, GetLocalAccountName001, TestSize.Level1)
{
    char* account = nullptr;
    uint32_t userId = 0;
    ASSERT_EQ(0, GetLocalAccountName(&account, userId));
    ASSERT_EQ(-1, GetLocalAccountName(nullptr, userId));
}

/**
 * @tc.name: OnStart001
 * @tc.desc: OnStart test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, OnStart001, TestSize.Level1)
{
    auto state = dlpPermissionService_->state_;
    dlpPermissionService_->state_ = ServiceRunningState::STATE_RUNNING;
    dlpPermissionService_->OnStart();
    dlpPermissionService_->state_ = state;
    ASSERT_EQ(true, dlpPermissionService_->RegisterAppStateObserver());
}

/**
 * @tc.name: ParseDlpCertificate001
 * @tc.desc: ParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, ParseDlpCertificate001, TestSize.Level1)
{
    std::vector<uint8_t> cert;
    uint32_t flag = 0;
    sptr<IDlpPermissionCallback> callback = nullptr;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->ParseDlpCertificate(cert, flag, callback));
}

/**
 * @tc.name: InsertDlpSandboxInfo001
 * @tc.desc: InsertDlpSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InsertDlpSandboxInfo001, TestSize.Level1)
{
    auto appStateObserver = dlpPermissionService_->appStateObserver_;
    DlpSandboxInfo sandboxInfo;
    dlpPermissionService_->InsertDlpSandboxInfo(sandboxInfo);
    std::string bundleName;
    int32_t appIndex = 111;
    int32_t userId = 111;
    ASSERT_TRUE(0 == dlpPermissionService_->DeleteDlpSandboxInfo(bundleName, appIndex, userId));
    dlpPermissionService_->appStateObserver_ = appStateObserver;
}

/**
 * @tc.name: GenerateDlpCertificate001
 * @tc.desc: GenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GenerateDlpCertificate001, TestSize.Level1)
{
    DLP_LOG_ERROR(LABEL, "GenerateDlpCertificate001");
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    DLP_LOG_ERROR(LABEL, "GenerateDlpCertificate001 1");
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    PermissionPolicy policy;
    policy.ownerAccount_ = "testAccount";
    policy.ownerAccountId_ = "testAccountId";
    policy.ownerAccountType_ = OHOS::Security::DlpPermission::DlpAccountType::CLOUD_ACCOUNT;

    AuthUserInfo user;
    NewUserSample(user);
    policy.authUsers_.emplace_back(user);
    policyParcel->policyParams_ = policy;
    res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);

    GeneratePolicy(policy, ACCOUNT_LENGTH, AESKEY_LEN, AESKEY_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM,
        DELTA_EXPIRY_TIME);
    policyParcel->policyParams_ = policy;
    res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    ASSERT_EQ(DLP_OK, res);

    delete callback;
    callback = nullptr;
    delete policyParcel;
    policyParcel = nullptr;
}

/**
 * @tc.name: SerializeEncPolicyData001
 * @tc.desc: SerializeEncPolicyData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SerializeEncPolicyData001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "SerializeEncPolicyData001");
    uint8_t* encPolicy = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(POLICY_CIPHER.c_str()));
    const char* exInfo = "DlpRestorePolicyTest_NormalInput_ExtraInfo";
    EncAndDecOptions encAndDecOptions = {
        .opt = ALLOW_RECEIVER_DECRYPT_WITHOUT_USE_CLOUD,
        .extraInfo = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(exInfo)),
        .extraInfoLen = strlen(exInfo)
    };
    DLP_EncPolicyData encPolicyData = {
        .dataLen = 0
    };
    nlohmann::json encDataJson;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.dataLen = DLP_MAX_CERT_SIZE + 1;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.dataLen = POLICY_CIPHER.size();
    DLP_LOG_INFO(LABEL, "SerializeEncPolicyData001 encData.options.extraInfoLen %{public}d",
        encAndDecOptions.extraInfoLen);
    encPolicyData.options = encAndDecOptions;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.data = encPolicy;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_OK, res);
    nlohmann::json decDataJson = encDataJson;
    encAndDecOptions.extraInfoLen = 0;
    encPolicyData.options = encAndDecOptions;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    DLP_EncPolicyData decPolicyData;
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, true);
    ASSERT_EQ(DLP_OK, res);
    AccountType tempType;
    encDataJson.at(ENC_ACCOUNT_TYPE).get_to(tempType);
    decDataJson[ENC_ACCOUNT_TYPE] = "test";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, true);
    ASSERT_EQ(DLP_OK, res);
    decDataJson.erase(ENC_ACCOUNT_TYPE);
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, true);
    ASSERT_EQ(DLP_OK, res);
    decDataJson[ENC_ACCOUNT_TYPE] = tempType;
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, true);
    ASSERT_EQ(DLP_OK, res);
}