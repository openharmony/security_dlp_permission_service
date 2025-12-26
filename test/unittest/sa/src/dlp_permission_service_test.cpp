/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <openssl/rand.h>
#include <string>
#include "accesstoken_kit.h"
#include "account_adapt.h"
#include "app_uninstall_observer.h"
#include "cert_parcel.h"
#define private public
#include "dlp_sandbox_change_callback_manager.h"
#include "open_dlp_file_callback_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_sandbox_change_callback_proxy.h"
#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "file_operator.h"
#include "ipc_skeleton.h"
#include "open_dlp_file_callback_proxy.h"
#include "open_dlp_file_callback_stub.h"
#include "open_dlp_file_callback_death_recipient.h"
#include "permission_policy.h"
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
static const int32_t INCORRECT_UID = 777;
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
static const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
static const std::string PERMISSION_APP = "com.ohos.permissionmanager";
const uint32_t ACCOUNT_LENGTH = 20;
const uint32_t USER_NUM = 1;
const int AUTH_PERM = 1;
const int64_t DELTA_EXPIRY_TIME = 200;
const uint64_t EXPIRY_TEN_MINUTE = 60 * 10;
const uint32_t AESKEY_LEN = 32;
const uint32_t HMACKEY_LEN = 32;
const std::string ENC_ACCOUNT_TYPE = "accountType";
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string EXTRA_INFO_LEN = "extraInfoLen";
const std::string EXTRA_INFO = "extraInfo";
const std::string ENC_POLICY = "encPolicy";
static int32_t g_userId = 100;
static const uint8_t ARRAY_CHAR_SIZE = 62;
static const char CHAR_ARRAY[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

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

uint64_t GetCurrentTimeSec(void)
{
    return static_cast<uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

void NewUserSample(AuthUserInfo& user)
{
    user.authAccount = "allowAccountA";
    user.authPerm = DLPFileAccess::FULL_CONTROL;
    user.permExpiryTime = GetCurrentTimeSec() + EXPIRY_TEN_MINUTE;
    user.authAccountType = OHOS::Security::DlpPermission::DlpAccountType::CLOUD_ACCOUNT;
}

static uint8_t GetRandNum()
{
    uint8_t rand;
    RAND_bytes(reinterpret_cast<unsigned char *>(&rand), sizeof(rand));
    return rand;
}

uint8_t* GenerateRandArray(uint32_t len)
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
        str[i] = GetRandNum() % 255; // uint8_t range 0 ~ 255
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
    uint32_t hmacKeyLen;
};

void GeneratePolicy(PermissionPolicy& encPolicy, GeneratePolicyParam param, DlpAccountType accountType)
{
    uint64_t curTime = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    GenerateRandStr(param.ownerAccountLen, encPolicy.ownerAccount_);
    encPolicy.ownerAccountId_ = encPolicy.ownerAccount_;
    encPolicy.ownerAccountType_ = accountType;
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
    uint8_t* hmacKey = GenerateRandArray(param.hmacKeyLen);
    encPolicy.SetHmacKey(hmacKey, param.hmacKeyLen);
    if (hmacKey != nullptr) {
        delete[] hmacKey;
        hmacKey = nullptr;
    }

    for (uint32_t user = 0; user < param.userNum; ++user) {
        std::string accountName;
        GenerateRandStr(param.authAccountLen, accountName);
        AuthUserInfo perminfo = {.authAccount = accountName,
            .authPerm = static_cast<DLPFileAccess>(param.authPerm),
            .permExpiryTime = curTime + param.deltaTime,
            .authAccountType = OHOS::Security::DlpPermission::DlpAccountType::DOMAIN_ACCOUNT
        };
        encPolicy.authUsers_.emplace_back(perminfo);
    }
}
}

namespace OHOS {
namespace AccountSA {
ErrCode OsAccountManager::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    id = DEFAULT_USERID;

    if (uid == INCORRECT_UID) {
        return 1;
    }
    return DLP_OK;
}
}
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
    dlpPermissionService_ = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    ASSERT_NE(nullptr, dlpPermissionService_);
    dlpPermissionService_->appStateObserver_ = new (std::nothrow) AppStateObserver();
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_ != nullptr);
    GetUserIdByForegroundAccount(&g_userId);
}

void DlpPermissionServiceTest::TearDown()
{
    if (dlpPermissionService_ != nullptr) {
        dlpPermissionService_->appStateObserver_ = nullptr;
    }
    dlpPermissionService_ = nullptr;
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
    DlpPermissionServiceTest::permType = -1;
    dlpPermissionService_->RegisterDlpSandboxChangeCallback(callback);
    res = dlpPermissionService_->UnRegisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, res);
    DlpPermissionServiceTest::permType = 0;
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
    DlpPermissionServiceTest::isSandbox = false;
    res = dlpPermissionService_->UnRegisterOpenDlpFileCallback(callback);
    DlpPermissionServiceTest::isSandbox = true;
    EXPECT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
    recipient->OnRemoteDied(remote);

    res = dlpPermissionService_->UnRegisterOpenDlpFileCallback(callback);
    ASSERT_EQ(DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR, res);

    DlpPermissionServiceTest::isCheckSandbox = false;
    res = dlpPermissionService_->UnRegisterOpenDlpFileCallback(callback);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
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
    RetentionInfo retentionInfo = {
        .appIndex = 1,
        .tokenId = 123456,
        .bundleName = "test.bundlName",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 100
    };
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    int32_t res = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
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
    RetentionInfo retentionInfo = {
        .appIndex = 1,
        .tokenId = 827878,
        .bundleName = "testbundle",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = g_userId
    };
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));
    int32_t uid = getuid();
    setuid(20010031);
    ASSERT_TRUE(sandboxJsonManager_->HasRetentionSandboxInfo("testbundle"));
    retentionInfo.bundleName = "testbundle1";
    retentionInfo.tokenId = 827818;
    retentionInfo.userId = 10000;
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));

    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(8888));

    RetentionInfo info;
    info.tokenId = 827878;
    std::set<std::string> docUriSet;
    ASSERT_TRUE(!sandboxJsonManager_->ClearDocUriSet(info, docUriSet));
    docUriSet.insert("testUri");
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, true);
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(827878));
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, false);
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->DelSandboxInfo(827878));
    sandboxJsonManager_->SetInitStatus(827878);
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
    RetentionInfo retentionInfo = {
        .appIndex = 1,
        .tokenId = 827818,
        .bundleName = "testbundle1",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 10000
    };
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    int32_t uid = getuid();
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    retentionInfo.bundleName = "testbundle";
    retentionInfo.tokenId = 827878;
    retentionInfo.userId = g_userId;
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", 2));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", 1));
    setuid(uid);
}

/**
 * @tc.name:SandboxJsonManager004
 * @tc.desc: GetBundleNameSetByUserId test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager004, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    std::set<std::string> keySet;
    int res = sandboxJsonManager_->GetBundleNameSetByUserId(100, keySet);
    ASSERT_EQ(DLP_OK, res);
    SandboxInfo sandboxInfo;
    res = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri1111");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    res = RetentionFileManager::GetInstance().GetBundleNameSetByUserId(100, keySet);
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    res = RetentionFileManager::GetInstance().RemoveRetentionInfoByUserId(100, keySet);
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    res = RetentionFileManager::GetInstance().RemoveRetentionInfoByUserId(100, keySet);
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, res);
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
    RetentionInfo retentionInfo = {
        .appIndex = 1,
        .tokenId = 827878,
        .bundleName = "testbundle",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 100
    };
    sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    int32_t uid = getuid();
    setuid(10031);
    ASSERT_TRUE(!RetentionFileManager::GetInstance().HasRetentionSandboxInfo("testbundle1"));
    setuid(20010031);
    RetentionFileManager::GetInstance().hasInit_ = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().AddSandboxInfo(retentionInfo));
    RetentionFileManager::GetInstance().hasInit_ = false;
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, RetentionFileManager::GetInstance().DelSandboxInfo(8888));
    RetentionFileManager::GetInstance().hasInit_ = false;
    ASSERT_TRUE(RetentionFileManager::GetInstance().CanUninstall(8888));
    RetentionFileManager::GetInstance().SetInitStatus(8888);
    RetentionFileManager::GetInstance().hasInit_ = false;
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        RetentionFileManager::GetInstance().RemoveRetentionState("testbundle1", -1));
    RetentionFileManager::GetInstance().hasInit_ = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().ClearUnreservedSandbox());
    RetentionFileManager::GetInstance().hasInit_ = false;
    std::vector<RetentionSandBoxInfo> vec;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().GetRetentionSandboxList("testbundle1", vec, false));

    setuid(uid);
}

/**
 * @tc.name:InstallDlpSandbox001
 * @tc.desc:InstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox001");
    SandboxInfo sandboxInfo;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    int32_t editAppIndex = sandboxInfo.appIndex;
    std::set<std::string> docUriSet;
    docUriSet.insert("testUri");
    RetentionInfo info;
    info.appIndex = editAppIndex;
    info.tokenId = sandboxInfo.tokenId;
    info.bundleName = DLP_MANAGER_APP;
    info.userId = DEFAULT_USERID;
    RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
    ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    editAppIndex = sandboxInfo.appIndex;
    dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri1");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    editAppIndex = sandboxInfo.appIndex;
    info.appIndex = editAppIndex;
    info.tokenId = sandboxInfo.tokenId;
    RetentionFileManager::GetInstance().UpdateSandboxInfo(docUriSet, info, true);
    ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::READ_ONLY, DEFAULT_USERID, sandboxInfo, "testUri");
    ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
}

/**
 * @tc.name:InstallDlpSandbox002
 * @tc.desc:InstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InstallDlpSandbox002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "InstallDlpSandbox002");
    SandboxInfo sandboxInfo;
    DlpPermissionServiceTest::permType = -1;
    int32_t ret = dlpPermissionService_->InstallDlpSandbox(
        DLP_MANAGER_APP, DLPFileAccess::CONTENT_EDIT, DEFAULT_USERID, sandboxInfo, "testUri");
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
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
 * @tc.name:UninstallDlpSandbox002
 * @tc.desc:UninstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, UninstallDlpSandbox002, TestSize.Level1)
{
    DlpPermissionServiceTest::permType = -1;
    int32_t ret = dlpPermissionService_->UninstallDlpSandbox("", -1, -1);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
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
    RetentionInfo retentionInfo = {
        .appIndex = 1,
        .tokenId = 827818,
        .bundleName = "testbundle",
        .dlpFileAccess = DLPFileAccess::CONTENT_EDIT,
        .userId = 100
    };
    int32_t ret = sandboxJsonManager_->AddSandboxInfo(retentionInfo);
    ASSERT_EQ(DLP_OK, ret);
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
    sptr<DlpPermissionServiceStub> stub = new (std::nothrow) DlpPermissionService(0, 0);
    ASSERT_TRUE(!(stub == nullptr));

    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    ASSERT_TRUE(!(policyParcel == nullptr));

    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    int32_t res;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    res = stub->OnRemoteRequest(static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_GENERATE_DLP_CERTIFICATE),
        data, reply, option);
    EXPECT_EQ(false, !res);

    res = data.WriteParcelable(policyParcel);
    EXPECT_EQ(false, res);

    res = data.WriteRemoteObject(callback->AsObject());
    EXPECT_EQ(false, !res);

    res = stub->OnRemoteRequest(static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_GENERATE_DLP_CERTIFICATE),
        data, reply, option);
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
    int32_t res = visitRecordJsonManager_->GetVisitRecordList(DLP_MANAGER_APP, 100, infoVec);
    ASSERT_EQ(DLP_FILE_NO_NEED_UPDATE, res);
    res = visitRecordJsonManager_->AddVisitRecord(DLP_MANAGER_APP, 100, "testuri");
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }

    res = visitRecordJsonManager_->AddVisitRecord(DLP_MANAGER_APP, 100, "testuri");
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }
    res = visitRecordJsonManager_->AddVisitRecord(DLP_MANAGER_APP, 100, "testur");
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }
    res = visitRecordJsonManager_->AddVisitRecord(DLP_MANAGER_APP, 1001, "testuri", 0, 1001);
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }
    res = visitRecordJsonManager_->AddVisitRecord(PERMISSION_APP, 100, "testuri");
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }
    res = visitRecordJsonManager_->GetVisitRecordList(PERMISSION_APP, 1001, infoVec);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    for (int32_t i = 1; i <= 1024; i++) {
        res = visitRecordJsonManager_->AddVisitRecord(PERMISSION_APP, 100 + i, "testuri", 0, 100 + i);
    }
    if (res != DLP_JSON_UPDATE_ERROR) {
        ASSERT_NE(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_JSON_UPDATE_ERROR, res);
    }
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
    ASSERT_TRUE(visitRecordJsonManager_->infoList_.size() == 0);
    jsonStr = "{\"recordList\":[{\"bundleName\":\"com.example.ohnotes\",\"docUri\":\"file://media/file/"
        "12\",\"userId\":100,\"timestamp\":1686844687,\"originalTokenId\":100}]}";
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
    int32_t res = visitRecordFileManager->GetVisitRecordList(DLP_MANAGER_APP, 100, infoVec);
    ASSERT_EQ(DLP_OK, res);
    visitRecordFileManager->hasInit_ = true;
    ASSERT_EQ(true, visitRecordFileManager->Init());
    visitRecordFileManager->hasInit_ = false;
    ASSERT_EQ(true, visitRecordFileManager->Init());
    ASSERT_EQ(DLP_OK, visitRecordFileManager->UpdateFile(DLP_FILE_NO_NEED_UPDATE));
    ASSERT_EQ(DLP_JSON_UPDATE_ERROR, visitRecordFileManager->UpdateFile(DLP_JSON_UPDATE_ERROR));
    visitRecordFileManager->hasInit_ = false;
    res = visitRecordFileManager->AddVisitRecord(DLP_MANAGER_APP, 100, "testuri");
    if (res != DLP_OK) {
        ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    } else {
        ASSERT_EQ(DLP_OK, res);
    }
    visitRecordFileManager->hasInit_ = false;
    res = visitRecordFileManager->GetVisitRecordList(DLP_MANAGER_APP, 100, infoVec);
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
    ASSERT_EQ(-1, GetLocalAccountName(nullptr, g_userId));
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
    dlpPermissionService_->OnStop();
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
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    sptr<IDlpPermissionCallback> callback = nullptr;
    int32_t ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, "", true);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);
    ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, "", true);
    ASSERT_EQ(DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED, ret);
}

/**
 * @tc.name: ParseDlpCertificate002
 * @tc.desc: ParseDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, ParseDlpCertificate002, TestSize.Level1)
{
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    sptr<IDlpPermissionCallback> callback = nullptr;
    DlpPermissionServiceTest::permType = 1;
    int32_t ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, "", true);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DlpPermissionServiceTest::permType = 2;
    ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, "", true);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);

    DlpPermissionServiceTest::permType = -1;
    ret = dlpPermissionService_->ParseDlpCertificate(certParcel, callback, "", true);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, ret);
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
    dlpPermissionService_->InsertDlpSandboxInfo(sandboxInfo, false, true);
    std::string bundleName;
    int32_t appIndex = 111;
    int32_t userId = 111;
    ASSERT_TRUE(0 == dlpPermissionService_->DeleteDlpSandboxInfo(bundleName, appIndex, userId));
    dlpPermissionService_->appStateObserver_ = appStateObserver;

    dlpPermissionService_->InsertDlpSandboxInfo(sandboxInfo, true, false);
}

/**
 * @tc.name: InsertDlpSandboxInfo002
 * @tc.desc: InsertDlpSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, InsertDlpSandboxInfo002, TestSize.Level1)
{
    std::string bundleName;
    int32_t appIndex = 111;
    int32_t userId = 111;
    ASSERT_TRUE(0 == dlpPermissionService_->DeleteDlpSandboxInfo(bundleName, appIndex, userId));
}

/**
 * @tc.name: GenerateDlpCertificate001
 * @tc.desc: GenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GenerateDlpCertificate001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpCertificate001");
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    int32_t res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    DLP_LOG_DEBUG(LABEL, "GenerateDlpCertificate001 1");
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
}

/**
 * @tc.name: GenerateDlpCertificate002
 * @tc.desc: GenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GenerateDlpCertificate002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpCertificate002");
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    PermissionPolicy policy;
    GeneratePolicyParam param = {ACCOUNT_LENGTH, AESKEY_LEN, AESKEY_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM,
        DELTA_EXPIRY_TIME, HMACKEY_LEN};
    GeneratePolicy(policy, param, OHOS::Security::DlpPermission::DlpAccountType::DOMAIN_ACCOUNT);
    policyParcel->policyParams_.CopyPermissionPolicy(policy);
    int32_t res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    ASSERT_EQ(DLP_PARSE_ERROR_ACCOUNT_INVALID, res);
}

/**
 * @tc.name: GenerateDlpCertificate003
 * @tc.desc: GenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GenerateDlpCertificate003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpCertificate003");
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    PermissionPolicy policy;
    GeneratePolicyParam param = {ACCOUNT_LENGTH, AESKEY_LEN, AESKEY_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM,
        DELTA_EXPIRY_TIME, HMACKEY_LEN};
    GeneratePolicy(policy, param, OHOS::Security::DlpPermission::DlpAccountType::CLOUD_ACCOUNT);
    policyParcel->policyParams_.CopyPermissionPolicy(policy);
    int32_t res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    ASSERT_EQ(DLP_OK, res);
}

/**
 * @tc.name: GenerateDlpCertificate004
 * @tc.desc: GenerateDlpCertificate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GenerateDlpCertificate004, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GenerateDlpCertificate004");
    sptr<DlpPolicyParcel> policyParcel = new (std::nothrow) DlpPolicyParcel();
    std::shared_ptr<GenerateDlpCertificateCallback> callback1 =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> callback = new (std::nothrow) DlpPermissionAsyncStub(callback1);

    PermissionPolicy policy;
    GeneratePolicyParam param = {ACCOUNT_LENGTH, AESKEY_LEN, AESKEY_LEN, USER_NUM, ACCOUNT_LENGTH, AUTH_PERM,
        DELTA_EXPIRY_TIME, HMACKEY_LEN};
    GeneratePolicy(policy, param, OHOS::Security::DlpPermission::DlpAccountType::CLOUD_ACCOUNT);
    policyParcel->policyParams_.CopyPermissionPolicy(policy);
    DlpPermissionServiceTest::permType = 1;
    int32_t res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_OK, res);

    DlpPermissionServiceTest::permType = 2;
    res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_OK, res);

    DlpPermissionServiceTest::permType = -1;
    res = dlpPermissionService_->GenerateDlpCertificate(policyParcel, callback);
    DlpPermissionServiceTest::permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_PERMISSION_DENY, res);
}

/**
 * @tc.name: SerializeEncPolicyData001
 * @tc.desc: SerializeEncPolicyData test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SerializeEncPolicyData001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SerializeEncPolicyData001");
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
    unordered_json encDataJson;
    int32_t res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.dataLen = DLP_MAX_CERT_SIZE + 1;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.dataLen = POLICY_CIPHER.size();
    DLP_LOG_DEBUG(LABEL, "SerializeEncPolicyData001 encData.options.extraInfoLen %{public}d",
        encAndDecOptions.extraInfoLen);
    encPolicyData.options = encAndDecOptions;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
    encPolicyData.data = encPolicy;
    res = DlpPermissionSerializer::GetInstance().SerializeEncPolicyData(encPolicyData, encDataJson);
    ASSERT_EQ(DLP_OK, res);
    unordered_json decDataJson = encDataJson;
    encAndDecOptions.extraInfoLen = 0;
    encPolicyData.options = encAndDecOptions;
    DLP_EncPolicyData decPolicyData;
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, false);
    ASSERT_EQ(DLP_OK, res);
    AccountType tempType;
    ASSERT_NE(encDataJson.find(ENC_ACCOUNT_TYPE), encDataJson.end());
    ASSERT_EQ(encDataJson.at(ENC_ACCOUNT_TYPE).is_number(), true);
    encDataJson.at(ENC_ACCOUNT_TYPE).get_to(tempType);
    decDataJson[ENC_ACCOUNT_TYPE] = "test";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, false);
    ASSERT_EQ(DLP_OK, res);
    decDataJson.erase(ENC_ACCOUNT_TYPE);
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, false);
    ASSERT_EQ(DLP_OK, res);
    decDataJson[ENC_ACCOUNT_TYPE] = tempType;
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyData(decDataJson, decPolicyData, false);
    ASSERT_EQ(DLP_OK, res);
}

/**
 * @tc.name: UninstallDlpSandboxApp001
 * @tc.desc: UninstallDlpSandboxApp test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, UninstallDlpSandboxApp001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "UninstallDlpSandboxApp001");

    std::string bundleName;
    int32_t appIndex = 0;
    int32_t userId = 0;
    int32_t ret = dlpPermissionService_->UninstallDlpSandboxApp(bundleName, appIndex, userId);
    ASSERT_EQ(DLP_SERVICE_ERROR_UNINSTALL_SANDBOX_FAIL, ret);
}

/**
 * @tc.name: GetSandboxExternalAuthorization001
 * @tc.desc: GetSandboxExternalAuthorization test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetSandboxExternalAuthorization001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetSandboxExternalAuthorization001");

    int sandboxUid = -1;
    AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    int32_t ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    sandboxUid = 0;
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: GetSandboxExternalAuthorization002
 * @tc.desc: GetSandboxExternalAuthorization test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetSandboxExternalAuthorization002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetSandboxExternalAuthorization002");

    int sandboxUid = -1;
    AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    DlpPermissionServiceTest::permType = -1;
    int32_t ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    DlpPermissionServiceTest::permType = 0;
    EXPECT_NE(DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL, ret);
}

/**
 * @tc.name: GetConfigFileValue001
 * @tc.desc: GetConfigFileValue test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetConfigFileValue001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetConfigFileValue001");

    std::string cfgFile;
    std::vector<std::string> typeList;
    (void)dlpPermissionService_->GetConfigFileValue(cfgFile, typeList);
    EXPECT_EQ(typeList.size(), 0);
}

/**
 * @tc.name: RemoveRetentionInfo001
 * @tc.desc: RemoveRetentionInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, RemoveRetentionInfo001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "RemoveRetentionInfo001");

    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    RetentionInfo info;
    bool ret = dlpPermissionService_->RemoveRetentionInfo(retentionSandBoxInfoVec, info);
    ASSERT_EQ(true, ret);
}

/**
 * @tc.name: DeserializeEncPolicyDataByFirstVersion001
 * @tc.desc: DeserializeEncPolicyDataByFirstVersion test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, DeserializeEncPolicyDataByFirstVersion001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DeserializeEncPolicyDataByFirstVersion001");
    unordered_json encDataJson = {
        { ENC_DATA_LEN, 11 }
    };
    unordered_json encDataJson2;
    DLP_EncPolicyData encData;
    std::string ownerAccountId;
    int res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    encDataJson[ENC_DATA] = "1";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    encDataJson[EXTRA_INFO] = "1";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_OK);
    encDataJson2[ENC_POLICY] = "1";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    encDataJson2[ENC_ACCOUNT_TYPE] = 2;
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    encDataJson2[EXTRA_INFO] = "1";
    res = DlpPermissionSerializer::GetInstance().DeserializeEncPolicyDataByFirstVersion(encDataJson, encDataJson2,
        encData, ownerAccountId);
    ASSERT_EQ(res, DLP_OK);
}

/**
 * @tc.name: SandboxConfigOperate001
 * @tc.desc: SandboxConfigOperate test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SandboxConfigOperate001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SandboxConfigOperate001");
    std::string config;
    int32_t ret = dlpPermissionService_->SandboxConfigOperate(config, SandboxConfigOperationEnum::ADD);
    ASSERT_NE(DLP_OK, ret);
}

/**
 * @tc.name: SetReadFlag001
 * @tc.desc: SetReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetReadFlag001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetReadFlag001");
    uint32_t uid = 0;
    int32_t ret = dlpPermissionService_->SetReadFlag(uid);
    ASSERT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: QueryDlpFileAccess001
 * @tc.desc: QueryDlpFileAccess test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, QueryDlpFileAccess001, TestSize.Level1)
{
    DLPPermissionInfoParcel permInfoParcel;
    DlpPermissionServiceTest::isSandbox = false;
    int32_t res = dlpPermissionService_->QueryDlpFileAccess(permInfoParcel);
    DlpPermissionServiceTest::isSandbox = true;
    ASSERT_EQ(DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR, res);

    DlpPermissionServiceTest::isCheckSandbox = false;
    res = dlpPermissionService_->QueryDlpFileAccess(permInfoParcel);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: RegisterOpenDlpFileCallback001
 * @tc.desc: RegisterOpenDlpFileCallback test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, RegisterOpenDlpFileCallback001, TestSize.Level1)
{
    DlpPermissionServiceTest::isSandbox = true;
    int32_t res = dlpPermissionService_->RegisterOpenDlpFileCallback(nullptr);
    ASSERT_EQ(DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR, res);

    DlpPermissionServiceTest::isCheckSandbox = false;
    res = dlpPermissionService_->RegisterOpenDlpFileCallback(nullptr);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
}


/**
 * @tc.name: SetRetentionState001
 * @tc.desc: SetRetentionState test success
 * @tc.type: FUNC
 * @tc.require:issue：IAIFTY
 */
HWTEST_F(DlpPermissionServiceTest, SetRetentionState001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetRetentionState001");

    std::vector<std::string> docUriVec;
    docUriVec.push_back("hh");
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId;
    ASSERT_EQ(GetUserIdFromUid(INCORRECT_UID, &userId), -1);
    uid = uid == INCORRECT_UID ? uid + 1 : uid;
    GetUserIdFromUid(uid, &userId);
    userId = uid == INCORRECT_UID ? INCORRECT_UID : userId;
    DlpSandboxInfo appInfo;
    appInfo = {
        .uid = uid,
        .userId = userId,
        .appIndex = 0,
        .bundleName = "testbundle1",
        .hasRead = false
    };
    dlpPermissionService_->appStateObserver_->AddSandboxInfo(appInfo);
    int32_t ret = dlpPermissionService_->SetRetentionState(docUriVec);
    ASSERT_EQ(ret, DLP_OK);

    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec;
    RetentionSandBoxInfo retentionSandBoxInfo;
    retentionSandBoxInfo.appIndex_ = appInfo.appIndex;
    retentionSandBoxInfoVec.push_back(retentionSandBoxInfo);
    RetentionSandBoxInfo retentionSandBoxInfo1;
    retentionSandBoxInfo1.appIndex_ = appInfo.appIndex + 1;
    retentionSandBoxInfoVec.push_back(retentionSandBoxInfo1);

    RetentionInfo info;
    info.bundleName = appInfo.bundleName;
    bool res = dlpPermissionService_->RemoveRetentionInfo(retentionSandBoxInfoVec, info);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: SetRetentionState002
 * @tc.desc: SetRetentionState test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetRetentionState002, TestSize.Level1)
{
    std::vector<std::string> docUriVec;
    docUriVec.push_back("hh");
    DlpPermissionServiceTest::isSandbox = false;
    int32_t ret = dlpPermissionService_->SetRetentionState(docUriVec);
    DlpPermissionServiceTest::isSandbox = true;
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_API_ONLY_FOR_SANDBOX_ERROR);

    DlpPermissionServiceTest::isCheckSandbox = false;
    ret = dlpPermissionService_->SetRetentionState(docUriVec);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);

    docUriVec.clear();
    ret = dlpPermissionService_->SetRetentionState(docUriVec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: GetRetentionSandboxList001
 * @tc.desc: GetRetentionSandboxList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetRetentionSandboxList001, TestSize.Level1)
{
    std::vector<RetentionSandBoxInfo> vec;
    DlpPermissionServiceTest::isSandbox = true;
    int32_t ret = dlpPermissionService_->GetRetentionSandboxList("testbundle1", vec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR);

    DlpPermissionServiceTest::isCheckSandbox = false;
    ret = dlpPermissionService_->GetRetentionSandboxList("testbundle1", vec);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: GetDLPFileVisitRecord001
 * @tc.desc: GetDLPFileVisitRecord test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetDLPFileVisitRecord001, TestSize.Level1)
{
    std::vector<VisitedDLPFileInfo> infoVec;

    DlpPermissionServiceTest::isSandbox = true;
    int32_t ret = dlpPermissionService_->GetDLPFileVisitRecord(infoVec);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR);

    DlpPermissionServiceTest::isCheckSandbox = false;
    ret = dlpPermissionService_->GetDLPFileVisitRecord(infoVec);
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: CleanSandboxAppConfig001
 * @tc.desc: CleanSandboxAppConfig test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, CleanSandboxAppConfig001, TestSize.Level1)
{
    DlpPermissionServiceTest::isSandbox = true;
    int32_t ret = dlpPermissionService_->CleanSandboxAppConfig();
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_API_NOT_FOR_SANDBOX_ERROR);

    DlpPermissionServiceTest::isCheckSandbox = false;
    ret = dlpPermissionService_->CleanSandboxAppConfig();
    DlpPermissionServiceTest::isCheckSandbox = true;
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: SetDlpFeature001
 * @tc.desc: SetDlpFeature test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetDlpFeature001, TestSize.Level1)
{
    uint32_t dlpFeatureInfo = 0;
    bool statusSetInfo;
    int32_t ret = dlpPermissionService_->SetDlpFeature(dlpFeatureInfo, statusSetInfo);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/**
 * @tc.name: GetDlpSupportFileType
 * @tc.desc: GetDlpSupportFileType test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetDlpSupportFileType, TestSize.Level1)
{
    std::vector<std::string> supportFileType;
    int32_t ret = dlpPermissionService_->GetDlpSupportFileType(supportFileType);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: SetMDMPolicy
 * @tc.desc: SetMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetMDMPolicy, TestSize.Level1)
{
    std::vector<std::string> appIdList_1;
    int32_t ret = dlpPermissionService_->SetMDMPolicy(appIdList_1);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
    appIdList_1.push_back("a");
    ret = dlpPermissionService_->SetMDMPolicy(appIdList_1);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_PERMISSION_DENY);
}

/**
 * @tc.name: GetMDMPolicy
 * @tc.desc: GetMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetMDMPolicy, TestSize.Level1)
{
    std::vector<std::string> appIdList_1;
    int32_t ret = dlpPermissionService_->GetMDMPolicy(appIdList_1);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_PERMISSION_DENY);
}

/**
 * @tc.name: RemoveMDMPolicy
 * @tc.desc: RemoveMDMPolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, RemoveMDMPolicy, TestSize.Level1)
{
    int32_t ret = dlpPermissionService_->RemoveMDMPolicy();
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_PERMISSION_DENY);
}

/**
 * @tc.name: SetEnterprisePolicy
 * @tc.desc: SetEnterprisePolicy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetEnterprisePolicy, TestSize.Level1)
{
    std::string policy = "policy";
    int32_t ret = dlpPermissionService_->SetEnterprisePolicy(policy);
    ASSERT_TRUE(ret != DLP_CALLBACK_SA_WORK_ABNORMAL);
}

/**
 * @tc.name: CheckIfEnterpriseAccount
 * @tc.desc: CheckIfEnterpriseAccount test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, CheckIfEnterpriseAccount, TestSize.Level1)
{
    int32_t ret = dlpPermissionService_->CheckIfEnterpriseAccount();
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: IsDLPFeatureProvided
 * @tc.desc: IsDLPFeatureProvided test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, IsDLPFeatureProvided, TestSize.Level1)
{
    bool isDLPFeatureProvided = true;
    int32_t ret = dlpPermissionService_->IsDLPFeatureProvided(isDLPFeatureProvided);
    ASSERT_FALSE(isDLPFeatureProvided);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: SetNotOwnerAndReadOnce
 * @tc.desc: SetNotOwnerAndReadOnce test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetNotOwnerAndReadOnce, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetNotOwnerAndReadOnce");
    std::string uri = "";
    int32_t ret = dlpPermissionService_->SetNotOwnerAndReadOnce(uri, true);
    ASSERT_EQ(ret, DLP_SERVICE_ERROR_URI_EMPTY);
    uri = "uri";
    ret = dlpPermissionService_->SetNotOwnerAndReadOnce(uri, false);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: SetWaterMark001
 * @tc.desc: SetNotOwnerAndReadOnce test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetWaterMark001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetWaterMark001");
    const int32_t pid = 1234;
    int32_t ret = dlpPermissionService_->SetWaterMark(pid);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: GetWaterMark001
 * @tc.desc: GetWaterMark test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetWaterMark001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetWaterMark001");

    sptr<IDlpPermissionCallback> callback = nullptr;
    int32_t res = dlpPermissionService_->GetWaterMark(true, callback);
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
}

/**
 * @tc.name: GetWaterMark003
 * @tc.desc: GetWaterMark test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetWaterMark003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetWaterMark003");

    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    if (callback == nullptr) {
        return;
    }

    sptr<IDlpPermissionCallback> callback3 = iface_cast<IDlpPermissionCallback>(callback->AsObject());
    EXPECT_NE(DLP_OK, dlpPermissionService_->GetWaterMark(false, callback3));
}

/**
 * @tc.name: GetWaterMark002
 * @tc.desc: GetWaterMark test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetWaterMark002, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetWaterMark002");

    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    sptr<IDlpPermissionCallback> callback2 = iface_cast<IDlpPermissionCallback>(callback->AsObject());
    int32_t res = dlpPermissionService_->GetWaterMark(true, callback2);
    EXPECT_NE(DLP_OK, res);
}