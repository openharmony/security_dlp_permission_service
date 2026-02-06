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

#include "dlppermissionservicesnormal_fuzzer.h"

#include <iostream>
#include <fcntl.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"
#include "securec.h"
#include "token_setproc.h"
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
static const uint32_t BUFFER_LEN = 30;
static const uint32_t TWO = 2;
static const uint8_t FOUR = 4;
static const uint8_t BUFF_SIZE = 10;
} // namespace

namespace OHOS {
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;
static constexpr uint8_t STATUS_NUM = 2;
static const std::string CONFIGINGO = "configInfo";

static void TestGenerateCert()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_GENERATE_DLP_CERTIFICATE);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);

    MessageParcel datas1;
    if (!datas1.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service1->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service1->OnRemoteRequest(code, datas1, reply, option);

    DlpPolicyParcel parcel;
    MessageParcel datas2;
    if (!datas2.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    if (!datas2.WriteParcelable(&parcel)) {
        return;
    }
    auto service2 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service2->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service2->OnRemoteRequest(code, datas2, reply, option);
}

static void TestParseCert()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_PARSE_DLP_CERTIFICATE);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);

    MessageParcel datas1;
    if (!datas1.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    if (!datas1.WriteParcelable(certParcel)) {
        return;
    }
    auto service1 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service1->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service1->OnRemoteRequest(code, datas1, reply, option);

    MessageParcel datas2;
    if (!datas2.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    sptr<CertParcel> certParcel1= new (std::nothrow) CertParcel();
    if (!datas2.WriteParcelable(certParcel1)) {
        return;
    }
    std::shared_ptr<ParseDlpCertificateCallback> callback = std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (!datas2.WriteRemoteObject(asyncStub->AsObject())) {
        return;
    }
    auto service2 = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service2->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service2->OnRemoteRequest(code, datas2, reply, option);
}

static void TestInstallDlpSandbox()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_INSTALL_DLP_SANDBOX);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestGetSandboxExternalAuthorization()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_GET_SANDBOX_EXTERNAL_AUTHORIZATION);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestRegisterRegisterDlpSandboxChangeCallback()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_REGISTER_DLP_SANDBOX_CHANGE_CALLBACK);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestRegisterRegisterOpenDlpFileCallback()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_REGISTER_OPEN_DLP_FILE_CALLBACK);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestUnRegisterUnregisterOpenDlpFileCallback()
{
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_UN_REGISTER_OPEN_DLP_FILE_CALLBACK);
    MessageParcel reply;
    MessageOption option;
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestSetSandboxConfig(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    MessageParcel datas;
    datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_GET_SANDBOX_APP_CONFIG);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

static void TestSetSandboxAppConfig(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string configInfo = CONFIGINGO;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->SetSandboxAppConfig(configInfo);
}

static void TestUnRegisterDlpSandboxChangeCallback(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    bool flag = false;
    service->UnRegisterDlpSandboxChangeCallback(flag);
    flag = true;
    service->UnRegisterDlpSandboxChangeCallback(flag);
}

static void TestDump(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    std::vector<std::u16string> args;
    args.emplace_back(Str8ToStr16("-h"));
    int32_t fd = -1;
    service->Dump(fd, args);
    fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    service->Dump(fd, args);
    args.clear();
    args.emplace_back(Str8ToStr16("-d"));
    service->Dump(fd, args);
    args.clear();
    args.emplace_back(Str8ToStr16("-n"));
    service->Dump(fd, args);
    close(fd);
    unlink("/data/fuse_test.txt");
}

static void TestRemoveMDMPolicy(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->RemoveMDMPolicy();
}

static void TestClearUnreservedSandbox(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->ClearUnreservedSandbox();
}

static void TestRegister(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFF_SIZE)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->UnregisterAccount();
    service->RegisterAccount();
    FuzzedDataProvider fdp(data, size);
    service->DelSandboxInfoByAccount(fdp.ConsumeBool());
    service->InitAccountListenerCallback();
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeBytesAsString(FOUR);
    service->OnAddSystemAbility(systemAbilityId, deviceId);
    std::vector<RetentionSandBoxInfo> retentionSandBoxInfoVec,
    RetentionInfo info;
    service->RemoveRetentionInfo(retentionSandBoxInfoVec, info);
}

static void TestWaterMark(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < TWO)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    service->CheckWaterMarkInfo();
    service->ChangeWaterMarkInfo();
    sptr<IDlpPermissionCallback> callback;
    service->GetWaterMark(fdp.ConsumeBool(), callback);
}

static void TestDomainAccount(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LEN)) {
        return;
    }
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, data[0] % STATUS_NUM);
    FuzzedDataProvider fdp(data, size);
    std::string accountNameInfo = fdp.ConsumeBytesAsString(FOUR);
    service->GetDomainAccountNameInfo(accountNameInfo);
    AAFwk::Want want;
    int32_t flags = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    service->GetAbilityInfos(want, flags, userId, abilityInfos);
    DlpSandboxInfo sandboxInfo;
    FileInfo fileInfo;
    service->InsertDlpSandboxInfo(sandboxInfo, fdp.ConsumeBool(), fileInfo);
    std::string bundleName = fdp.ConsumeBytesAsString(FOUR);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    service->UninstallDlpSandboxApp(bundleName, appIndex, userId); 
}

bool DlpPermissionServicesNormalFuzzTest(const uint8_t* data, size_t size)
{
    TestSetSandboxConfig(data, size);
    TestGenerateCert();
    TestParseCert();
    TestInstallDlpSandbox();
    TestGetSandboxExternalAuthorization();
    TestRegisterRegisterDlpSandboxChangeCallback();
    TestRegisterRegisterOpenDlpFileCallback();
    TestUnRegisterUnregisterOpenDlpFileCallback();
    TestSetSandboxAppConfig(data, size);
    TestUnRegisterDlpSandboxChangeCallback(data, size);
    TestDump(data, size);
    TestRemoveMDMPolicy(data, size);
    TestClearUnreservedSandbox(data, size);
    TestRegister(data, size);
    TestWaterMark(data, size);
    TestDomainAccount(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DlpPermissionServicesNormalFuzzTest(data, size);
    return 0;
}
