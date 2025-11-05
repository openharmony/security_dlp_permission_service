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

#include "dlp_callback_test.h"
#include <string>
#include "gtest/gtest.h"
#define  private public
#include "dlp_sandbox_change_callback_manager.h"
#include "open_dlp_file_callback_manager.h"
#undef private
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "iremote_broker.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static const uint32_t MAX_CALLBACK_SIZE = 1024;
static const int32_t DEFAULT_USERID = 100;
static const int32_t TIME_STAMP = 100;
static const std::string DLP_MANAGER_APP = "com.ohos.dlpmanager";
static const std::string URI = "test";
static const uint32_t MAX_CALLBACKS = 100;
}  // namespace

void DlpCallbackTest::SetUpTestCase() {}

void DlpCallbackTest::TearDownTestCase() {}

void DlpCallbackTest::SetUp() {}

void DlpCallbackTest::TearDown() {}

class DlpTestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.test");

    DlpTestRemoteObj() = default;
    virtual ~DlpTestRemoteObj() noexcept = default;
};

/**
 * @tc.name: DlpSandboxChangeCallback001
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, DlpSandboxChangeCallback001, TestSize.Level1)
{
    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    auto proxy = std::make_shared<DlpSandboxChangeCallbackProxy>(callback->AsObject());
    DlpSandboxCallbackInfo input;
    proxy->DlpSandboxStateChangeCallback(input);
    EXPECT_EQ(true, (callback != nullptr));
}

class DlpSandboxChangeCallbackTest : public DlpSandboxChangeCallbackStub {
public:
    DlpSandboxChangeCallbackTest() = default;
    ~DlpSandboxChangeCallbackTest() override;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo &result) override;
};

/**
 * @tc.name: DlpSandboxChangeCallback002
 * @tc.desc: DlpSandboxChangeCallbackManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, DlpSandboxChangeCallback002, TestSize.Level1)
{
    int32_t res = DlpSandboxChangeCallbackManager::GetInstance().AddCallback(0, nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);

    sptr<DlpSandboxChangeCallbackTest> callback = new (std::nothrow) DlpSandboxChangeCallbackTest();
    EXPECT_TRUE(callback != nullptr);

    for (uint32_t index = 0; index <= MAX_CALLBACK_SIZE; ++index) {
        DlpSandboxChangeCallbackRecord recordInstance;
        recordInstance.callbackObject_ = callback->AsObject();
        recordInstance.pid = index;
        DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.
            insert(std::pair<int32_t, DlpSandboxChangeCallbackRecord>(index, recordInstance));
    }
    res = DlpSandboxChangeCallbackManager::GetInstance().AddCallback(0, callback->AsObject());
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    res = DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.pid = MAX_CALLBACK_SIZE + 1;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    dlpSandboxInfo.pid = 1;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    bool result = false;
    res = DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(0, result);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    for (auto it = DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.begin();
        it != DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.end(); ++it) {
        it->second.callbackObject_ = nullptr;
        DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.erase(it);
    }
    DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.clear();
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
 * @tc.name: OpenDlpFileCallbackProxy001
 * @tc.desc: OpenDlpFileCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallbackProxy001, TestSize.Level1)
{
    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    ASSERT_NE(nullptr, callback);

    auto proxy = std::make_shared<OpenDlpFileCallbackProxy>(callback->AsObject());
    OpenDlpFileCallbackInfo input;
    proxy->OnOpenDlpFile(input);
    ASSERT_NE(nullptr, callback);
}

/**
 * @tc.name: OpenDlpFileCallback001
 * @tc.desc: AddCallback if callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback001, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    int32_t res =
        OpenDlpFileCallbackManager::GetInstance().AddCallback(getpid(), DEFAULT_USERID, DLP_MANAGER_APP, nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: OpenDlpFileCallback002
 * @tc.desc: AddCallback in normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback002, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    // repeat add
    res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid(), callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback003
 * @tc.desc: AddCallback if openDlpFileCallbackMap_ reach max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback003, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    uint32_t pid;
    for (pid = 10; pid < MAX_CALLBACKS + 10; ++pid) {
        sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
        ASSERT_NE(nullptr, callback);
        int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
            pid, DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
        EXPECT_EQ(DLP_OK, res);
    }
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        pid, DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
}

/**
 * @tc.name: OpenDlpFileCallback004
 * @tc.desc: AddCallback if openDlpFileCallbackMap_.second reach max size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback004, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    for (uint32_t index = 0; index < MAX_CALLBACKS; ++index) {
        sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
        ASSERT_NE(nullptr, callback);
        int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
            getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
        EXPECT_EQ(DLP_OK, res);
    }

    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, res);
}

/**
 * @tc.name: OpenDlpFileCallback005
 * @tc.desc: RemoveCallback from pid if callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback005, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    int32_t res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid(), nullptr);
    EXPECT_EQ(res, DLP_CALLBACK_PARAM_INVALID);
}

/**
 * @tc.name: OpenDlpFileCallback006
 * @tc.desc: RemoveCallback from pid if pid is 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback006, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(0, callback->AsObject());
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: OpenDlpFileCallback007
 * @tc.desc: RemoveCallback from pid in noraml case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback007, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid(), callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback008
 * @tc.desc: RemoveCallback from pid if pid not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback008, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid() + 1, callback->AsObject());
    EXPECT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
}

/**
 * @tc.name: OpenDlpFileCallback009
 * @tc.desc: RemoveCallback from pid if callback not found at first time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback009, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback1 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback1);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback1->AsObject());
    EXPECT_EQ(DLP_OK, res);
    sptr<TestOpenDlpFileCallback> callback2 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback2);
    res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid(), callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback010
 * @tc.desc: RemoveCallback from pid if callback not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback010, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback1 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback1);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback1->AsObject());
    EXPECT_EQ(DLP_OK, res);
    sptr<TestOpenDlpFileCallback> callback2 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback2);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(getpid(), callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback011
 * @tc.desc: RemoveCallback from death if callback is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback011, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    int32_t res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
}

/**
 * @tc.name: OpenDlpFileCallback012
 * @tc.desc: RemoveCallback from death in normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback012, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
}


/**
 * @tc.name: OpenDlpFileCallback013
 * @tc.desc: RemoveCallback from death if callback not found at first time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback013, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback1 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback1);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback1->AsObject());
    EXPECT_EQ(DLP_OK, res);
    sptr<TestOpenDlpFileCallback> callback2 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback2);
    res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback014
 * @tc.desc: RemoveCallback from death if callback not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback014, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback1 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback1);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback1->AsObject());
    EXPECT_EQ(DLP_OK, res);
    sptr<TestOpenDlpFileCallback> callback2 = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback2);
    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(callback2->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback015
 * @tc.desc: ExecuteCallbackAsync in normal case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback015, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);

    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.uri = URI;
    dlpSandboxInfo.userId = DEFAULT_USERID;
    dlpSandboxInfo.bundleName = DLP_MANAGER_APP;
    dlpSandboxInfo.timeStamp = TIME_STAMP;
    OpenDlpFileCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    usleep(50000); // sleep 50ms
    EXPECT_EQ(true, callback->called_);

    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
}

/**
 * @tc.name: OpenDlpFileCallback016
 * @tc.desc: ExecuteCallbackAsync if not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, OpenDlpFileCallback016, TestSize.Level1)
{
    OpenDlpFileCallbackManager::GetInstance().openDlpFileCallbackMap_.clear();
    sptr<TestOpenDlpFileCallback> callback = new (std::nothrow) TestOpenDlpFileCallback();
    ASSERT_NE(nullptr, callback);
    int32_t res = OpenDlpFileCallbackManager::GetInstance().AddCallback(
        getpid(), DEFAULT_USERID, DLP_MANAGER_APP, callback->AsObject());
    EXPECT_EQ(DLP_OK, res);

    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.uri = URI;
    dlpSandboxInfo.userId = DEFAULT_USERID + 1;
    dlpSandboxInfo.bundleName = DLP_MANAGER_APP;
    dlpSandboxInfo.timeStamp = TIME_STAMP;
    OpenDlpFileCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    usleep(50000); // sleep 50ms
    EXPECT_EQ(false, callback->called_);

    res = OpenDlpFileCallbackManager::GetInstance().RemoveCallback(callback->AsObject());
    EXPECT_EQ(DLP_OK, res);
}
