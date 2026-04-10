/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "open_dlp_file_callback_stub_test.h"

#include "dlp_permission.h"
#include "open_dlp_file_callback_info_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

void OpenDlpFileCallbackStubTest::SetUpTestCase() {}

void OpenDlpFileCallbackStubTest::TearDownTestCase() {}

void OpenDlpFileCallbackTest::OnOpenDlpFile(OpenDlpFileCallbackInfo &result)
{
    called_ = true;
    lastInfo_ = result;
}

void OpenDlpFileCallbackStubTest::SetUp()
{
    stub_ = new (std::nothrow) OpenDlpFileCallbackTest();
    ASSERT_NE(stub_, nullptr);
}

void OpenDlpFileCallbackStubTest::TearDown()
{
    delete stub_;
    stub_ = nullptr;
}

/**
 * @tc.name: OpenDlpFileCallbackStub001
 * @tc.desc: Cover descriptor mismatch branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OpenDlpFileCallbackStubTest, OpenDlpFileCallbackStub001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    int32_t ret = stub_->OnRemoteRequest(IOpenDlpFileCallback::ON_OPEN_DLP_FILE, data, reply, option);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_IPC_REQUEST_FAIL);
}

/**
 * @tc.name: OpenDlpFileCallbackStub002
 * @tc.desc: Cover ReadParcelable failed branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OpenDlpFileCallbackStubTest, OpenDlpFileCallbackStub002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IOpenDlpFileCallback::GetDescriptor());
    int32_t ret = stub_->OnRemoteRequest(IOpenDlpFileCallback::ON_OPEN_DLP_FILE, data, reply, option);
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_PARCEL_OPERATE_FAIL);
    EXPECT_FALSE(stub_->called_);
}

/**
 * @tc.name: OpenDlpFileCallbackStub003
 * @tc.desc: Cover success branch for ON_OPEN_DLP_FILE.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OpenDlpFileCallbackStubTest, OpenDlpFileCallbackStub003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IOpenDlpFileCallback::GetDescriptor());
    sptr<OpenDlpFileCallbackInfoParcel> parcel = new (std::nothrow) OpenDlpFileCallbackInfoParcel();
    ASSERT_NE(parcel, nullptr);
    parcel->fileInfo.uri = "test_uri";
    parcel->fileInfo.timeStamp = 123;
    data.WriteParcelable(parcel);

    int32_t ret = stub_->OnRemoteRequest(IOpenDlpFileCallback::ON_OPEN_DLP_FILE, data, reply, option);
    EXPECT_EQ(ret, DLP_OK);
    EXPECT_TRUE(stub_->called_);
    EXPECT_EQ(stub_->lastInfo_.uri, "test_uri");
    EXPECT_EQ(stub_->lastInfo_.timeStamp, 123);
}

/**
 * @tc.name: OpenDlpFileCallbackStub004
 * @tc.desc: Cover non-ON_OPEN_DLP_FILE code branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(OpenDlpFileCallbackStubTest, OpenDlpFileCallbackStub004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IOpenDlpFileCallback::GetDescriptor());
    int32_t ret = stub_->OnRemoteRequest(IOpenDlpFileCallback::ON_OPEN_DLP_FILE + 1, data, reply, option);
    EXPECT_NE(ret, DLP_OK);
    EXPECT_FALSE(stub_->called_);
}
