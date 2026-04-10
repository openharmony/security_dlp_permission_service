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

#include "dlp_permission_info_parcel_test.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

void DlpPermissionInfoParcelTest::SetUpTestCase() {}

void DlpPermissionInfoParcelTest::TearDownTestCase() {}

void DlpPermissionInfoParcelTest::SetUp() {}

void DlpPermissionInfoParcelTest::TearDown() {}

/**
 * @tc.name: DlpPermissionInfoParcelMarshalling001
 * @tc.desc: Cover Marshalling success branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionInfoParcelTest, DlpPermissionInfoParcelMarshalling001, TestSize.Level1)
{
    DLPPermissionInfoParcel parcel;
    parcel.permInfo_.dlpFileAccess = DLPFileAccess::READ_ONLY;
    parcel.permInfo_.flags = ACTION_VIEW;

    Parcel out;
    EXPECT_TRUE(parcel.Marshalling(out));
}

/**
 * @tc.name: DlpPermissionInfoParcelUnmarshalling001
 * @tc.desc: Cover Unmarshalling branch when first ReadUint32 fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionInfoParcelTest, DlpPermissionInfoParcelUnmarshalling001, TestSize.Level1)
{
    Parcel in;
    auto result = DLPPermissionInfoParcel::Unmarshalling(in);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DlpPermissionInfoParcelUnmarshalling002
 * @tc.desc: Cover Unmarshalling branch when second ReadUint32 fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionInfoParcelTest, DlpPermissionInfoParcelUnmarshalling002, TestSize.Level1)
{
    Parcel in;
    ASSERT_TRUE(in.WriteUint32(static_cast<uint32_t>(DLPFileAccess::CONTENT_EDIT)));

    auto result = DLPPermissionInfoParcel::Unmarshalling(in);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DlpPermissionInfoParcelUnmarshalling003
 * @tc.desc: Cover Unmarshalling success branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionInfoParcelTest, DlpPermissionInfoParcelUnmarshalling003, TestSize.Level1)
{
    Parcel in;
    ASSERT_TRUE(in.WriteUint32(static_cast<uint32_t>(DLPFileAccess::FULL_CONTROL)));
    ASSERT_TRUE(in.WriteUint32(static_cast<uint32_t>(ACTION_PERMISSION_CHANGE)));

    auto result = DLPPermissionInfoParcel::Unmarshalling(in);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->permInfo_.dlpFileAccess, DLPFileAccess::FULL_CONTROL);
    EXPECT_EQ(result->permInfo_.flags, ACTION_PERMISSION_CHANGE);
    delete result;
}
