/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "dlp_permission_service.cpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

void DlpPermissionServiceTest::SetUpTestCase()
{}

void DlpPermissionServiceTest::TearDownTestCase()
{}

void DlpPermissionServiceTest::SetUp()
{}

void DlpPermissionServiceTest::TearDown()
{}


/**
 * @tc.name: SetWatermarkToRS001
 * @tc.desc: SetWatermarkToRS test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, SetWatermarkToRS001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "SetWatermarkToRS001");
    const std::string name = "dlpwatereeee";
    ASSERT_NE(SetWatermarkToRS(name, nullptr), DLP_OK);
}

/**
 * @tc.name: GetPixelmapFromFd001
 * @tc.desc: GetPixelmapFromFd test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionServiceTest, GetPixelmapFromFd001, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "GetPixelmapFromFd001");
    
    WaterMarkInfo info;
    std::shared_mutex  mutex;

    ASSERT_NE(GetPixelmapFromFd(info, mutex), DLP_OK);
}