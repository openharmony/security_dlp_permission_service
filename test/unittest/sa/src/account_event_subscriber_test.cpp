/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "account_event_subscriber_test.h"
#include "common_event_support.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using OHOS::EventFwk::CommonEventSubscribeInfo;
using OHOS::EventFwk::CommonEventSupport;
using OHOS::EventFwk::MatchingSkills;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountEventSubscriberTest"};
static uint32_t g_cntRegister = 0;
static uint32_t g_cntUnregister = 0;
}

void AccountEventSubscriberTest::SetUpTestCase() {}

void AccountEventSubscriberTest::TearDownTestCase() {}

void AccountEventSubscriberTest::SetUp()
{
    g_cntRegister = 0;
    g_cntUnregister = 0;
}

void AccountEventSubscriberTest::TearDown() {}

void RegisterAccount()
{
    g_cntRegister++;
    return;
}

void UnregisterAccount()
{
    g_cntUnregister++;
    return;
}

/**
 * @tc.name: OnReceiveEvent001
 * @tc.desc: OnReceiveEvent test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountEventSubscriberTest, OnReceiveEvent001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnReceiveEvent001");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    AccountEventSubscriber subscriber(subscribeInfo, callback);

    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    ASSERT_EQ(1, g_cntRegister);
    ASSERT_EQ(2, g_cntUnregister);
}

/**
 * @tc.name: OnReceiveEvent002
 * @tc.desc: OnReceiveEvent test with null register callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountEventSubscriberTest, OnReceiveEvent002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnReceiveEvent002");

    AccountListenerCallback callback;
    callback.registerAccount = nullptr;
    callback.unregisterAccount = UnregisterAccount;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    AccountEventSubscriber subscriber(subscribeInfo, callback);

    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    ASSERT_EQ(0, g_cntRegister);
    ASSERT_EQ(0, g_cntUnregister);
}

/**
 * @tc.name: OnReceiveEvent003
 * @tc.desc: OnReceiveEvent test with null unregister callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountEventSubscriberTest, OnReceiveEvent003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnReceiveEvent003");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = nullptr;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    AccountEventSubscriber subscriber(subscribeInfo, callback);

    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    ASSERT_EQ(0, g_cntRegister);
    ASSERT_EQ(0, g_cntUnregister);
}

/**
 * @tc.name: OnReceiveEvent004
 * @tc.desc: OnReceiveEvent test with both null callbacks
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountEventSubscriberTest, OnReceiveEvent004, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "OnReceiveEvent004");

    AccountListenerCallback callback;
    callback.registerAccount = nullptr;
    callback.unregisterAccount = nullptr;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    AccountEventSubscriber subscriber(subscribeInfo, callback);

    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOUT);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGOFF);
    data.SetWant(want);
    subscriber.OnReceiveEvent(data);
    ASSERT_EQ(0, g_cntRegister);
    ASSERT_EQ(0, g_cntUnregister);
}

/**
 * @tc.name: Destructor001
 * @tc.desc: AccountEventSubscriber destructor test with mutex protection
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountEventSubscriberTest, Destructor001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "Destructor001");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    AccountEventSubscriber* subscriber = new AccountEventSubscriber(subscribeInfo, callback);

    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_DISTRIBUTED_ACCOUNT_LOGIN);
    data.SetWant(want);
    subscriber->OnReceiveEvent(data);
    ASSERT_EQ(1, g_cntRegister);

    delete subscriber;
    ASSERT_EQ(1, g_cntRegister);
}