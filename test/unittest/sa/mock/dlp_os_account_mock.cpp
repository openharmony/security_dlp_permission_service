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

#include "dlp_os_account_mock.h"

namespace OHOS {
namespace AccountSA {
static const int32_t MAIN_OS_ACCOUNT_ID = 100;
static const int32_t DEFAULT_USERID = 100;
std::string g_accountId = "accountIdA";
std::string g_accountName = "accountIdA";
std::string g_parameters = R"({"parameters":{"adConfig":{"adDomain":"test"},"type":"AD"}})";

OhosAccountKits& OhosAccountKits::GetInstance()
{
    static OhosAccountKits instance;
    return instance;
}

std::pair<bool, OhosAccountInfo> OhosAccountKits::QueryOhosAccountInfo()
{
    OhosAccountInfo accountInfo;
    accountInfo.name_ = g_accountName;
    accountInfo.status_ = ACCOUNT_STATE_LOGIN;
    accountInfo.SetRawUid(g_accountId);
    return std::make_pair(false, accountInfo);
}

std::pair<bool, OhosAccountInfo> OhosAccountKits::QueryOsAccountDistributedInfo(std::int32_t userId)
{
    (void)userId;
    OhosAccountInfo accountInfo;
    accountInfo.name_ = g_accountName;
    accountInfo.status_ = ACCOUNT_STATE_LOGIN;
    accountInfo.SetRawUid(g_accountId);
    return std::make_pair(true, accountInfo);
}

ErrCode OhosAccountKits::GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &accountInfo)
{
    accountInfo.name_ = g_accountName;
    accountInfo.status_ = ACCOUNT_STATE_LOGIN;
    accountInfo.SetRawUid(g_accountId);
    return 0;
}

DomainAccountClient& DomainAccountClient::GetInstance()
{
    static DomainAccountClient instance;
    return instance;
}

void OsAccountInfo::GetDomainInfo(DomainAccountInfo &domainInfo)
{
    domainInfo.accountId_ = g_accountId;
    domainInfo.accountName_ = g_accountName;
}

ErrCode DomainAccountClient::GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config)
{
    config.parameters_ = g_parameters;
    return 0;
}

ErrCode DomainAccountClient::GetAccountStatus(DomainAccountInfo &info, DomainAccountStatus &status)
{
    status = DomainAccountStatus::LOGIN;
    return 0;
}

int OsAccountManager::GetForegroundOsAccountLocalId(int32_t &localId)
{
    localId = MAIN_OS_ACCOUNT_ID;
    return 0;
}

int OsAccountManager::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    return 0;
}

int OsAccountManager::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    ids.push_back(MAIN_OS_ACCOUNT_ID);
    return 0;
}

int OsAccountManager::GetOsAccountLocalIdFromUid(const int uid, int &id)
{
    id = DEFAULT_USERID;
    return 0;
}
} // namespace AccountSA
} // namespace OHOS

namespace OHOS {
namespace Security {
namespace DlpPermissionUnitTest {
void SetAccountServerConfigParameters(std::string &parameters)
{
    OHOS::AccountSA::g_parameters = parameters;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS