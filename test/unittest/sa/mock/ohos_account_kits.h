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

#ifndef OHOS_ACCOUNT_KITS_H
#define OHOS_ACCOUNT_KITS_H

#include <cstdint>
#include <string>
#include "errors.h"

namespace OHOS {
namespace AccountSA {
const int32_t ACCOUNT_STATE_UNBOUND = 0;
const int32_t ACCOUNT_STATE_LOGIN = 1;
const int32_t ACCOUNT_ID_NORMAL = 0;

class DomainAccountInfo {
public:
    DomainAccountInfo()
    {
        accountId_ = ACCOUNT_ID_NORMAL;
        accountName_ = "test";
    }
    virtual ~DomainAccountInfo() = default;

    std::string accountId_;
    std::string accountName_;
};

class DomainServerConfig {
public:
    DomainServerConfig()
    {
        id_ = "name";
        domain_ = "domain";
        parameters_ = "parameters";
    }
    virtual ~DomainServerConfig() = default;

    std::string id_;
    std::string parameters_;
    std::string domain_;
};

enum class DomainAccountStatus {
    LOGIN = ACCOUNT_STATE_LOGIN,
    LOGOUT
};

class DomainAccountClient {
public:
    DomainAccountClient() = default;
    virtual ~DomainAccountClient() = default;

    static DomainAccountClient& GetInstance();
    ErrCode GetAccountServerConfig(const DomainAccountInfo &info, DomainServerConfig &config);
    ErrCode GetAccountStatus(DomainAccountInfo &info, DomainAccountStatus &status);
};

class OhosAccountInfo {
public:
    OhosAccountInfo()
    {
        name_ = "";
        status_ = ACCOUNT_STATE_UNBOUND;
    }

    OhosAccountInfo(const std::string &name, const std::int32_t status)
        :name_(name), status_(status)
    {
    }
    ~OhosAccountInfo() = default;

    std::string GetRawUid() const
    {
        return rawUid_;
    }

    void SetRawUid(std::string rawUid)
    {
        rawUid_ = rawUid;
    }

    std::string uid_;
    std::string name_;
    std::int32_t status_;
    std::string rawUid_;
};

class OhosAccountKits {
public:
    OhosAccountKits() = default;
    virtual ~OhosAccountKits() = default;
    static OhosAccountKits& GetInstance();
    std::pair<bool, OhosAccountInfo> QueryOhosAccountInfo();
    std::pair<bool, OhosAccountInfo> QueryOsAccountDistributedInfo(std::int32_t userId);
    ErrCode GetOsAccountDistributedInfo(int32_t localId, OhosAccountInfo &accountInfo);
};

class OsAccountInfo {
public:
    OsAccountInfo() = default;
    ~OsAccountInfo() = default;
    void GetDomainInfo(DomainAccountInfo &domainInfo);
};

class OsAccountManager {
public:
    OsAccountManager() = default;
    ~OsAccountManager() = default;
    static int GetForegroundOsAccountLocalId(int32_t &localId);
    static int QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo);
    static int QueryActiveOsAccountIds(std::vector<int32_t>& ids);
    static int GetOsAccountLocalIdFromUid(const int32_t uid, int32_t &id);
};

} // namespace AccountSA
} // namespace OHOS
#endif