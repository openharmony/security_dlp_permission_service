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

#ifndef FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H
#define FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H

#include <string>
#include <vector>

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const uint32_t DLP_MAX_CERT_SIZE = 1024 * 1024; // 1M
static const uint32_t DLP_MAX_EXTRA_INFO_LEN = 100 * 1024; // 100K

#define DLP_CERT_UPDATED 0xff56

enum DlpAccountType : uint32_t {
    INVALID_ACCOUNT = 0,
    CLOUD_ACCOUNT = 1,
    DOMAIN_ACCOUNT = 2,
    APPLICATION_ACCOUNT = 3,
};

enum DLPFileAccess : uint32_t {
    NO_PERMISSION = 0,
    READ_ONLY = 1,
    CONTENT_EDIT = 2,
    FULL_CONTROL = 3,
};

enum GatheringPolicyType : uint32_t {
    GATHERING = 1,
    NON_GATHERING = 2
};

enum class DlpAuthType : uint32_t {
    ONLINE_AUTH_ONLY = 0,
    ONLINE_AUTH_FOR_OFFLINE_CERT = 1,
    OFFLINE_AUTH_ONLY = 2,
};

enum ActionFlags : uint32_t {
    ACTION_INVALID = 0,
    ACTION_VIEW = 1,
    ACTION_SAVE = 1 << 1,
    ACTION_SAVE_AS = 1 << 2,
    ACTION_EDIT = 1 << 3,
    ACTION_SCREEN_CAPTURE = 1 << 4,
    ACTION_SCREEN_SHARE = 1 << 5,
    ACTION_SCREEN_RECORD = 1 << 6,
    ACTION_COPY = 1 << 7,
    ACTION_PRINT = 1 << 8,
    ACTION_EXPORT = 1 << 9,
    ACTION_PERMISSION_CHANGE = 1 << 10
};

typedef struct DLPPermissionInfo {
    DLPFileAccess dlpFileAccess = NO_PERMISSION;
    ActionFlags flags = ACTION_INVALID;
} DLPPermissionInfo;

typedef struct AuthUserInfo {
    std::string authAccount;
    DLPFileAccess authPerm = NO_PERMISSION;
    uint64_t permExpiryTime = 0;
    DlpAccountType authAccountType = INVALID_ACCOUNT;
} AuthUserInfo;

typedef struct SandboxInfo {
    int32_t appIndex = -1;
    uint32_t tokenId = 0;
} SandboxInfo;

struct DlpProperty {
    std::string ownerAccount;
    std::string ownerAccountId;
    std::vector<AuthUserInfo> authUsers;
    std::string contactAccount;
    DlpAccountType ownerAccountType = INVALID_ACCOUNT;
    bool offlineAccess = false;
    bool supportEveryone = false;
    DLPFileAccess everyonePerm = NO_PERMISSION;
    uint64_t expireTime = 0;
};

typedef enum SandBoxExternalAuthorType {
    DENY_START_ABILITY,
    ALLOW_START_ABILITY,
} SandBoxExternalAuthorType;

class PermissionPolicy final {
public:
    PermissionPolicy();
    PermissionPolicy(const DlpProperty& property);
    ~PermissionPolicy();
    void CopyPermissionPolicy(const PermissionPolicy& srcPolicy);
    void FreePermissionPolicyMem();
    void CopyPolicyHmac(const PermissionPolicy& srcPolicy);

    bool IsValid() const;
    void SetAeskey(const uint8_t* key, uint32_t keyLen);
    uint8_t* GetAeskey() const;
    uint32_t GetAeskeyLen() const;
    void SetIv(const uint8_t* iv, uint32_t ivLen);
    uint8_t* GetIv() const;
    uint32_t GetIvLen() const;
    void SetHmacKey(const uint8_t* key, uint32_t keyLen);
    uint8_t* GetHmacKey() const;
    uint32_t GetHmacKeyLen() const;

    std::string ownerAccount_;
    std::string ownerAccountId_;
    DlpAccountType ownerAccountType_;
    std::vector<AuthUserInfo> authUsers_;
    bool supportEveryone_ = false;
    DLPFileAccess everyonePerm_ = NO_PERMISSION;
    uint64_t expireTime_ = 0;
    uint32_t needOnline_ = 0;
    uint32_t dlpVersion_ = 0;

private:
    uint8_t* aeskey_;
    uint32_t aeskeyLen_;
    uint8_t* iv_;
    uint32_t ivLen_;
    uint8_t* hmacKey_;
    uint32_t hmacKeyLen_;
};

void FreeCharBuffer(char* buff, uint32_t buffLen);
bool CheckAccountType(DlpAccountType accountType);
bool CheckAesParamLen(uint32_t len);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // FRAMEWORKS_COMMON_INCLUDE_DLP_POLICY__H
