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

#include "dlpfilenew_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <fstream>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include "dlp_file.h"
#include "dlp_raw_file.h"
#include "dlp_zip_file.h"
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_zip.h"
#include "c_mock_common.h"
#include "nlohmann/json.hpp"
#include "accesstoken_kit.h"
#include "ohos_account_kits.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace std;
using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
    
static constexpr int32_t ZERO = 0;
static constexpr int32_t TWO = 2;
static constexpr int32_t FOUR = 4;
static constexpr int32_t EIGHT = 8;
static constexpr int32_t TEN = 10;
static constexpr int32_t SIXTEEN = 16;
static constexpr int32_t EIGHTEEN = 18;
static constexpr int32_t TWENTY = 20;
static constexpr int32_t FORTY = 40;
static constexpr int32_t SIXTY_EIGHT = 68;
static constexpr int32_t NINETY_NINE = 99;
static constexpr int32_t HUNDRED = 100;
static constexpr int32_t HUNDRED_AND_EIGHT = 108;
static constexpr int32_t TWO_HUNDRED_AND_EIGHT = 208;
static constexpr int32_t TWO_HUNDRED_SEVENTY_TWO = 272;
static constexpr int32_t THOUSAND = 1000;
static constexpr int32_t PERM = 0777;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileTest"};
static constexpr int32_t READ_SIZE = 100;
static constexpr int32_t SECOND = 2;
static constexpr int32_t MIN_LENGTH = 100;
static const std::string DLP_TEST_DIR = "/data/dlpTest/";
const std::string DLP_GENERAL_INFO = "dlp_general_info";
const std::string DLP_CERT = "dlp_cert";
const std::string DLP_ENC_DATA = "encrypted_data";
const std::string DLP_OPENING_ENC_DATA = "opened_encrypted_data";
const std::string DLP_WRITING_FILE = "write_dlp_file";
const std::string DLP_GEN_FILE = "gen_dlp_file";

const std::string DLP_CONTACT_ACCOUNT = "contactAccount";
const std::string DLP_VERSION = "dlpVersion";
const std::string DLP_OFFLINE_FLAG = "offlineAccess";
const std::string DLP_EXTRA_INFO = "extraInfo";

void initDlpFileCiper(DlpRawFile &testFile)
{
    uint8_t keyData[SIXTEEN] = {};
    struct DlpBlob key = {
        .data = keyData,
        .size = SIXTEEN
    };

    uint8_t ivData[SIXTEEN] = {};
    struct DlpCipherParam param;
    param.iv.data = ivData;
    param.iv.size = IV_SIZE;
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    testFile.policy_.dlpVersion_ = SECOND;
    testFile.version_ = SECOND;

    testFile.SetCipher(key, spec, hmacKey);
    uint8_t* cert = new (std::nothrow) uint8_t[SIXTEEN];
    if (cert == nullptr) {
        return;
    }
    struct DlpBlob certKey = {
        .data = cert,
        .size = SIXTEEN
    };
    testFile.SetEncryptCert(certKey);
    delete[] certKey.data;
    certKey.data = nullptr;
    certKey.size = ZERO;
}

void initDlpFileCiper(DlpZipFile &testFile)
{
    uint8_t keyData[SIXTEEN] = {};
    struct DlpBlob key = {
        .data = keyData,
        .size = SIXTEEN
    };

    uint8_t ivData[SIXTEEN] = {};
    struct DlpCipherParam param;
    param.iv.data = ivData;
    param.iv.size = IV_SIZE;
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    testFile.policy_.dlpVersion_ = SECOND;
    testFile.version_ = SECOND;

    testFile.SetCipher(key, spec, hmacKey);
    uint8_t* cert = new (std::nothrow) uint8_t[SIXTEEN];
    if (cert == nullptr) {
        return;
    }
    struct DlpBlob certKey = {
        .data = cert,
        .size = SIXTEEN
    };
    testFile.SetEncryptCert(certKey);
    delete[] certKey.data;
    certKey.data = nullptr;
    certKey.size = ZERO;
}
}

namespace OHOS {
void TearDownTestCase()
{
    rmdir(DLP_TEST_DIR.c_str());
}

void SetUp()
{
    struct stat fstat;
    if (stat(DLP_TEST_DIR.c_str(), &fstat) != ZERO) {
        if (errno == ENOENT) {
            int32_t dRet = mkdir(DLP_TEST_DIR.c_str(), S_IRWXU | S_IRWXG | S_IRWXO);
            if (dRet < ZERO) {
                DLP_LOG_ERROR(LABEL, "mkdir mount point failed errno %{public}d", errno);
                return;
            }
        } else {
            DLP_LOG_ERROR(LABEL, "get mount point failed errno %{public}d", errno);
            return;
        }
    }
}

void IsValidCipher001()
{
    SetUp();
    struct DlpBlob key = {
        .data = nullptr,
    };

    struct DlpUsageSpec spec;
    uint8_t keyData[DLP_KEY_LEN_256] = { ZERO };

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    // key.data nullptr
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.IsValidCipher(key, spec, hmacKey);

    // key size is invalid
    key.data = keyData;
    key.size = HUNDRED;
    testFile.IsValidCipher(key, spec, hmacKey);

    // key size DLP_KEY_LEN_128, mode is not ctr
    key.size = DLP_KEY_LEN_128;
    spec.mode = TWO;
    testFile.IsValidCipher(key, spec, hmacKey);

    // key size DLP_KEY_LEN_192, algParam is null
    key.size = DLP_KEY_LEN_192;
    spec.mode = DLP_MODE_CTR;
    spec.algParam = nullptr;
    testFile.IsValidCipher(key, spec, hmacKey);

    // key size DLP_KEY_LEN_256, iv size invalid
    key.size = DLP_KEY_LEN_256;
    struct DlpCipherParam algParam;
    uint8_t ivData[IV_SIZE] = { ZERO };
    spec.algParam = &algParam;
    spec.algParam->iv.size = 1;
    spec.algParam->iv.data = ivData;
    testFile.IsValidCipher(key, spec, hmacKey);

    // key size DLP_KEY_LEN_256, iv data invalid
    key.size = DLP_KEY_LEN_256;
    spec.algParam = &algParam;
    spec.algParam->iv.size = SIXTEEN;
    spec.algParam->iv.data = nullptr;
    testFile.IsValidCipher(key, spec, hmacKey);

    // all valid
    key.size = DLP_KEY_LEN_256;
    spec.algParam = &algParam;
    spec.algParam->iv.size = SIXTEEN;
    spec.algParam->iv.data = ivData;
    testFile.IsValidCipher(key, spec, hmacKey);
}

void CopyBlobParam001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpBlob src = {
        .data = nullptr,
    };
    struct DlpBlob dst;

    // src.data null
    testFile.CopyBlobParam(src, dst);

    // src.size ZERO
    uint8_t data[SIXTEEN] = {ZERO};
    src.data = data;
    src.size = ZERO;
    testFile.CopyBlobParam(src, dst);

    // size > DLP_MAX_CERT_SIZE
    src.size = DLP_MAX_CERT_SIZE + 1;
    testFile.CopyBlobParam(src, dst);

    // params ok
    src.size = SIXTEEN;
    testFile.CopyBlobParam(src, dst);
    if (dst.data != nullptr) {
        delete dst.data;
    }
}

void CleanBlobParam001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpBlob blob = {
        .data = nullptr,
    };

    // blob.data null
    testFile.CleanBlobParam(blob);

    // blob.size ZERO
    uint8_t* data = new (std::nothrow) uint8_t[SIXTEEN];
    if (data == nullptr) {
        return;
    }
    blob.data = data;
    blob.size = ZERO;
    testFile.CleanBlobParam(blob);

    blob.size = SIXTEEN;
    testFile.CleanBlobParam(blob);
}

void GetLocalAccountName001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    std::string account;
    int dlpRet = testFile.GetLocalAccountName(account);
}

void GetDomainAccountName001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    std::string account;
    int dlpRet = testFile.GetDomainAccountName(account);
}

void UpdateDlpFilePermission001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.policy_.ownerAccount_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountId_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountType_ = DOMAIN_ACCOUNT;
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;

    testFile.UpdateDlpFilePermission();
}

void UpdateDlpFilePermission002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    AuthUserInfo user = {
        .authAccount = "ohosAnonymousName",
        .authPerm = DLPFileAccess::READ_ONLY
    };

    testFile.policy_.authUsers_.emplace_back(user);
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;

    testFile.UpdateDlpFilePermission();
}

void UpdateDlpFilePermission003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.policy_.ownerAccount_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountId_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountType_ = DOMAIN_ACCOUNT;
    testFile.policy_.supportEveryone_ = true;
    testFile.policy_.everyonePerm_ = DLPFileAccess::CONTENT_EDIT;
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;

    testFile.UpdateDlpFilePermission();
}

void UpdateDlpFilePermission004()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    AuthUserInfo user = {
        .authAccount = "noExistUser",
        .authPerm = DLPFileAccess::FULL_CONTROL
    };
    testFile.policy_.ownerAccountType_ = DOMAIN_ACCOUNT;
    testFile.policy_.authUsers_.emplace_back(user);
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;
    testFile.UpdateDlpFilePermission();
}

void UpdateDlpFilePermission005()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.policy_.ownerAccount_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountId_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountType_ = DOMAIN_ACCOUNT;
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;

    testFile.UpdateDlpFilePermission();
}

void UpdateDlpFilePermission006()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.policy_.ownerAccount_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountId_ = "ohosAnonymousName";
    testFile.policy_.ownerAccountType_ = DOMAIN_ACCOUNT;
    testFile.policy_.supportEveryone_ = true;
    testFile.authPerm_ = DLPFileAccess::NO_PERMISSION;

    testFile.UpdateDlpFilePermission();
}

void SetCipher001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpBlob key = {
        .data = nullptr,
    };
    struct DlpUsageSpec spec;

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    testFile.SetCipher(key, spec, hmacKey);
}

void SetCipher002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t keyData[DLP_KEY_LEN_256] = { ZERO };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { ZERO };
    spec.algParam->iv.size = SIXTEEN;
    spec.algParam->iv.data = ivData;
    spec.mode = DLP_MODE_CTR;

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    testFile.SetCipher(key, spec, hmacKey);
    CleanMockConditions();
}

void SetCipher003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t keyData[DLP_KEY_LEN_256] = { ZERO };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { ZERO };
    spec.algParam->iv.size = SIXTEEN;
    spec.algParam->iv.data = ivData;
    spec.mode = DLP_MODE_CTR;

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    DlpCMockCondition condition;
    condition.mockSequence = { false, true };
    SetMockConditions("memcpy_s", condition);
    testFile.SetCipher(key, spec, hmacKey);
    CleanMockConditions();
}

void SetCipher004()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t keyData[DLP_KEY_LEN_256] = { ZERO };
    struct DlpBlob key;
    key.data = keyData;
    key.size = DLP_KEY_LEN_256;
    struct DlpUsageSpec spec;
    struct DlpCipherParam algParam;
    spec.algParam = &algParam;
    uint8_t ivData[IV_SIZE] = { ZERO };
    spec.algParam->iv.size = SIXTEEN;
    spec.algParam->iv.data = ivData;

    uint8_t hmacKeyData[32] = {};
    struct DlpBlob hmacKey = {
        .data = hmacKeyData,
        .size = 32
    };

    spec.mode = DLP_MODE_CTR;
    testFile.SetCipher(key, spec, hmacKey);
}

void SetContactAccount001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.SetContactAccount("");

    std::string invalidAccount(DLP_MAX_CERT_SIZE + 1, 'a');
    testFile.SetContactAccount(invalidAccount);

    // head_.certSize = ZERO
    testFile.head_.certSize = ZERO;
    testFile.SetContactAccount("testAccount");
}

void SetPolicy001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    PermissionPolicy policy;
    testFile.SetPolicy(policy);
}

void IsValidDlpHeader001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .fileType = TEN,
        .offlineAccess = ZERO,
        .algType = DLP_MODE_CTR,
        .txtOffset = sizeof(struct DlpHeader) + HUNDRED_AND_EIGHT,
        .txtSize = HUNDRED,
        .hmacOffset = sizeof(struct DlpHeader) + TWO_HUNDRED_AND_EIGHT,
        .hmacSize = 64,
        .certOffset = sizeof(struct DlpHeader) + TWO_HUNDRED_SEVENTY_TWO,
        .certSize = 256,
        .contactAccountOffset = sizeof(struct DlpHeader) + EIGHT,
        .contactAccountSize = HUNDRED,
        .offlineCertOffset = sizeof(struct DlpHeader) + TWO_HUNDRED_SEVENTY_TWO,
        .offlineCertSize = ZERO
    };

    // valid header
    testFile.IsValidDlpHeader(header);

    // wrong magic
    header.magic = ZERO;
    testFile.IsValidDlpHeader(header);
    header.magic = DLP_FILE_MAGIC;

    // certSize ZERO
    header.certSize = ZERO;
    testFile.IsValidDlpHeader(header);

    // certSize too large
    header.certSize = DLP_MAX_CERT_SIZE + 1;
    testFile.IsValidDlpHeader(header);
    header.certSize = TWENTY;

    // certOffset invalid
    header.certOffset = HUNDRED;
    testFile.IsValidDlpHeader(header);
    header.certOffset = sizeof(struct DlpHeader) + TWO_HUNDRED_SEVENTY_TWO;

    // contactAccountSize ZERO
    header.contactAccountSize = ZERO;
    testFile.IsValidDlpHeader(header);

    // contactAccountSize too large
    header.contactAccountSize = DLP_MAX_CERT_SIZE + 1;
    testFile.IsValidDlpHeader(header);

    // contactAccountOffset invalid
    header.contactAccountOffset = HUNDRED;
    testFile.IsValidDlpHeader(header);
    header.contactAccountOffset = sizeof(struct DlpHeader);

    // txtOffset invalid
    header.txtOffset = HUNDRED;
    testFile.IsValidDlpHeader(header);
    header.txtOffset = sizeof(struct DlpHeader) + TWENTY;

    // txtOffset invalid
    header.txtSize = DLP_MAX_CONTENT_SIZE + 1;
    testFile.IsValidDlpHeader(header);
}

void ParseDlpHeader001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    testFile.dlpFd_ = -1;
    testFile.ProcessDlpFile();

    testFile.dlpFd_ = THOUSAND;
    testFile.isFuseLink_ = true;
    testFile.ProcessDlpFile();

    // fd > ZERO but invalid
    testFile.dlpFd_ = THOUSAND;
    testFile.isFuseLink_ = false;
    testFile.ProcessDlpFile();
}

void ParseDlpHeader002()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = TWENTY,
        .contactAccountSize = TWENTY,
    };

    // write less than header size
    write(fd, &header, sizeof(header) - 1);
    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void ParseDlpHeader003()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certSize = ZERO,
        .contactAccountSize = TWENTY,
    };

    // write less than header size
    write(fd, &header, sizeof(header));
    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void ParseDlpHeader004()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = ZERO,
        .certSize = TWENTY,
        .contactAccountOffset = sizeof(struct DlpHeader) + TWENTY,
        .contactAccountSize = TWENTY,
        .txtOffset  = sizeof(struct DlpHeader) + TWENTY + TWENTY,
        .txtSize = HUNDRED,
        .offlineCertOffset = ZERO,
        .offlineCertSize = ZERO,
    };
    write(fd, &header, sizeof(header));

    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void ParseDlpHeader005()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader),
        .offlineAccess = ZERO,
        .certSize = TWENTY,
        .contactAccountOffset = sizeof(struct DlpHeader) + TWENTY,
        .contactAccountSize = TWENTY,
        .txtOffset  = sizeof(struct DlpHeader) + TWENTY + TWENTY,
        .txtSize = HUNDRED,
        .offlineCertOffset = ZERO,
        .offlineCertSize = ZERO,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[TWENTY] = {ZERO};
    write(fd, buffer, TWENTY);

    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void ParseDlpHeader006()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader) + TWENTY + HUNDRED + SIXTY_EIGHT,
        .offlineAccess = ZERO,
        .certSize = TWENTY,
        .contactAccountOffset = sizeof(struct DlpHeader),
        .contactAccountSize = TWENTY,
        .txtOffset  = sizeof(struct DlpHeader) + TWENTY,
        .txtSize = HUNDRED,
        .offlineCertOffset = ZERO,
        .offlineCertSize = ZERO,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[TWO_HUNDRED_AND_EIGHT] = {ZERO};
    write(fd, buffer, TWO_HUNDRED_AND_EIGHT);

    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void ParseDlpHeader007()
{
    SetUp();
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    DlpRawFile testFile(fd, "txt");

    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .certOffset = sizeof(struct DlpHeader) + TWENTY + HUNDRED + SIXTY_EIGHT,
        .offlineAccess = ZERO,
        .certSize = TWENTY,
        .contactAccountOffset = sizeof(struct DlpHeader),
        .contactAccountSize = TWENTY,
        .txtOffset  = sizeof(struct DlpHeader) + TWENTY,
        .txtSize = HUNDRED,
        .offlineCertOffset = ZERO,
        .offlineCertSize = ZERO,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[FORTY] = {ZERO};
    write(fd, buffer, FORTY);

    testFile.ProcessDlpFile();
    close(fd);
    unlink("/data/fuse_test.txt");
}

void SetEncryptCert001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpBlob cert = {
        .data = nullptr,
        .size = ZERO
    };
    // size = ZERO
    testFile.SetEncryptCert(cert);

    // size too large
    uint8_t data[SIXTEEN] = {};
    cert.data = data;
    cert.size = DLP_MAX_CERT_SIZE + 1;
    testFile.SetEncryptCert(cert);
}

void SetEncryptCert002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = 32
    };
    uint8_t *oldCert = new (std::nothrow) uint8_t[SIXTEEN];
    testFile.cert_.data = oldCert;
    testFile.cert_.size = SIXTEEN;
    if (testFile.cert_.data == nullptr) {
        return;
    }

    testFile.SetEncryptCert(cert);
}

void SetEncryptCert003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t data[32] = {};
    struct DlpBlob cert = {
        .data = data,
        .size = ZERO
    };

    testFile.SetEncryptCert(cert);
}

void DupUsageSpec001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    struct DlpUsageSpec spec;

    testFile.DupUsageSpec(spec);
}

void DupUsageSpec002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t data[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = data,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec specOld = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = specOld;

    struct DlpUsageSpec spec;
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    testFile.DupUsageSpec(spec);
    CleanMockConditions();
}

void DupUsageSpec003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t data[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = data,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec specOld = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = specOld;

    struct DlpUsageSpec spec;
    testFile.DupUsageSpec(spec);
}

void DoDlpBlockCryptOperation001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    uint8_t data1[SIXTEEN] = {};
    uint8_t data2[SIXTEEN] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = SIXTEEN
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = SIXTEEN
    };

    // offset not aligned
    testFile.DoDlpBlockCryptOperation(message1, message2, 1, false);

    // message1 data nullptr
    message1.data = nullptr;
    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
    message1.data = data1;

    // message1 size ZERO
    message1.size = ZERO;
    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
    message1.size = SIXTEEN;

    // message2 data nullptr
    message2.data = nullptr;
    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
    message2.data = data1;

    // message2 size ZERO
    message2.size = ZERO;
    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
    message2.size = SIXTEEN;
}

void DoDlpBlockCryptOperation002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    uint8_t data1[SIXTEEN] = {};
    uint8_t data2[SIXTEEN] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = SIXTEEN
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = SIXTEEN
    };

    testFile.cipher_.usageSpec.algParam = nullptr;
    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
}

void DoDlpBlockCryptOperation003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    uint8_t data1[SIXTEEN] = {};
    uint8_t data2[SIXTEEN] = {};
    struct DlpBlob message1 = {
        .data = data1,
        .size = SIXTEEN
    };

    struct DlpBlob message2 = {
        .data = data2,
        .size = SIXTEEN
    };

    uint8_t ivData[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    testFile.DoDlpBlockCryptOperation(message1, message2, SIXTEEN, false);
}

void DoDlpContentCryptyOperation001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t ivData[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    testFile.DoDlpContentCryptyOperation(THOUSAND, THOUSAND, ZERO, TEN, true);
}

void DoDlpContentCryptyOperation002()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    uint8_t ivData[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    uint8_t buffer[FORTY] = {1};
    write(fd, buffer, FORTY);
    lseek(fd, ZERO, SEEK_SET);
    testFile.DoDlpContentCryptyOperation(fd, THOUSAND, ZERO, TEN, true);
    close(fd);
    unlink("/data/fuse_test.txt");
}

void DoDlpContentCryptyOperation003()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    initDlpFileCiper(testFile);

    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    uint8_t buffer[FORTY] = {1};
    write(fd, buffer, FORTY);
    lseek(fd, ZERO, SEEK_SET);
    testFile.DoDlpContentCryptyOperation(fd, THOUSAND, ZERO, TEN, true);
    close(fd);
    unlink("/data/fuse_test.txt");
}

void GenFile001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");

    testFile.GenFile(-1);

    testFile.dlpFd_ = -1;
    testFile.GenFile(1);

    testFile.dlpFd_ = THOUSAND;
    testFile.GenFile(1);
}

void GenFile002()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("ftruncate", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("lseek", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("lseek", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("write", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("write", condition);
    testFile.GenFile(fdPlain);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void RemoveDlpPermission001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    // isFuseLink_ true
    testFile.isFuseLink_ = true;
    testFile.RemoveDlpPermission(fdPlain);
    testFile.isFuseLink_ = false;

    // authPerm_ DLPFileAccess::READ_ONLY
    testFile.authPerm_ = DLPFileAccess::READ_ONLY;
    testFile.RemoveDlpPermission(fdPlain);
    testFile.authPerm_ = DLPFileAccess::FULL_CONTROL;

    // outPlainFileFd invalid
    testFile.RemoveDlpPermission(-1);

    // dlpFd invalid
    testFile.dlpFd_ = -1;
    testFile.RemoveDlpPermission(fdPlain);
    testFile.dlpFd_ = fdDlp;

    // cipher invalid
    testFile.cipher_.encKey.size = ZERO;
    testFile.RemoveDlpPermission(fdPlain);
    testFile.cipher_.encKey.size = SIXTEEN;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.RemoveDlpPermission(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("ftruncate", condition);
    testFile.RemoveDlpPermission(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("lseek", condition);
    testFile.RemoveDlpPermission(fdPlain);
    CleanMockConditions();

    condition.mockSequence = { false, false, true };
    SetMockConditions("lseek", condition);
    testFile.RemoveDlpPermission(fdPlain);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void DlpFileRead001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);
    int32_t uid = getuid();
    bool hasRead = true;
    // isFuseLink_ true
    testFile.DlpFileRead(ZERO, nullptr, TEN, hasRead, uid);

    uint8_t buffer[SIXTEEN] = {};
    testFile.DlpFileRead(ZERO, buffer, ZERO, hasRead, uid);
    testFile.DlpFileRead(DLP_MAX_RAW_CONTENT_SIZE, buffer, 1, hasRead, uid);
    testFile.DlpFileRead(ZERO, buffer, DLP_FUSE_MAX_BUFFLEN + 1, hasRead, uid);

    testFile.dlpFd_ = -1;
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);
    testFile.dlpFd_ = fdDlp;

    testFile.cipher_.encKey.size = ZERO;
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);
    testFile.cipher_.encKey.size = SIXTEEN;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);
    CleanMockConditions();

    // read size ZERO
    testFile.head_.txtOffset = ZERO;
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);

    // do crypt failed
    write(fdDlp, "1111", FOUR);
    lseek(fdDlp, ZERO, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    SetMockConditions("memcpy_s", condition);
    testFile.DlpFileRead(ZERO, buffer, SIXTEEN, hasRead, uid);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void WriteFirstBlockData001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[SIXTEEN] = {0x1};

    testFile.dlpFd_ = -1;
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    testFile.dlpFd_ = fdDlp;

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("memcpy_s", condition);
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    CleanMockConditions();

    // decrypt fail
    write(fdDlp, "1111", FOUR);
    lseek(fdDlp, ZERO, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    CleanMockConditions();

    // encrypt fail
    lseek(fdDlp, ZERO, SEEK_SET);
    condition.mockSequence = { false, true };
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    CleanMockConditions();

    // lseek fail
    lseek(fdDlp, ZERO, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    CleanMockConditions();

    // write fail
    lseek(fdDlp, ZERO, SEEK_SET);
    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    testFile.WriteFirstBlockData(FOUR, writeBuffer, SIXTEEN);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void DoDlpFileWrite001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[EIGHTEEN] = {0x1};

    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.DoDlpFileWrite(ZERO, writeBuffer, EIGHTEEN);
    CleanMockConditions();

    condition.mockSequence = { true };
    lseek(fdDlp, ZERO, SEEK_SET);
    SetMockConditions("memcpy_s", condition);
    testFile.DoDlpFileWrite(ZERO, writeBuffer, EIGHTEEN);
    CleanMockConditions();

    condition.mockSequence = { true };
    lseek(fdDlp, ZERO, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    testFile.DoDlpFileWrite(ZERO, writeBuffer, EIGHTEEN);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    lseek(fdDlp, ZERO, SEEK_SET);
    SetMockConditions("EVP_CIPHER_CTX_new", condition);
    testFile.DoDlpFileWrite(ZERO, writeBuffer, EIGHTEEN);
    CleanMockConditions();

    condition.mockSequence = { false, true };
    lseek(fdDlp, ZERO, SEEK_SET);
    SetMockConditions("write", condition);
    testFile.DoDlpFileWrite(ZERO, writeBuffer, EIGHTEEN);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void GetFsContentSize001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = SIXTEEN;
    testFile.GetFsContentSize();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void UpdateDlpFileContentSize001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = SIXTEEN;
    testFile.head_.txtSize = ZERO;
    testFile.UpdateDlpFileContentSize();
    testFile.head_.txtOffset = ZERO;
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.UpdateDlpFileContentSize();
    CleanMockConditions();

    condition.mockSequence = { true };
    SetMockConditions("write", condition);
    testFile.UpdateDlpFileContentSize();
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void FillHoleData001()
{
    SetUp();
    DlpRawFile testFile(-1, "txt");
    testFile.FillHoleData(ZERO, SIXTEEN);
}

void DlpFileWrite001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);
    uint8_t writeBuffer[SIXTEEN] = {0x1};

    testFile.head_.txtOffset = ZERO;

    testFile.authPerm_ = DLPFileAccess::READ_ONLY;
    testFile.DlpFileWrite(FOUR, writeBuffer, SIXTEEN);
    testFile.authPerm_ = DLPFileAccess::FULL_CONTROL;

    testFile.DlpFileWrite(FOUR, nullptr, SIXTEEN);
    testFile.DlpFileWrite(FOUR, writeBuffer, ZERO);
    testFile.DlpFileWrite(DLP_MAX_RAW_CONTENT_SIZE, writeBuffer, 1);
    testFile.DlpFileWrite(FOUR, writeBuffer, DLP_FUSE_MAX_BUFFLEN + 1);

    testFile.dlpFd_ = -1;
    testFile.DlpFileWrite(FOUR, writeBuffer, SIXTEEN);
    testFile.dlpFd_ = fdDlp;

    testFile.cipher_.encKey.size = ZERO;
    testFile.DlpFileWrite(FOUR, writeBuffer, SIXTEEN);
    testFile.cipher_.encKey.size = SIXTEEN;

    // fill hole data fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.DlpFileWrite(SIXTEEN, writeBuffer, SIXTEEN);
    CleanMockConditions();

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void Truncate001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    testFile.head_.txtOffset = ZERO;
    testFile.head_.txtSize = ZERO;
    testFile.authPerm_ = DLPFileAccess::READ_ONLY;
    testFile.Truncate(SIXTEEN);
    testFile.authPerm_ = DLPFileAccess::FULL_CONTROL;

    testFile.dlpFd_ = -1;
    testFile.Truncate(SIXTEEN);
    testFile.dlpFd_ = fdDlp;

    testFile.Truncate(0xffffffff);

    testFile.Truncate(ZERO);

    // fill hole data fail
    DlpCMockCondition condition;
    condition.mockSequence = { true };
    SetMockConditions("lseek", condition);
    testFile.Truncate(SIXTEEN);
    CleanMockConditions();
    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void DoDlpContentCopyOperation001(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= sizeof(uint8_t) * MIN_LENGTH)) {
        return;
    }
    SetUp();
    DlpZipFile testFile(THOUSAND, DLP_TEST_DIR, ZERO, "txt");
    uint8_t ivData[SIXTEEN] = {};

    struct DlpCipherParam param = {
        .iv = {
            .data = ivData,
            .size = SIXTEEN
        }
    };
    struct DlpUsageSpec spec = {
        .mode = DLP_MODE_CTR,
        .algParam = &param
    };
    testFile.cipher_.usageSpec = spec;

    FuzzedDataProvider fdp(data, size);
    int32_t inFd = fdp.ConsumeIntegral<int32_t>();
    int32_t outFd = fdp.ConsumeIntegral<int32_t>();
    uint64_t inOffset = fdp.ConsumeIntegral<uint64_t>();
    uint64_t inFileLen = fdp.ConsumeIntegral<uint64_t>();
    testFile.DoDlpContentCopyOperation(inFd, outFd, inOffset, inFileLen);
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd == -1) {
        return;
    }
    uint8_t buffer[FORTY] = {1};
    write(fd, buffer, FORTY);
    lseek(fd, ZERO, SEEK_SET);
    testFile.DoDlpContentCopyOperation(fd, ZERO, TEN, HUNDRED);
    int fd2 = open("/data/fuse_test2.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fd2 == -1) {
        close(fd);
        return;
    }
    testFile.DoDlpContentCopyOperation(fd, fd2, TEN, HUNDRED);
}

void CheckDlpFile001(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= sizeof(uint8_t) * MIN_LENGTH)) {
        return;
    }
    SetUp();
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    FuzzedDataProvider fdp(data, size);
    testFile.head_.certSize = fdp.ConsumeIntegral<uint32_t>();
    testFile.head_.contactAccountSize = fdp.ConsumeIntegral<uint32_t>();
    testFile.head_.contactAccountOffset = sizeof(struct DlpHeader) + TEN;
    testFile.head_.txtOffset = sizeof(struct DlpHeader) + TEN + TEN;
    testFile.head_.txtSize = fdp.ConsumeIntegral<uint64_t>();
    // dlp file version not exist
    testFile.version_ = NINETY_NINE;
    write(fdDlp, &testFile.head_, sizeof(struct DlpHeader));
    lseek(fdDlp, ZERO, SEEK_SET);
    int res = testFile.CheckDlpFile();
    close(fdDlp);
}

void NeedAdapter001()
{
    SetUp();
    DlpRawFile testFile(THOUSAND, "txt");
    testFile.NeedAdapter();
    testFile.version_ = 1;
    testFile.NeedAdapter();
    testFile.version_ = TWO;
    testFile.NeedAdapter();
}

void GenZipFile001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);

    testFile.GenFile(fdPlain);

    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void CleanTmpFile001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.CleanTmpFile();
    close(fdPlain);
    close(fdDlp);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void ParseDlpInfo001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);

    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile2(fdDlp2, DLP_TEST_DIR, 1, "txt");
    testFile2.ProcessDlpFile();
    char cwd[PATH_MAX] = {ZERO};
    (void)getcwd(cwd, PATH_MAX);
    std::string path = DLP_TEST_DIR + "/1";
    (void)chdir(path.c_str());
    testFile2.ParseDlpInfo();

    std::string dst = DLP_TEST_DIR + "/1" + "/dlp_general_info";
    int fInfo = open(dst.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    testFile2.ParseDlpInfo();

    int dlpRet = ftruncate(fInfo, ZERO);

    nlohmann::json dlp_general_info;
    dlp_general_info[DLP_VERSION] = "dlp_general_info";
    std::string out = dlp_general_info.dump();
    dlpRet = lseek(fInfo, ZERO, SEEK_SET);
    dlpRet = write(fInfo, out.c_str(), out.size());
    fsync(fInfo);
    testFile2.ParseDlpInfo();

    (void)chdir(cwd);
    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);
    close(fInfo);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void ParseDlpInfo002()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile2(fdDlp2, DLP_TEST_DIR, 1, "txt");
    testFile2.ProcessDlpFile();
    char cwd[PATH_MAX] = {ZERO};
    (void)getcwd(cwd, PATH_MAX);
    std::string path = DLP_TEST_DIR + "/1";
    (void)chdir(path.c_str());
    testFile2.ParseDlpInfo();

    std::string dst = DLP_TEST_DIR + "/1" + "/dlp_general_info";
    int fInfo = open(dst.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    testFile2.ParseDlpInfo();

    int dlpRet = ftruncate(fInfo, ZERO);

    nlohmann::json dlp_general_info;
    std::string out;
    dlp_general_info[DLP_VERSION] = 1;
    dlp_general_info[DLP_OFFLINE_FLAG] = "dlp_general_info";

    out = dlp_general_info.dump();
    dlpRet = lseek(fInfo, ZERO, SEEK_SET);
    dlpRet = write(fInfo, out.c_str(), out.size());
    fsync(fInfo);
    testFile2.ParseDlpInfo();

    (void)chdir(cwd);
    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);
    close(fInfo);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void ParseCert001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile2(fdDlp2, DLP_TEST_DIR, 1, "txt");
    testFile2.ProcessDlpFile();
    char cwd[PATH_MAX] = {ZERO};
    (void)getcwd(cwd, PATH_MAX);
    std::string path = DLP_TEST_DIR + "/1";
    (void)chdir(path.c_str());
    testFile2.ParseCert();

    std::string dst = DLP_TEST_DIR + "/1" + "/dlp_cert";
    unlink(dst.c_str());
    testFile2.ParseCert();

    mkdir(dst.c_str(), PERM);
    testFile2.ParseCert();
    rmdir(dst.c_str());

    int fInfo = open(dst.c_str(), O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    testFile2.cert_.size = READ_SIZE;
    testFile2.ParseCert();

    (void)chdir(cwd);
    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);
    close(fInfo);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void ParseEncData001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile2(fdDlp2, DLP_TEST_DIR, 1, "txt");
    testFile2.ProcessDlpFile();
    char cwd[PATH_MAX] = {ZERO};
    (void)getcwd(cwd, PATH_MAX);
    std::string path = DLP_TEST_DIR + "/1";
    (void)chdir(path.c_str());
    testFile2.ParseEncData();

    std::string dst = DLP_TEST_DIR + "/1" + "/opened_encrypted_data";
    unlink(dst.c_str());
    testFile2.ParseEncData();

    (void)chdir(cwd);
    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void UnzipDlpFile001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }
    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);
    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR, S_IRWXU);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }
    DlpZipFile testFile2(fdDlp2, DLP_TEST_DIR, 1, "txt");
    initDlpFileCiper(testFile2);
    testFile2.ProcessDlpFile();
    int fdDlp3 = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp3 == -1) {
        close(fdPlain);
        close(fdDlp);
        close(fdDlp2);
        return;
    }
    std::string tmp = "abc";
    int32_t dlpRet = AddBuffToZip(tmp.c_str(), tmp.size(), "dlp_general_info",
        "/data/fuse_test_dlp.txt");
    dlpRet = AddBuffToZip(tmp.c_str(), tmp.size(), "dlp_cert",
        "/data/fuse_test_dlp.txt");
    testFile2.ProcessDlpFile();
    dlpRet = ftruncate(fdDlp3, ZERO);

    dlpRet = AddBuffToZip(tmp.c_str(), tmp.size(), "dlp_general_info",
        "/data/fuse_test_dlp.txt");
    testFile2.ProcessDlpFile();

    dlpRet = ftruncate(fdDlp3, ZERO);
    testFile2.ProcessDlpFile();
    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);
    close(fdDlp3);
    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void GenFileZip001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    DlpRawFile testFile2(fdDlp, "txt");
    initDlpFileCiper(testFile2);
    testFile2.contactAccount_ = "aa";
    testFile2.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void RemoveDlpPermissionZip001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);
    
    DlpRawFile testFile2(fdDlp, "txt");
    initDlpFileCiper(testFile2);
    testFile2.contactAccount_ = "aa";
    testFile2.GenFile(fdPlain);
    testFile2.head_.txtOffset = ZERO;
    testFile2.RemoveDlpPermissionInRaw(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile3(fdDlp, DLP_TEST_DIR, TWO, "txt");
    initDlpFileCiper(testFile3);
    testFile3.contactAccount_ = "aa";
    testFile3.GenFile(fdPlain);
    testFile3.RemoveDlpPermissionInZip(fdPlain);

    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void GenFileInZip001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenFile(fdPlain);

    DlpRawFile testFile2(fdDlp, "txt");
    initDlpFileCiper(testFile2);
    testFile2.contactAccount_ = "aa";
    testFile2.GenFile(fdPlain);

    int fdDlp2 = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp2 == -1) {
        close(fdPlain);
        close(fdDlp);
        return;
    }

    DlpZipFile testFile3(fdDlp, DLP_TEST_DIR, TWO, "txt");
    initDlpFileCiper(testFile3);
    testFile3.contactAccount_ = "aa";
    testFile3.GenFile(fdPlain);

    DlpRawFile testFile4(-1, "txt");
    initDlpFileCiper(testFile4);
    testFile4.contactAccount_ = "aa";
    testFile4.GenFile(-1);

    close(fdPlain);
    close(fdDlp);
    close(fdDlp2);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void GenEncData001()
{
    SetUp();
    int fdPlain = open("/data/fuse_test_plain.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdPlain == -1) {
        return;
    }
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        close(fdPlain);
        return;
    }

    DlpZipFile testFile(fdDlp, DLP_TEST_DIR, ZERO, "txt");
    initDlpFileCiper(testFile);
    testFile.contactAccount_ = "aa";
    testFile.GenEncData(-1);

    DlpZipFile testFile2(fdDlp, DLP_TEST_DIR, 1, "txt");
    initDlpFileCiper(testFile2);
    testFile2.contactAccount_ = "aa";
    testFile2.GenEncData(fdPlain) >= ZERO;
    (void)unlink(DLP_OPENING_ENC_DATA.c_str());

    close(fdPlain);
    close(fdDlp);

    unlink("/data/fuse_test_plain.txt");
    unlink("/data/fuse_test_dlp.txt");
}

void UpdateCertAndText001()
{
    SetUp();
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    std::vector<uint8_t> cert;
    std::string workDir = "";
    DlpBlob certBlob;

    testFile.UpdateCertAndText(cert, certBlob);

    close(fdDlp);
}

void GetOfflineAccess001()
{
    SetUp();
    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    testFile.GetOfflineAccess();

    close(fdDlp);
}

void GetOfflineCert001()
{
    SetUp();
    DlpBlob offlineCert = { ZERO };

    int fdDlp = open("/data/fuse_test_dlp.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    if (fdDlp == -1) {
        return;
    }
    DlpRawFile testFile(fdDlp, "txt");
    initDlpFileCiper(testFile);

    testFile.GetOfflineCert(offlineCert);

    close(fdDlp);
}

bool DlpFileNewFuzzTest(const uint8_t* data, size_t size)
{
    IsValidCipher001();
    CopyBlobParam001();
    CleanBlobParam001();
    GetLocalAccountName001();
    GetDomainAccountName001();
    UpdateDlpFilePermission001();
    UpdateDlpFilePermission002();
    UpdateDlpFilePermission003();
    UpdateDlpFilePermission004();
    UpdateDlpFilePermission005();
    UpdateDlpFilePermission006();
    SetCipher001();
    SetCipher002();
    SetCipher003();
    SetCipher004();
    SetContactAccount001();
    SetPolicy001();
    IsValidDlpHeader001();
    ParseDlpHeader001();
    ParseDlpHeader002();
    ParseDlpHeader003();
    ParseDlpHeader004();
    ParseDlpHeader005();
    ParseDlpHeader006();
    ParseDlpHeader007();
    SetEncryptCert001();
    SetEncryptCert002();
    SetEncryptCert003();
    DupUsageSpec001();
    DupUsageSpec002();
    DupUsageSpec003();
    DoDlpContentCopyOperation001(data, size);
    return true;
}

bool DlpFileNewFuzz2Test(const uint8_t* data, size_t size)
{
    DoDlpBlockCryptOperation001();
    DoDlpBlockCryptOperation002();
    DoDlpBlockCryptOperation003();
    DoDlpContentCryptyOperation001();
    DoDlpContentCryptyOperation002();
    DoDlpContentCryptyOperation003();
    GenFile001();
    GenFile002();
    RemoveDlpPermission001();
    DlpFileRead001();
    WriteFirstBlockData001();
    DoDlpFileWrite001();
    GetFsContentSize001();
    UpdateDlpFileContentSize001();
    FillHoleData001();
    DlpFileWrite001();
    Truncate001();
    CheckDlpFile001(data, size);
    NeedAdapter001();
    GenZipFile001();
    CleanTmpFile001();
    ParseDlpInfo001();
    ParseDlpInfo002();
    ParseCert001();
    ParseEncData001();
    UnzipDlpFile001();
    GenFileZip001();
    RemoveDlpPermissionZip001();
    GenFileInZip001();
    GenEncData001();
    UpdateCertAndText001();
    GetOfflineAccess001();
    GetOfflineCert001();
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(HUNDRED, "com.ohos.dlpmanager", ZERO); // user_id = HUNDRED
    SetSelfTokenID(tokenId);
    return ZERO;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DlpFileNewFuzzTest(data, size);
    OHOS::DlpFileNewFuzz2Test(data, size);
    return ZERO;
}