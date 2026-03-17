/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "parsedlpheader_fuzzer.h"
#include <dlfcn.h>
#include <iostream>
#include <fcntl.h>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "dlp_file.h"
#include "dlp_raw_file.h"
#include "dlp_zip_file.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef ssize_t (*WriteFuncT)(int fd, const void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count)
{
    WriteFuncT func = reinterpret_cast<WriteFuncT>(dlsym(RTLD_NEXT, "write"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(fd, buf, count);
}
#ifdef __cplusplus
}
#endif

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using namespace std;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
} // namespace

namespace OHOS {
static const uint32_t BUFFERSIZE = 40;
static uint32_t g_size = 0;
const int32_t ONE = 10;
const int32_t TWO = 20;
const int32_t HUNDRED = 100;

#define MAX_MALLOC_SIZE (1024 * 500) /* 500K */
static void *HcMalloc(uint32_t size, char val)
{
    if (size == 0 || size > MAX_MALLOC_SIZE) {
        return nullptr;
    }
    void *addr = malloc(size);
    if (addr != nullptr) {
        (void)memset_s(addr, size, val, size);
    }
    return addr;
}

static void HcFree(void *addr)
{
    if (addr != nullptr) {
        free(addr);
    }
}

static void PrepareFuzzTest(FuzzedDataProvider& fdp, int& fd, DlpRawFile& testFile,
    std::shared_ptr<DlpRawFile>& filePtr, vector<DlpBlob>& messages)
{
    fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);
    size_t innerSize = fdp.ConsumeIntegral<uint8_t>();
    if (innerSize == 0 || innerSize > g_size) {
        return;
    }
    uint32_t txtSize = fdp.ConsumeIntegral<uint32_t>();
    std::string workDir = fdp.ConsumeBytesAsString(innerSize - sizeof(int32_t));
    testFile = DlpRawFile(fd, "txt");
    filePtr = std::make_shared<DlpRawFile>(-1, "mp4");
    messages[0] = {0, nullptr};
    messages[1] = {0, nullptr};
    messages[0].size = innerSize;
    messages[0].data = static_cast<uint8_t *>(HcMalloc(innerSize, 0));
    messages[1].size = innerSize;
    messages[1].data = static_cast<uint8_t *>(HcMalloc(innerSize, 0));
    filePtr->ParseEnterpriseFileId(0, 0);
    filePtr->DoDlpHIAECryptOperation(messages[0], messages[1], 0, true);
    uint32_t certSize = txtSize;
    uint32_t contactAccountSize = txtSize;
    if (innerSize > ONE) {
        certSize = fdp.ConsumeIntegral<uint8_t>() % HUNDRED;
    }
    if (innerSize > TWO) {
        contactAccountSize = fdp.ConsumeIntegral<uint8_t>() % HUNDRED;
    }
    struct DlpHeader header = {
        .magic = DLP_FILE_MAGIC,
        .offlineAccess = 0,
        .txtOffset = sizeof(struct DlpHeader) + certSize + contactAccountSize,
        .txtSize = txtSize,
        .certOffset = sizeof(struct DlpHeader),
        .certSize = certSize,
        .contactAccountOffset = sizeof(struct DlpHeader) + contactAccountSize,
        .contactAccountSize = contactAccountSize,
        .offlineCertOffset = 0,
        .offlineCertSize = 0,
    };
    write(fd, &header, sizeof(header));
    uint8_t buffer[BUFFERSIZE] = {0};
    write(fd, buffer, BUFFERSIZE);
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    g_size = size;
    FuzzedDataProvider fdp(data, size);
    int fd = -1;
    DlpRawFile testFile(-1, "");
    std::shared_ptr<DlpRawFile> filePtr = nullptr;
    vector<DlpBlob> messages = {{0, nullptr}, {0, nullptr}};
    PrepareFuzzTest(fdp, fd, testFile, filePtr, messages);
    testFile.ProcessDlpFile();
    close(fd);
#ifndef SUPPORT_DLP_CREDENTIAL
#define SUPPORT_DLP_CREDENTIAL
    filePtr->DoDlpHIAECryptOperation(messages[0], messages[1], 1, true);
    filePtr->DoDlpHIAECryptOperation(messages[0], messages[1], 0, true);
#endif
    messages[0].size = fdp.ConsumeIntegral<uint32_t>();
    HcFree(messages[0].data);
    HcFree(messages[1].data);
}

bool ParseCertFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
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
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
