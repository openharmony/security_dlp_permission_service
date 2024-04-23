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
#include <thread>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <unistd.h>
#include "accesstoken_kit.h"
#include "dlp_file.h"
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
namespace OHOS {
static const uint32_t BUFFERSIZE = 40;
const int32_t ONE = 1;
const int32_t TWO = 2;
const int32_t HUNDRED = 100;
static void FuzzTest(const uint8_t* data, size_t size)
{
    int fd = open("/data/fuse_test.txt", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU);

    DlpFile testFile(fd, "abc", 0, false);
    uint32_t txtSize = static_cast<uint32_t>(size) % HUNDRED;
    uint32_t certSize = txtSize;
    uint32_t contactAccountSize = txtSize;
    if (size > ONE) {
        certSize = data[0] % HUNDRED;
    }
    if (size > TWO) {
        contactAccountSize = data[ONE] % HUNDRED;
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
    testFile.ParseDlpHeader();
}

bool ParseCertFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
