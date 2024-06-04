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

#include "dlp_zip.h"

#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "dlp_permission_log.h"

#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Defer = std::shared_ptr<void>;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileZip"};
const uint32_t ZIP_BUFF_SIZE = 1024;
const int32_t DLP_ZIP_FAIL = -1;
const int32_t DLP_ZIP_OK = 0;
const std::string DLP_GENERAL_INFO = "dlp_general_info";
}

int32_t AddBuffToZip(const void *buf, uint32_t size, const char *nameInZip, const char *zipName)
{
    if (buf == nullptr || zipName == nullptr) {
        DLP_LOG_ERROR(LABEL, "Buff or zipName is nullptr.");
        return DLP_ZIP_FAIL;
    }
    zipFile zf = zipOpen64(zipName, APPEND_STATUS_ADDINZIP);
    if (zf == nullptr) {
        DLP_LOG_ERROR(LABEL, "AddBuffToZip fail err %{public}d, zipName %{public}s",
            errno, zipName);
        return DLP_ZIP_FAIL;
    }
    int compressLevel = 0;
    zip_fileinfo zi = {};

    int32_t err = zipOpenNewFileInZip3_64(zf, nameInZip, &zi,
        NULL, 0, NULL, 0, NULL /* comment */,
        (compressLevel != 0) ? Z_DEFLATED : 0,
        compressLevel, 0,
        /* -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, */
        -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
        NULL, 0, 0);
    if (err != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "AddBuffToZip fail err %{public}d, nameInZip %{public}s", err, nameInZip);
        (void)zipClose(zf, NULL);
        return DLP_ZIP_FAIL;
    }
    int32_t res = DLP_ZIP_OK;
    err = zipWriteInFileInZip (zf, buf, (unsigned)size);
    if (err != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipWriteInFileInZip fail err %{public}d, %{public}s", err, nameInZip);
        res = DLP_ZIP_FAIL;
    }

    if (zipCloseFileInZip(zf) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipCloseFileInZip fail nameInZip %{public}s", nameInZip);
        res = DLP_ZIP_FAIL;
    }

    if (zipClose(zf, NULL) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipClose fail nameInZip %{public}s", nameInZip);
        return DLP_ZIP_FAIL;
    }

    return res;
}

int32_t AddFileContextToZip(int32_t fd, const char *nameInZip, const char *zipName)
{
    zipFile zf = zipOpen64(zipName, APPEND_STATUS_ADDINZIP);
    if (zf == nullptr) {
        DLP_LOG_ERROR(LABEL, "AddFileContextToZip fail err %{public}d, zipName %{public}s",
            errno, zipName);
        return DLP_ZIP_FAIL;
    }
    int32_t compressLevel = 0;
    zip_fileinfo zi = {};

    int32_t err = zipOpenNewFileInZip3_64(zf, nameInZip, &zi,
        NULL, 0, NULL, 0, NULL /* comment */,
        (compressLevel != 0) ? Z_DEFLATED : 0,
        compressLevel, 0,
        /* -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY, */
        -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY,
        NULL, 0, 0);
    if (err != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "create zip file fail err %{public}d, nameInZip %{public}s", err, nameInZip);
        zipClose(zf, NULL);
        return DLP_ZIP_FAIL;
    }
    int32_t readLen;
    int32_t res = DLP_ZIP_OK;
    auto buf = std::make_unique<char[]>(ZIP_BUFF_SIZE);
    while ((readLen = read(fd, buf.get(), ZIP_BUFF_SIZE)) > 0) {
        err = zipWriteInFileInZip (zf, buf.get(), (unsigned)readLen);
        if (err != ZIP_OK) {
            DLP_LOG_ERROR(LABEL, "zipWriteInFileInZip fail err %{public}d, %{public}s", err, nameInZip);
            res = DLP_ZIP_FAIL;
            break;
        }
    }

    if (readLen == -1) {
        DLP_LOG_ERROR(LABEL, "read errno %{public}s", strerror(errno));
        res = DLP_ZIP_FAIL;
    }

    if (zipCloseFileInZip(zf) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipCloseFileInZip fail nameInZip %{public}s", nameInZip);
        res = DLP_ZIP_FAIL;
    }

    if (zipClose(zf, NULL) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipClose fail nameInZip %{public}s", nameInZip);
        return DLP_ZIP_FAIL;
    }

    return res;
}

static void *FdOpenFileFunc(void *opaque, const char *filename, int mode)
{
    if ((opaque == nullptr) || (filename == nullptr)) {
        return nullptr;
    }
    FILE *file = nullptr;
    const char *modeFopen = nullptr;
    uint32_t modeInner = static_cast<uint32_t>(mode);
    if ((modeInner & ZLIB_FILEFUNC_MODE_READWRITEFILTER) == ZLIB_FILEFUNC_MODE_READ) {
        modeFopen = "rb";
    } else if (modeInner & ZLIB_FILEFUNC_MODE_EXISTING) {
        modeFopen = "r+b";
    } else if (modeInner & ZLIB_FILEFUNC_MODE_CREATE) {
        modeFopen = "wb";
    }
    if (modeFopen != nullptr) {
        int fd = dup(*static_cast<int *>(opaque));
        if (fd != -1) {
            file = fdopen(fd, modeFopen);
        }
    }

    return file;
}

static int FdCloseFileFunc(void *opaque, void *stream)
{
    if (fclose(static_cast<FILE *>(stream)) != 0) {
        DLP_LOG_ERROR(LABEL, "fclose fail errno %{public}d", errno);
    }
    free(opaque);  // malloc'ed in FillFdOpenFileFunc()
    return 0;
}

static void FillFdOpenFileFunc(zlib_filefunc_def *pzlibFilefuncDef, int fd)
{
    if (pzlibFilefuncDef == nullptr) {
        return;
    }
    fill_fopen_filefunc(pzlibFilefuncDef);
    pzlibFilefuncDef->zopen_file = FdOpenFileFunc;
    pzlibFilefuncDef->zclose_file = FdCloseFileFunc;
    int *ptrFd = static_cast<int *>(malloc(sizeof(fd)));
    if (ptrFd == nullptr) {
        free(ptrFd);
        return;
    }
    *ptrFd = fd;
    pzlibFilefuncDef->opaque = ptrFd;
}

static unzFile OpenFdForUnzipping(int zipFD)
{
    zlib_filefunc_def zipFuncs;
    FillFdOpenFileFunc(&zipFuncs, zipFD);
    return unzOpen2("fd", &zipFuncs);
}

static zipFile OpenZipFile(int fd)
{
    zipFile uf = OpenFdForUnzipping(fd);
    if (uf == nullptr) {
        DLP_LOG_ERROR(LABEL, "unzOpenFile fail errno %{public}d", errno);
        return nullptr;
    }
    return uf;
}

int32_t UnzipSpecificFile(int32_t fd, const char*nameInZip, const char *unZipName)
{
    zipFile uf;
    int32_t outFd = open(unZipName, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (outFd == -1) {
        DLP_LOG_ERROR(LABEL, "open fail %{public}s errno %{public}d", unZipName, errno);
        return DLP_ZIP_FAIL;
    }
    Defer p(nullptr, [&](...) {
        close(outFd);
    });

    uf = OpenZipFile(fd);
    if (uf == nullptr) {
        return DLP_ZIP_FAIL;
    }

    if (unzLocateFile(uf, nameInZip, 0) != UNZ_OK) {
        DLP_LOG_ERROR(LABEL, "unzLocateFile fail %{public}s errno %{public}d", nameInZip, errno);
        (void)unzClose(uf);
        return DLP_ZIP_FAIL;
    }

    int32_t err = unzOpenCurrentFile(uf);
    if (err != UNZ_OK) {
        DLP_LOG_ERROR(LABEL, "unzOpenCurrentFile fail %{public}s errno %{public}d", nameInZip, err);
        (void)unzClose(uf);
        return DLP_ZIP_FAIL;
    }

    int32_t readSize = 0;
    auto buf = std::make_unique<char[]>(ZIP_BUFF_SIZE);
    do {
        readSize = unzReadCurrentFile(uf, buf.get(), ZIP_BUFF_SIZE);
        int32_t writeSize = write(outFd, buf.get(), readSize);
        if (writeSize != readSize) {
            err = DLP_ZIP_FAIL;
            DLP_LOG_ERROR(LABEL, "write zip fail %{public}s errno %{public}d write %{public}d read %{public}d",
                nameInZip, errno, writeSize, readSize);
            break;
        }
    } while (readSize > 0);

    if (readSize < 0) {
        DLP_LOG_ERROR(LABEL, "unzReadCurrentFile fail %{public}s errno %{public}d", nameInZip, errno);
    }

    if (unzCloseCurrentFile(uf) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "unzCloseCurrentFile fail nameInZip %{public}s", nameInZip);
    }

    if (unzClose(uf) != ZIP_OK) {
        DLP_LOG_ERROR(LABEL, "zipClose fail nameInZip %{public}s", nameInZip);
        return DLP_ZIP_FAIL;
    }

    return err;
}

bool IsZipFile(int32_t fd)
{
    unzFile uz = OpenFdForUnzipping(fd);
    if (uz == nullptr) {
        DLP_LOG_ERROR(LABEL, "unzOpenFile fail, %{public}d", errno);
        return false;
    }

    if (unzLocateFile(uz, DLP_GENERAL_INFO.c_str(), 0) != UNZ_OK) {
        DLP_LOG_ERROR(LABEL, "unzLocateFile fail %{public}s errno %{public}d", DLP_GENERAL_INFO.c_str(), errno);
        (void)unzClose(uz);
        return false;
    }

    (void)unzClose(uz);
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
