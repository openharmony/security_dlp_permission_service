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

#include "dlp_file_kits.h"
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include "dlp_permission_log.h"
#include "dlp_zip.h"
#include "file_uri.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileKits"};
} // namespace
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

static const std::unordered_map<std::string, std::string> SUFFIX_MIMETYPE_MAP = {
    {"txt", "text/plain"},
    {"doc", "text/plain"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
};

static bool IsDlpFileName(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIX.size();
    uint32_t fileNameLen = dlpFileName.size();
    if (fileNameLen <= dlpSuffixLen) {
        return false;
    }

    if (dlpFileName.substr(fileNameLen - dlpSuffixLen, dlpSuffixLen) != DLP_FILE_SUFFIX) {
        return false;
    }
    return true;
}

static std::string GetDlpFileRealSuffix(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIX.size();
    std::string realFileName = dlpFileName.substr(0, dlpFileName.size() - dlpSuffixLen);
    char escape = '.';
    std::size_t escapeLocate = realFileName.find_last_of(escape);
    if (escapeLocate >= realFileName.size()) {
        DLP_LOG_ERROR(LABEL, "Get file suffix fail, no '.' in file name");
        return DEFAULT_STRING;
    }

    return realFileName.substr(escapeLocate + 1);
}

static std::string GetMimeTypeBySuffix(const std::string& suffix)
{
    auto iter = SUFFIX_MIMETYPE_MAP.find(suffix);
    if (iter != SUFFIX_MIMETYPE_MAP.end()) {
        return iter->second;
    }
    return DEFAULT_STRING;
}

static bool IsValidDlpHeader(const struct DlpHeader& head)
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE ||
        head.certOffset != sizeof(struct DlpHeader) ||
        head.contactAccountOffset != (sizeof(struct DlpHeader) + head.certSize) ||
        head.txtOffset != (sizeof(struct DlpHeader) + head.certSize + head.contactAccountSize + head.offlineCertSize) ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.offlineCertSize > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "parse dlp file header error.");
        return false;
    }
    return true;
}

bool DlpFileKits::IsDlpFile(int32_t dlpFd)
{
    if (dlpFd < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is invalid");
        return false;
    }

    if (IsZipFile(dlpFd)) {
        return true;
    }

    off_t curPos = lseek(dlpFd, 0, SEEK_CUR);
    if (curPos < 0) {
        DLP_LOG_ERROR(LABEL, "seek dlp file current failed, %{public}s", strerror(errno));
        return false;
    }

    if (lseek(dlpFd, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return false;
    }
    struct DlpHeader head;
    if (read(dlpFd, &head, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file head, %{public}s", strerror(errno));
        return false;
    }

    if (lseek(dlpFd, curPos, SEEK_SET) < 0) {
        DLP_LOG_ERROR(LABEL, "seek dlp file back failed, %{public}s", strerror(errno));
        return false;
    }

    return IsValidDlpHeader(head);
}

bool DlpFileKits::GetSandboxFlag(Want& want)
{
    std::string action = want.GetAction();
    if (action != TAG_ACTION_VIEW && action != TAG_ACTION_EDIT) {
        DLP_LOG_DEBUG(LABEL, "Action %{public}s is not dlp scene", action.c_str());
        return false;
    }

    std::string uri = want.GetUriString();
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string fileName = fileUri.GetName();
    if (fileName.empty() || !IsDlpFileName(fileName)) {
        DLP_LOG_DEBUG(LABEL, "File name is not exist or not dlp, name=%{private}s", fileName.c_str());
        return false;
    }
    std::string path = fileUri.GetRealPath();
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        DLP_LOG_ERROR(LABEL, "open file error, uri=%{private}s path=%{private}s error=%{public}d", uri.c_str(),
            path.c_str(), errno);
        return false;
    }
    if (!IsDlpFile(fd)) {
        DLP_LOG_WARN(LABEL, "Fd %{public}d is not dlp file", fd);
        close(fd);
        return false;
    }
    close(fd);
    std::string realSuffix = GetDlpFileRealSuffix(fileName);
    if (realSuffix != DEFAULT_STRING) {
        DLP_LOG_DEBUG(LABEL, "Real suffix is %{public}s", realSuffix.c_str());
        std::string realType = GetMimeTypeBySuffix(realSuffix);
        if (realType != DEFAULT_STRING) {
            want.SetType(realType);
        } else {
            DLP_LOG_INFO(LABEL, "Real suffix %{public}s not match known type, using origin type %{public}s",
                realSuffix.c_str(), want.GetType().c_str());
        }
    }
    DLP_LOG_INFO(LABEL, "Sanbox flag is true");
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
