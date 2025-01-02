/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "dlp_utils.h"
#include "dlp_permission.h"

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
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"dot", "application/msword"},
    {"dotx", "application/vnd.openxmlformats-officedocument.wordprocessingml.template"},
    {"odt", "application/vnd.oasis.opendocument.text"},
    {"pdf", "application/pdf"},
    {"pot", "application/vnd.ms-powerpoint"},
    {"potx", "application/vnd.openxmlformats-officedocument.presentationml.template"},
    {"pps", "application/vnd.ms-powerpoint"},
    {"ppsx", "application/vnd.openxmlformats-officedocument.presentationml.slideshow"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"rtf", "text/rtf"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"xlt", "application/vnd.ms-excel"},
    {"xltx", "application/vnd.openxmlformats-officedocument.spreadsheetml.template"},
    {"xlam", "application/vnd.ms-excel.addin.macroEnabled.12"},
    {"xlsb", "application/vnd.ms-excel.sheet.binary.macroEnabled.12"},
    {"xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12"},
    {"xltm", "application/vnd.ms-excel.template.macroEnabled.12"},
    {"xml", "text/xml"},
    {"ppam", "application/vnd.ms-powerpoint.addin.macroEnabled.12"},
    {"pptm", "application/vnd.ms-powerpoint.presentation.macroEnabled.12"},
    {"ppsm", "application/vnd.ms-powerpoint.slideshow.macroEnabled.12"},
    {"potm", "application/vnd.ms-powerpoint.template.macroEnabled.12"},
    {"docm", "application/vnd.ms-word.document.macroEnabled.12"},
    {"dotm", "application/vnd.ms-word.template.macroEnabled.12"},
    {"odp", "application/vnd.oasis.opendocument.presentation"},
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

static std::string GetMimeTypeBySuffix(const std::string& suffix)
{
    std::string lower = DlpUtils::ToLowerString(suffix);
    auto iter = SUFFIX_MIMETYPE_MAP.find(lower);
    if (iter != SUFFIX_MIMETYPE_MAP.end()) {
        return iter->second;
    }
    return DEFAULT_STRING;
}

static bool IsValidDlpHeader(const struct DlpHeader& head)
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE ||
        head.certOffset != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "Parse dlp file header error. certSize=%{public}u, contactAccountSize=%{public}u",
            head.certSize, head.contactAccountSize);
        return false;
    }
    if (head.contactAccountOffset != (sizeof(struct DlpHeader) + head.certSize) ||
        head.txtOffset != (sizeof(struct DlpHeader) + head.certSize + head.contactAccountSize + head.offlineCertSize) ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.offlineCertSize > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Parse dlp file header error.");
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
        return CheckUnzipFileInfo(dlpFd);
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
    fd = -1;
    std::string realSuffix = DlpUtils::GetDlpFileRealSuffix(fileName);
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

static int32_t ConvertAbilityInfoWithBundleName(const std::string &abilityName, const std::string &bundleName,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    Want want;
    AppExecFwk::ElementName name;
    name.SetAbilityName(abilityName);
    name.SetBundleName(bundleName);
    want.SetElement(name);

    int32_t flags = static_cast<int32_t>(AppExecFwk::GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT);
    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        DLP_LOG_ERROR(LABEL, "Get os account localId error, %{public}d", ret);
        return DLP_PARSE_ERROR_GET_ACCOUNT_FAIL;
    }

    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        return DLP_SERVICE_ERROR_IPC_REQUEST_FAIL;
    }
    ret = bundleMgrProxy->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    if (ret != ERR_OK) {
        DLP_LOG_ERROR(LABEL, "Get ability info error, %{public}d", ret);
        return DLP_PARSE_ERROR_BMS_ERROR;
    }
    return DLP_OK;
}

static bool IsSupportDlp(const std::vector<std::string> &whitelist,
    const std::string &bundleName, const std::string &fileType)
{
    auto it = std::find(whitelist.begin(), whitelist.end(), bundleName);
    if (it != whitelist.end()) {
        return true;
    }
    return false;
}

void DlpFileKits::ConvertAbilityInfoWithSupportDlp(const AAFwk::Want &want,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    if (abilityInfos.size() == 0) {
        DLP_LOG_INFO(LABEL, "ability size is zero.");
        return;
    }

    std::string uri = want.GetUriString();
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string fileName = fileUri.GetName();
    if (fileName.empty() || !IsDlpFileName(fileName)) {
        DLP_LOG_ERROR(LABEL, "File name is not exist or not dlp, name=%{private}s", fileName.c_str());
        return;
    }

    std::string realSuffix = DlpUtils::GetDlpFileRealSuffix(fileName);
    if (realSuffix == DEFAULT_STRING) {
        return;
    }
    std::string fileType = DlpUtils::GetFileTypeBySuffix(realSuffix);
    if (fileType == DEFAULT_STRING) {
        DLP_LOG_ERROR(LABEL, "%{public}s is not support dlp.", realSuffix.c_str());
        return;
    }
    std::vector<std::string> whitelist;
    if (!DlpUtils::GetWhitelistWithType(DLP_WHITELIST, fileType, whitelist)) {
        return;
    }

    for (auto it = abilityInfos.begin(); it != abilityInfos.end();) {
        if (!IsSupportDlp(whitelist, it->bundleName, fileType)) {
            abilityInfos.erase(it);
        } else {
            ++it;
        }
    }

    if (abilityInfos.size() != 0) {
        return;
    }
    std::vector<std::string> defalutWhitelist;
    if (!DlpUtils::GetWhitelistWithType(DLP_WHITELIST, DLP_DEFAULT_WHITELIST, defalutWhitelist) ||
        defalutWhitelist.size() <= 1) {
        return;
    }
    int32_t ret = ConvertAbilityInfoWithBundleName(defalutWhitelist[0], defalutWhitelist[1], abilityInfos);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Query ability info with bundleName error.");
    }
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
