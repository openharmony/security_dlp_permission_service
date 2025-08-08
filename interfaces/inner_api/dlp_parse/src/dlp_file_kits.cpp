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
#include "dlp_file.h"
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
    static const std::string FILE_SCHEME_PREFIX = "file://";
    static const std::string DEFAULT_STRINGS = "";
    static const uint32_t BYTE_TO_HEX_OPER_LENGTH = 2;
    static const uint32_t CURRENT_VERSION = 3;
    static const uint32_t FILE_HEAD = 8;
    static const uint32_t HMAC_SIZE = 32;
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
    {"bmp", "image/bmp"},
    {"bm", "image/bmp"},
    {"dng", "image/x-adobe-dng"},
    {"gif", "image/gif"},
    {"heic", "image/heic"},
    {"heics", "image/heic"},
    {"heif", "image/heif"},
    {"heifs", "image/heif"},
    {"hif", "image/heif"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"jpe", "image/jpeg"},
    {"png", "image/png"},
    {"webp", "image/webp"},
    {"cur", "image/ico"},
    {"raf", "image/x-fuji-raf"},
    {"ico", "image/x-icon"},
    {"nrw", "image/x-nikon-nrw"},
    {"rw2", "image/x-panasonic-raw"},
    {"pef", "image/x-pentax-pef"},
    {"srw", "image/x-samsung-srw"},
    {"svg", "image/svg+xml"},
    {"arw", "image/x-sony-arw"},
    {"3gpp2", "video/3gpp2"},
    {"3gp2", "video/3gpp2"},
    {"3g2", "video/3gpp2"},
    {"3gpp", "video/3gpp"},
    {"3gp", "video/3gpp"},
    {"avi", "video/avi"},
    {"m4v", "video/mp4"},
    {"f4v", "video/mp4"},
    {"mp4v", "video/mp4"},
    {"mpeg4", "video/mp4"},
    {"mp4", "video/mp4"},
    {"m2ts", "video/mp2t"},
    {"mts", "video/mp2t"},
    {"ts", "video/mp2ts"},
    {"vt", "video/vnd.youtube.yt"},
    {"wrf", "video/x-webex"},
    {"mpeg", "video/mpeg"},
    {"mpeg2", "video/mpeg"},
    {"mpv2", "video/mpeg"},
    {"mp2v", "video/mpeg"},
    {"m2v", "video/mpeg"},
    {"m2t", "video/mpeg"},
    {"mpeg1", "video/mpeg"},
    {"mpv1", "video/mpeg"},
    {"mp1v", "video/mpeg"},
    {"m1v", "video/mpeg"},
    {"mpg", "video/mpeg"},
    {"mov", "video/quicktime"},
    {"mkv", "video/x-matroska"},
    {"webm", "video/webm"},
    {"h264", "video/H264"},
    {"wbmp", "image/vnd.wap.wbmp"},
    {"nef", "image/x-nikon-nef"},
    {"cr2", "image/x-canon-cr2"},
};

static bool IsDlpFileName(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIX.size();
    uint32_t fileNameLen = dlpFileName.size();
    if (fileNameLen < dlpSuffixLen) {
        return false;
    }

    std::string fileSuffix = dlpFileName.substr(fileNameLen - dlpSuffixLen, dlpSuffixLen);
    if (DlpUtils::ToLowerString(fileSuffix) != DLP_FILE_SUFFIX) {
        return false;
    }
    return true;
}

static std::string GetMimeTypeBySuffix(const std::string& suffix)
{
    std::string lower = DlpUtils::ToLowerString(suffix);
    for (size_t len = MAX_REALY_TYPE_LENGTH; len >= MIN_REALY_TYPE_LENGTH; len--) {
        if (len > lower.size()) {
            continue;
        }
        std::string newStr = lower.substr(0, len);
        auto iter = SUFFIX_MIMETYPE_MAP.find(newStr);
        if (iter != SUFFIX_MIMETYPE_MAP.end()) {
            return iter->second;
        }
    }
    return DEFAULT_STRING;
}

static bool IsValidDlpHeader(const struct DlpHeader& head)
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountOffset != sizeof(struct DlpHeader) + FILE_HEAD ||
        head.txtOffset != head.contactAccountOffset + head.contactAccountSize ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.hmacOffset != head.txtOffset + head.txtSize ||
        head.hmacSize != HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH || head.offlineCertSize > DLP_MAX_CERT_SIZE ||
        !(head.certOffset == head.txtOffset || head.certOffset == head.hmacOffset + head.hmacSize)) {
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

    uint32_t version = 0;
    if (read(dlpFd, &version, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read version, %{public}s", strerror(errno));
        return false;
    }

    uint32_t dlpHeaderSize = 0;
    if (read(dlpFd, &dlpHeaderSize, sizeof(uint32_t)) != sizeof(uint32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read dlpHeaderSize, %{public}s", strerror(errno));
        return false;
    }
    if (version != CURRENT_VERSION || dlpHeaderSize != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "version or dlpHeaderSize is error");
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
    if (!action.empty() && action != TAG_ACTION_VIEW && action != TAG_ACTION_EDIT) {
        DLP_LOG_DEBUG(LABEL, "Action %{public}s is not dlp scene", action.c_str());
        return false;
    }

    std::string uri = want.GetUriString();
    if (uri.find(FILE_SCHEME_PREFIX) != 0) {
        DLP_LOG_DEBUG(LABEL, "uri is missing file://");
        return false;
    }
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string fileName = fileUri.GetName();
    if (fileName.empty() || !IsDlpFileName(fileName)) {
        DLP_LOG_DEBUG(LABEL, "File name is not exist or not dlp, name=%{private}s", fileName.c_str());
        return false;
    }
    std::string path = fileUri.GetRealPath();
    int fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        DLP_LOG_ERROR(LABEL, "open file error, error=%{public}d", errno);
        return false;
    }
    if (!IsDlpFile(fd)) {
        DLP_LOG_WARN(LABEL, "Fd %{public}d is not dlp file", fd);
    }
    bool isFromUriName = false;
    std::string realSuffix = DlpUtils::GetRealTypeWithFd(fd, isFromUriName);
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
    close(fd);
    fd = -1;
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

static bool IsSupportDlp(const std::vector<std::string> &authPolicy, const std::string &bundleName)
{
    auto it = std::find(authPolicy.begin(), authPolicy.end(), bundleName);
    if (it != authPolicy.end()) {
        return true;
    }
    return false;
}

static std::string GetRealFileType(const AAFwk::Want &want)
{
    std::string uri = want.GetUriString();
    if (uri.find(FILE_SCHEME_PREFIX) != 0) {
        DLP_LOG_DEBUG(LABEL, "uri is missing file://");
        return DEFAULT_STRINGS;
    }
    AppFileService::ModuleFileUri::FileUri fileUri(uri);
    std::string fileName = fileUri.GetName();
    if (fileName.empty() || !IsDlpFileName(fileName)) {
        DLP_LOG_ERROR(LABEL, "File name is not exist or not dlp, name=%{private}s", fileName.c_str());
        return DEFAULT_STRINGS;
    }

    std::string realMimeType = want.GetType();
    if (realMimeType == DEFAULT_STRING) {
        DLP_LOG_ERROR(LABEL, "get real mime mype error.");
        return DEFAULT_STRINGS;
    }

    std::string realSuffix = DEFAULT_STRING;
    for (const auto& p : SUFFIX_MIMETYPE_MAP) {
        if (p.second == realMimeType) {
            realSuffix = p.first;
            break;
        }
    }
    std::string fileType = DlpUtils::GetFileTypeBySuffix(realSuffix, false);
    if (fileType == DEFAULT_STRING) {
        DLP_LOG_ERROR(LABEL, "%{public}s is not support dlp.", realSuffix.c_str());
    }
    return fileType;
}

void DlpFileKits::ConvertAbilityInfoWithSupportDlp(const AAFwk::Want &want,
    std::vector<AppExecFwk::AbilityInfo> &abilityInfos)
{
    std::string fileType = GetRealFileType(want);
    if (fileType == DEFAULT_STRING) {
        return;
    }

    std::vector<std::string> authPolicy;
    if (!DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, fileType, authPolicy)) {
        return;
    }

    for (auto it = abilityInfos.begin(); it != abilityInfos.end();) {
        if (!IsSupportDlp(authPolicy, it->bundleName)) {
            abilityInfos.erase(it);
        } else {
            ++it;
        }
    }

    if (abilityInfos.size() != 0) {
        return;
    }
    std::vector<std::string> defalutAuthPolicy;
    if (!DlpUtils::GetAuthPolicyWithType(DLP_AUTH_POLICY, DLP_DEFAULT_AUTH_POLICY, defalutAuthPolicy) ||
        defalutAuthPolicy.size() <= 1) {
        return;
    }
    int32_t ret = ConvertAbilityInfoWithBundleName(defalutAuthPolicy[0], defalutAuthPolicy[1], abilityInfos);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Query ability info with bundleName error.");
    }
}

bool DlpFileKits::IsDlpFileBySuffix(const std::string &fileSuffix)
{
    std::string lowerFileSuffix = DlpUtils::ToLowerString(fileSuffix);
    if (lowerFileSuffix != DLP_FILE_SUFFIX) {
        DLP_LOG_DEBUG(LABEL, "%{public}s is not dlp file suffix", lowerFileSuffix.c_str());
        return false;
    }
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
