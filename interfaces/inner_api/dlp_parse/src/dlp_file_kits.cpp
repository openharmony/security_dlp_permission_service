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
#include "dlp_permission_public_interface.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileKits"};
    static const std::string FILE_SCHEME_PREFIX = "file://";
    static const std::string DEFAULT_STRINGS = "";
    static const std::string DLP_TYPE = "dlp";
    static const uint32_t BYTE_TO_HEX_OPER_LENGTH = 2;
    static const uint32_t FILE_HEAD = 8;
    static const uint32_t HMAC_SIZE = 32;
    static const uint32_t ENTERPRISE_HEAD_MAX = 1024;

} // namespace
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

static const std::unordered_map<std::string, std::string> SUFFIX_MIMETYPE_MAP = {
    {"txt", "text/plain"},
    {"doc", "application/msword"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"pdf", "application/pdf"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"xls", "application/vnd.ms-excel"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"bmp", "image/jpeg"},
    {"bm", "image/jpeg"},
    {"dng", "image/jpeg"},
    {"gif", "image/jpeg"},
    {"heic", "image/jpeg"},
    {"heics", "image/jpeg"},
    {"heif", "image/jpeg"},
    {"heifs", "image/jpeg"},
    {"hif", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"jpeg", "image/jpeg"},
    {"jpe", "image/jpeg"},
    {"png", "image/jpeg"},
    {"webp", "image/jpeg"},
    {"cur", "image/jpeg"},
    {"raf", "image/jpeg"},
    {"ico", "image/jpeg"},
    {"nrw", "image/jpeg"},
    {"rw2", "image/jpeg"},
    {"pef", "image/jpeg"},
    {"srw", "image/jpeg"},
    {"svg", "image/jpeg"},
    {"arw", "image/jpeg"},
    {"3gpp2", "video/mp4"},
    {"3gp2", "video/mp4"},
    {"3g2", "video/mp4"},
    {"3gpp", "video/mp4"},
    {"3gp", "video/mp4"},
    {"avi", "video/mp4"},
    {"m4v", "video/mp4"},
    {"f4v", "video/mp4"},
    {"mp4v", "video/mp4"},
    {"mpeg4", "video/mp4"},
    {"mp4", "video/mp4"},
    {"m2ts", "video/mp4"},
    {"mts", "video/mp4"},
    {"ts", "video/mp4"},
    {"vt", "video/mp4"},
    {"wrf", "video/mp4"},
    {"mpeg", "video/mp4"},
    {"mpeg2", "video/mp4"},
    {"mpv2", "video/mp4"},
    {"mp2v", "video/mp4"},
    {"m2v", "video/mp4"},
    {"m2t", "video/mp4"},
    {"mpeg1", "video/mp4"},
    {"mpv1", "video/mp4"},
    {"mp1v", "video/mp4"},
    {"m1v", "video/mp4"},
    {"mpg", "video/mp4"},
    {"mov", "video/mp4"},
    {"mkv", "video/mp4"},
    {"webm", "video/mp4"},
    {"h264", "video/mp4"},
    {"wbmp", "image/jpeg"},
    {"nef", "image/jpeg"},
    {"cr2", "image/jpeg"},
    {"mp3", "audio/mp3"},
    {"flac", "audio/mp3"},
    {"m4a", "audio/mp3"},
    {"aac", "audio/mp3"},
    {"wav", "audio/mp3"},
    {"ogg", "audio/mp3"},
    {"amr", "audio/mp3"},
    {"m4b", "audio/mp3"},
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

static bool IsValidEnterpriseDlpHeader(const struct DlpHeader& head, uint32_t dlpHeaderSize)
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE ||
        head.contactAccountSize != 0 ||
        head.contactAccountOffset != dlpHeaderSize + FILE_HEAD ||
        head.txtOffset != head.contactAccountOffset + head.contactAccountSize ||
        head.txtSize > DLP_MAX_CONTENT_SIZE || head.hmacOffset != head.txtOffset + head.txtSize ||
        head.hmacSize != HMAC_SIZE * BYTE_TO_HEX_OPER_LENGTH || head.offlineCertSize > DLP_MAX_CERT_SIZE ||
        !(head.certOffset == head.txtOffset || head.certOffset == head.hmacOffset + head.hmacSize)) {
        DLP_LOG_ERROR(LABEL, "IsValidEnterpriseDlpHeader error.");
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
    if (version != CURRENT_VERSION || dlpHeaderSize < sizeof(struct DlpHeader) ||
        dlpHeaderSize > ENTERPRISE_HEAD_MAX) {
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

    return dlpHeaderSize == sizeof(struct DlpHeader) ? IsValidDlpHeader(head) :
        IsValidEnterpriseDlpHeader(head, dlpHeaderSize);
}

static bool GetIsReadOnce(const int32_t& fd, std::string& generateInfoStr)
{
    int32_t allowedOpenCount = 0;
    if (IsZipFile(fd)) {
        GenerateInfoParams params;
        if (ParseDlpGeneralInfo(generateInfoStr, params) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "ParseDlpGeneralInfo error: %{public}s", generateInfoStr.c_str());
            return false;
        }
        allowedOpenCount = params.allowedOpenCount;
    } else {
        int32_t res = DlpUtils::GetRawFileAllowedOpenCount(fd, allowedOpenCount);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "GetRawFileAllowedOpenCount error");
            return false;
        }
    }

    if (allowedOpenCount > 0) {
        DLP_LOG_INFO(LABEL, "allowedOpenCount is bigger than 0");
        return true;
    }
    return false;
}

static void SetWantType(Want& want, const int32_t& fd)
{
    bool isFromUriName = false;
    std::string generateInfoStr = DEFAULT_STRINGS;
    std::string realSuffix = DlpUtils::GetRealTypeWithFd(fd, isFromUriName, generateInfoStr);
    if (realSuffix != DEFAULT_STRING) {
        DLP_LOG_DEBUG(LABEL, "Real suffix is %{public}s", realSuffix.c_str());
        std::string realType = GetMimeTypeBySuffix(realSuffix);
        if (realType != DEFAULT_STRING) {
            want.SetType(realType);
        } else {
            DLP_LOG_INFO(LABEL, "Real suffix %{public}s not match known type, using origin type %{public}s",
                realSuffix.c_str(), want.GetType().c_str());
            want.SetType("image/jpeg");
        }
    } else {
        DLP_LOG_INFO(LABEL, "GetRealTypeWithFd empty");
        want.SetType("image/jpeg");
    }
    bool isReadOnce = GetIsReadOnce(fd, generateInfoStr);
    DLP_LOG_DEBUG(LABEL, "isReadOnce %{public}d", isReadOnce);
    if (isReadOnce) {
        want.SetType("image/jpeg");
    }
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
    SetWantType(want, fd);
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

void DlpFileKits::ConvertAbilityInfoWithSupportDlp(AAFwk::Want &want,
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
            it = abilityInfos.erase(it);
        } else {
            ++it;
        }
    }

    want.SetType(DLP_TYPE);

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
