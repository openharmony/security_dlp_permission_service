/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlp_utils.h"
#include <cctype>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <filesystem>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_permission_public_interface.h"
#include "dlp_file.h"
#include "dlp_zip.h"
#include "ipc_skeleton.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Defer = std::shared_ptr<void>;
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpUtils"};
static constexpr uint32_t MAX_DLP_FILE_SIZE = 1000;
static const std::string DLP_FILE_SUFFIXS = ".dlp";
static const std::string DEFAULT_STRINGS = "";
static const std::string PATH_SEPARATOR = "/";
static const std::string DESCRIPTOR_MAP_PATH = "/proc/self/fd/";
const std::string DLP_GENERAL_INFO = "dlp_general_info";
const std::string CACHE_PATH = "/data/storage/el2/base/files/cache/";
const uint32_t DLP_CWD_MAX = 256;
const uint32_t DLP_RAW_HEAD_OFFSET = 8;
std::mutex g_fileOpLock;
const int32_t FILEID_SIZE = 46;
const int32_t FILEID_SIZE_OPPOSITE = -46;
const int32_t FILEID_ALLOWEDOPEN_OPPOSITE = -54;
}


sptr<AppExecFwk::IBundleMgr> DlpUtils::GetBundleMgrProxy(void)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        DLP_LOG_ERROR(LABEL, "failed to get system ability manager");
        return nullptr;
    }

    sptr<IRemoteObject> remoteObj = systemAbilityManager->CheckSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObj == nullptr) {
        DLP_LOG_ERROR(LABEL, "Fail to connect bundle manager service.");
        return nullptr;
    }

    return iface_cast<AppExecFwk::IBundleMgr>(remoteObj);
}

bool DlpUtils::GetAuthPolicyWithType(const std::string &cfgFile, const std::string &type,
    std::vector<std::string> &authPolicy)
{
    std::string content;
    (void)FileOperator().GetFileContentByPath(cfgFile, content);
    if (content.empty()) {
        return false;
    }
    auto jsonObj = nlohmann::json::parse(content, nullptr, false);
    if (jsonObj.is_discarded() || (!jsonObj.is_object())) {
        DLP_LOG_WARN(LABEL, "JsonObj is discarded");
        return false;
    }
    auto result = jsonObj.find(type);
    if (result != jsonObj.end() && result->is_array() && !result->empty() && (*result)[0].is_string()) {
        authPolicy = result->get<std::vector<std::string>>();
    }
    if (authPolicy.size() != 0) {
        return true;
    }
    return false;
}

std::string DlpUtils::ToLowerString(const std::string& str)
{
    std::string lower;
    for (char c : str) {
        lower += std::tolower(c);
    }
    return lower;
}

std::string DlpUtils::GetFileTypeBySuffix(const std::string& suffix, const bool isFromUriName)
{
    std::string lower = DlpUtils::ToLowerString(suffix);
    if (isFromUriName) {
        for (size_t len = MAX_REALY_TYPE_LENGTH; len >= MIN_REALY_TYPE_LENGTH; len--) {
            if (len > lower.size()) {
                continue;
            }
            std::string newStr = lower.substr(0, len);
            auto iter = FILE_TYPE_MAP.find(newStr);
            if (iter != FILE_TYPE_MAP.end()) {
                return iter->second;
            }
        }
    } else {
        auto iter = FILE_TYPE_MAP.find(lower);
        if (iter != FILE_TYPE_MAP.end()) {
            return iter->second;
        }
    }
    return DEFAULT_STRINGS;
}

bool DlpUtils::GetFileType(const std::string& realFileType)
{
    std::string lower = DlpUtils::ToLowerString(realFileType);
    for (size_t len = MAX_REALY_TYPE_LENGTH; len >= MIN_REALY_TYPE_LENGTH; len--) {
        if (len > lower.size()) {
            continue;
        }
        std::string newStr = lower.substr(0, len);
        if (newStr == DLP_HIAE_TYPE) {
            DLP_LOG_DEBUG(LABEL, "the file supports the HIAE.");
            return true;
        }
    }
    return false;
}

std::string DlpUtils::GetDlpFileRealSuffix(const std::string& dlpFileName, bool& isFromUriName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIXS.size();
    if (dlpFileName.size() <= dlpSuffixLen) {
        DLP_LOG_ERROR(LABEL, "invalid fileName!");
        return DEFAULT_STRINGS;
    }
    std::string realFileName = dlpFileName.substr(0, dlpFileName.size() - dlpSuffixLen);
    char escape = '.';
    std::size_t escapeLocate = realFileName.find_last_of(escape);
    if (escapeLocate >= realFileName.size()) {
        DLP_LOG_ERROR(LABEL, "Get file suffix fail, no '.' in file name");
        return DEFAULT_STRINGS;
    }

    isFromUriName = true;
    return realFileName.substr(escapeLocate + 1);
}

int32_t DlpUtils::GetFilePathByFd(const int32_t &fd, std::string &filePath)
{
    char *fileName = new (std::nothrow) char[MAX_DLP_FILE_SIZE + 1];
    if (fileName == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)memset_s(fileName, MAX_DLP_FILE_SIZE + 1, 0, MAX_DLP_FILE_SIZE + 1);

    std::string path = DESCRIPTOR_MAP_PATH + std::to_string(fd);

    int readLinkRes = readlink(path.c_str(), fileName, MAX_DLP_FILE_SIZE);
    if (readLinkRes < 0) {
        DLP_LOG_ERROR(LABEL, "fail to readlink uri, errno = %{public}d", errno);
        delete[] fileName;
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    fileName[readLinkRes] = '\0';
    filePath = std::string(fileName);
    delete[] fileName;
    return DLP_OK;
}

int32_t DlpUtils::GetFileNameWithDlpFd(const int32_t &fd, std::string &srcFileName)
{
    std::string filePath;
    int res = DlpUtils::GetFilePathByFd(fd, filePath);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetFilePathByFd fail, err = %{public}d.", res);
        return res;
    }
    std::size_t pos = filePath.find_last_of(".");
    if (std::string::npos == pos) {
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    srcFileName = filePath.substr(0, pos);
    return DLP_OK;
}

int32_t DlpUtils::GetFileNameWithFd(const int32_t &fd, std::string &srcFileName)
{
    char *fileName = new (std::nothrow) char[MAX_DLP_FILE_SIZE + 1];
    if (fileName == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    (void)memset_s(fileName, MAX_DLP_FILE_SIZE + 1, 0, MAX_DLP_FILE_SIZE + 1);

    std::string path = DESCRIPTOR_MAP_PATH + std::to_string(fd);

    int readLinkRes = readlink(path.c_str(), fileName, MAX_DLP_FILE_SIZE);
    if (readLinkRes < 0) {
        DLP_LOG_ERROR(LABEL, "fail to readlink uri");
        delete[] fileName;
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    fileName[readLinkRes] = '\0';

    srcFileName = std::string(fileName);
    delete[] fileName;
    return DLP_OK;
}

int32_t DlpUtils::GetFilePathWithFd(const int32_t &fd, std::string &srcFilePath)
{
    std::string filePath;
    int res = DlpUtils::GetFilePathByFd(fd, filePath);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "GetFilePathByFd fail, err = %{public}d.", res);
        return res;
    }
    std::size_t pos = filePath.find_last_of(PATH_SEPARATOR);
    if (std::string::npos == pos) {
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    srcFilePath = filePath.substr(0, pos + 1);
    return DLP_OK;
}

static bool IsExistFile(const std::string& path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISREG(buf.st_mode);
}

static std::string GetFileContent(const std::string& path)
{
    if (!IsExistFile(path)) {
        DLP_LOG_DEBUG(LABEL, "cannot find file");
        return DEFAULT_STRINGS;
    }
    std::stringstream buffer;
    std::ifstream i(path);
    if (!i.is_open()) {
        DLP_LOG_DEBUG(LABEL, "cannot open file, errno %{public}d.", errno);
        return DEFAULT_STRINGS;
    }
    buffer << i.rdbuf();
    std::string content = buffer.str();
    i.close();
    return content;
}

static void RemoveCachePath(const std::string& path)
{
    if (remove(DLP_GENERAL_INFO.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "remove dlp_general_info file fail, error %{public}s", strerror(errno));
    }
    if (rmdir(path.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "remove cache path fail, error %{public}s", strerror(errno));
    }
}

static std::string GetGenerateInfoStr(const int32_t& fd)
{
    std::lock_guard<std::mutex> lock(g_fileOpLock);
    char cwd[DLP_CWD_MAX] = {0};
    if (getcwd(cwd, DLP_CWD_MAX) == nullptr) {
        DLP_LOG_ERROR(LABEL, "getcwd fail error %{public}s", strerror(errno));
        return DEFAULT_STRINGS;
    }
    Defer p(nullptr, [&](...) {
        if (chdir(cwd) != 0) {
            DLP_LOG_ERROR(LABEL, "chdir failed, %{public}s", strerror(errno));
        }
    });

    std::filesystem::path cachePath = CACHE_PATH;
    if (!std::filesystem::exists(cachePath) || !std::filesystem::is_directory(cachePath)) {
        if (mkdir(cachePath.c_str(), S_IRWXU) != 0) {
            DLP_LOG_ERROR(LABEL, "mkdir cache path failed, errorno is %{public}s", strerror(errno));
            return DEFAULT_STRINGS;
        }
    }

    int64_t timeStamp =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    std::string path = CACHE_PATH + std::to_string(timeStamp);
    if (mkdir(path.c_str(), S_IRWXU) != 0) {
        DLP_LOG_ERROR(LABEL, "mkdir timeStamp path failed, errorno is %{public}s", strerror(errno));
        return DEFAULT_STRINGS;
    }

    if (chdir(path.c_str()) != 0) {
        DLP_LOG_ERROR(LABEL, "chdir cache err, errno is %{public}d", errno);
        RemoveCachePath(path);
        return DEFAULT_STRINGS;
    }
    if (!CheckUnzipFileInfo(fd) ||
        UnzipSpecificFile(fd, DLP_GENERAL_INFO.c_str(), DLP_GENERAL_INFO.c_str()) != ZIP_OK) {
        RemoveCachePath(path);
        return DEFAULT_STRINGS;
    }

    std::string generateInfoStr = GetFileContent(DLP_GENERAL_INFO);
    RemoveCachePath(path);
    return generateInfoStr;
}

std::string DlpUtils::GetRealTypeWithRawFile(const int32_t& fd)
{
    if (lseek(fd, DLP_RAW_HEAD_OFFSET, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "file head is error: %{public}s", strerror(errno));
        return DEFAULT_STRINGS;
    }
    struct DlpHeader head;
    if (read(fd, &head, sizeof(head)) != sizeof(head)) {
        DLP_LOG_ERROR(LABEL, "can not read file head : %{public}s", strerror(errno));
        return DEFAULT_STRINGS;
    }
    auto iter = NUM_TO_TYPE_MAP.find(head.fileType);
    if (iter != NUM_TO_TYPE_MAP.end()) {
        return iter->second;
    }
    DLP_LOG_DEBUG(LABEL, "find file type of raw is error");
    return DEFAULT_STRINGS;
}

int32_t DlpUtils::GetRawFileAllowedOpenCount(const int32_t& fd, int32_t& allowedOpenCount)
{
    if (lseek(fd, FILEID_ALLOWEDOPEN_OPPOSITE, SEEK_END) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "get to allowedopen invalid");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    int32_t flag = 0;
    if (read(fd, &flag, sizeof(int32_t)) != sizeof(int32_t)) {
        DLP_LOG_ERROR(LABEL, "can not read flag, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    allowedOpenCount = 0;
    if (flag == 1) {
        if (read(fd, &allowedOpenCount, sizeof(int32_t)) != sizeof(int32_t)) {
            DLP_LOG_ERROR(LABEL, "can not read allowedOpenCount, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
        }
    }

    uint8_t *fileIdtmpBuf = new (std::nothrow)uint8_t[FILEID_SIZE];
    if (fileIdtmpBuf == nullptr) {
        DLP_LOG_ERROR(LABEL, "fileId memory operate fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    off_t fileLen = lseek(fd, FILEID_SIZE_OPPOSITE, SEEK_END);
    if (fileLen == static_cast<off_t>(-1)) {
        delete[] fileIdtmpBuf;
        DLP_LOG_ERROR(LABEL, "get fileid fileLen invalid, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (read(fd, fileIdtmpBuf, FILEID_SIZE) != FILEID_SIZE) {
        delete[] fileIdtmpBuf;
        DLP_LOG_ERROR(LABEL, "can not read fileId, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }
    if (fileIdtmpBuf[0] != 0 && flag == 0) {
        allowedOpenCount = 1;
    }
    delete[] fileIdtmpBuf;
    return DLP_OK;
}

std::string DlpUtils::GetRealTypeWithFd(const int32_t& fd, bool& isFromUriName, std::string& generateInfoStr,
    bool isEnterprise)
{
    std::string realType = DEFAULT_STRINGS;
    do {
        if (IsZipFile(fd)) {
            generateInfoStr = GetGenerateInfoStr(fd);
            if (generateInfoStr == DEFAULT_STRINGS) {
                break;
            }
            GenerateInfoParams params;
            if (ParseDlpGeneralInfo(generateInfoStr, params) != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "ParseDlpGeneralInfo error: %{public}s", generateInfoStr.c_str());
                break;
            }
            realType = params.realType;
        } else {
            if (!isEnterprise) {
                return GetRealTypeWithRawFile(fd);
            }
            realType = GetRealTypeWithRawFile(fd);
        }
    } while (0);

    if (realType.size() >= MIN_REALY_TYPE_LENGTH && realType.size() <= MAX_REALY_TYPE_LENGTH) {
        return realType;
    }
    DLP_LOG_DEBUG(LABEL, "not get real file type in dlp_general_info, will get to file name.");

    std::string fileName;
    if (DlpUtils::GetFileNameWithFd(fd, fileName) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get file name with fd error");
        return DEFAULT_STRINGS;
    }
    return DlpUtils::GetDlpFileRealSuffix(fileName, isFromUriName);
}

bool DlpUtils::GetBundleInfoWithBundleName(const std::string &bundleName, int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    return bundleMgrProxy->GetBundleInfo(bundleName, flag, bundleInfo, userId);
}

bool DlpUtils::GetAppIdFromToken(std::string &appId)
{
    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    int32_t ret = bundleMgrProxy->GetBundleInfoForSelf(static_cast<int32_t>(
        AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo);
    if (ret != DLP_OK || bundleInfo.appId.size() == 0) {
        DLP_LOG_ERROR(LABEL, "GetBundleInfoForSelf failed %{public}d", ret);
        return false;
    }
    appId = bundleInfo.appId;
    return true;
}

bool DlpUtils::GetUserIdByForegroundAccount(int32_t &userId)
{
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        DLP_LOG_ERROR(LABEL, "GetForegroundOsAccountLocalId failed %{public}d", ret);
        return false;
    }
    return true;
}

std::string DlpUtils::GetAppIdentifierByAppId(const std::string &appId, const int32_t &userId)
{
    auto bundleMgr = DlpUtils::GetBundleMgrProxy();
    if (bundleMgr == nullptr) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier not get bundleMgr.");
        return DEFAULT_STRINGS;
    }

    std::string bundleName = DEFAULT_STRINGS;
    int ret = bundleMgr->GetBundleNameByAppId(appId, bundleName);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "GetBundleNameByAppId failed to errCode %{public}d.", ret);
        return DEFAULT_STRINGS;
    }

    AppExecFwk::BundleInfo bundleInfo;
    ret = bundleMgr->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId);
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier failed to get bundle info for %{public}s due to errCode %{public}d.",
            bundleName.c_str(), ret);
        return DEFAULT_STRINGS;
    }
    if (bundleInfo.signatureInfo.appIdentifier.empty()) {
        DLP_LOG_ERROR(LABEL, "GetAppIdentifier not get appIdentifier.");
        return DEFAULT_STRINGS;
    }
    return bundleInfo.signatureInfo.appIdentifier;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
