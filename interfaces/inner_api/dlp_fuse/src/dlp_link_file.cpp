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

#include "dlp_link_file.h"

#include <securec.h>
#include "dlp_fuse_utils.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

#ifdef SECURITY_GUARD_ENABLE
#include <chrono>
#include "nlohmann/json.hpp"
#include "event_info.h"
#include "sg_collect_client.h"

extern "C" int GetDevUdid(char *udid, int size);
#endif

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpLinkFile"};
static const int DEFAULT_INODE_RO_ACCESS = 0440;
static const int DEFAULT_INODE_RW_ACCESS = 0640;
#ifdef SECURITY_GUARD_ENABLE
static const int64_t EVENTID = 0x00F000006;
static const std::string SGVERSION = "1";
#endif
} // namespace

DlpLinkFile::DlpLinkFile(const std::string& dlpLinkName, const std::shared_ptr<DlpFile>& dlpFile)
    : dlpLinkName_(dlpLinkName), dlpFile_(dlpFile), refcount_(1), stopLinkFlag_(false), hasRead_(false)
{
    (void)memset_s(&fileStat_, sizeof(fileStat_), 0, sizeof(fileStat_));
    fileStat_.st_ino = static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(this));
    if (dlpFile != nullptr) {
        uint32_t fileMode =
            (dlpFile->GetAuthPerm() == DLPFileAccess::READ_ONLY) ? DEFAULT_INODE_RO_ACCESS : DEFAULT_INODE_RW_ACCESS;
        fileStat_.st_mode = S_IFREG | fileMode;
    } else {
        fileStat_.st_mode = 0;
    }
    fileStat_.st_nlink = 1;
    fileStat_.st_uid = getuid();
    fileStat_.st_gid = getgid();

    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_atim);
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_mtim);
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_ctim);
}

DlpLinkFile::~DlpLinkFile()
{
}

bool DlpLinkFile::SubAndCheckZeroRef(int ref)
{
    if (ref <= 0) {
        DLP_LOG_WARN(LABEL, "Need sub reference %{public}d is error", ref);
        return false;
    }
    std::lock_guard<std::mutex> lock(refLock_);
    if (refcount_ < ref) {
        DLP_LOG_WARN(LABEL, "Need sub reference %{public}d is larger than refcount %{public}d",
            ref, static_cast<int>(refcount_));
        return false;
    }
    refcount_ -= ref;
    return (refcount_ <= 0);
}

bool DlpLinkFile::IncreaseRef()
{
    std::lock_guard<std::mutex> lock(refLock_);
    if (refcount_ <= 0) {
        DLP_LOG_WARN(LABEL, "refcount <= 0, can not increase");
        return false;
    }
    refcount_++;
    return true;
}

struct stat DlpLinkFile::GetLinkStat()
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Get link file stat fail, dlpFile is null");
        return fileStat_;
    }

    uint64_t res = dlpFile_->GetFsContentSize();
    if (res != INVALID_FILE_SIZE) {
        fileStat_.st_size = static_cast<off_t>(res);
    }
    return fileStat_;
}

int32_t DlpLinkFile::Truncate(uint64_t modifySize)
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    if (stopLinkFlag_) {
        DLP_LOG_INFO(LABEL, "linkFile is stopping link");
        return DLP_LINK_FILE_NOT_ALLOW_OPERATE;
    }

    if (modifySize >= DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Truncate fail, modify size %{public}s is invalid", std::to_string(modifySize).c_str());
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Truncate link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    int32_t res = dlpFile_->Truncate(modifySize);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Truncate %{public}s file fail, res=%{public}d", std::to_string(modifySize).c_str(), res);
    } else {
        DLP_LOG_INFO(LABEL, "Truncate %{public}s in link file succ", std::to_string(modifySize).c_str());
    }
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_mtim);
    return res;
}

void DlpLinkFile::UpdateAtimeStat()
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_atim);
}

void DlpLinkFile::UpdateMtimeStat()
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_mtim);
}

static int32_t ProcessWriteReport(std::shared_ptr<DlpFile> &filePtr, int32_t ret)
{
    int32_t res = DLP_OK;
#ifdef SECURITY_GUARD_ENABLE
    DLP_LOG_INFO(LABEL, "ProcessWriteReport begin!");
    const int32_t INPUT_UDID_LEN = 65;
    std::string udid = "UNKNOW";
    char *udidStr = reinterpret_cast<char*>(malloc(INPUT_UDID_LEN));
    if (udidStr != nullptr) {
        (void)memset_s(udidStr, INPUT_UDID_LEN, 0, INPUT_UDID_LEN);
        if (GetDevUdid(udidStr, INPUT_UDID_LEN) == 0) {
            udid = udidStr;
        }
        free(udidStr);
    }
    int64_t timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()
        .time_since_epoch()).count();
 
    nlohmann::json reportJson;
    std::string fileId;
    filePtr->GetFileId(fileId);
    reportJson["operation"] =  "DLP_FILE_WRITE";
    reportJson["status"] =  ret >= 0 ? "0" : "1";
    reportJson["deviceUDID"] =  udid;
    reportJson["fileIdentification"] =  fileId;
    reportJson["lastOperationId"] =  filePtr->GetEventId();
    reportJson["currOperationId"] =  "";
    reportJson["happenTime"] =  timeStamp;
 
    std::string context = reportJson.dump();
    std::shared_ptr<SecurityGuard::EventInfo> eventInfo =
        std::make_shared<SecurityGuard::EventInfo>(EVENTID, SGVERSION, context);
 
    res = OHOS::Security::SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    if (res == DLP_OK) {
        DLP_LOG_INFO(LABEL, "ReportSecurityInfo success");
    } else {
        DLP_LOG_ERROR(LABEL, "ReportSecurityInfo, fail: %{public}d", res);
    }
#endif
    return res;
}

int32_t DlpLinkFile::Write(uint64_t offset, void* buf, uint32_t size)
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    if (stopLinkFlag_) {
        DLP_LOG_INFO(LABEL, "linkFile is stopping link");
        return DLP_LINK_FILE_NOT_ALLOW_OPERATE;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Write link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    int32_t res = dlpFile_->DlpFileWrite(offset, buf, size);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Write link file fail, err=%{public}d.", res);
    }
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_mtim);
    if (res >= 0 && dlpFile_->GetAccountType() == ENTERPRISE_ACCOUNT) {
        ProcessWriteReport(dlpFile_, res);
    }
    return res;
}

int32_t DlpLinkFile::Read(uint64_t offset, void* buf, uint32_t size, uint32_t uid)
{
    std::unique_lock<std::shared_mutex> lock(linkRwMutex_);
    if (stopLinkFlag_) {
        DLP_LOG_INFO(LABEL, "linkFile is stopping link");
        return DLP_LINK_FILE_NOT_ALLOW_OPERATE;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_atim);
    bool localHasRead = hasRead_.load();
    int32_t res = dlpFile_->DlpFileRead(offset, buf, size, localHasRead, uid);
    if (localHasRead) {
        hasRead_.store(true);
    }
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Read link file failed, res %{public}d.", res);
    }
    return res;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
