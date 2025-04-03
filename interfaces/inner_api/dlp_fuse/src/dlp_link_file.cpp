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

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpLinkFile"};
static const int DEFAULT_INODE_RO_ACCESS = 0440;
static const int DEFAULT_INODE_RW_ACCESS = 0640;
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
        return true;
    }
    refcount_ -= ref;
    return (refcount_ <= 0);
}

void DlpLinkFile::IncreaseRef()
{
    std::lock_guard<std::mutex> lock(refLock_);
    if (refcount_ <= 0) {
        DLP_LOG_WARN(LABEL, "refcount <= 0, can not increase");
        return;
    }
    refcount_++;
}

struct stat DlpLinkFile::GetLinkStat()
{
    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Get link file stat fail, dlpFile is null");
        return fileStat_;
    }

    uint32_t res = dlpFile_->GetFsContentSize();
    if (res != INVALID_FILE_SIZE) {
        fileStat_.st_size = res;
    }
    return fileStat_;
}

int32_t DlpLinkFile::Truncate(uint32_t modifySize)
{
    if (stopLinkFlag_) {
        DLP_LOG_INFO(LABEL, "linkFile is stopping link");
        return DLP_LINK_FILE_NOT_ALLOW_OPERATE;
    }

    if (modifySize >= DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Truncate link file fail, modify size %{public}u is invalid", modifySize);
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Truncate link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    int32_t res = dlpFile_->Truncate(modifySize);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Truncate %{public}u in link file fail, res=%{public}d", modifySize, res);
    } else {
        DLP_LOG_INFO(LABEL, "Truncate %{public}u in link file succ", modifySize);
    }
    UpdateMtimeStat();
    return res;
}

void DlpLinkFile::UpdateAtimeStat()
{
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_atim);
}

void DlpLinkFile::UpdateMtimeStat()
{
    DlpFuseUtils::UpdateCurrTimeStat(&fileStat_.st_mtim);
}

int32_t DlpLinkFile::Write(uint32_t offset, void* buf, uint32_t size)
{
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
    UpdateMtimeStat();
    return res;
}

int32_t DlpLinkFile::Read(uint32_t offset, void* buf, uint32_t size, uint32_t uid)
{
    if (stopLinkFlag_) {
        DLP_LOG_INFO(LABEL, "linkFile is stopping link");
        return DLP_LINK_FILE_NOT_ALLOW_OPERATE;
    }

    if (dlpFile_ == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    UpdateAtimeStat();
    int32_t res = dlpFile_->DlpFileRead(offset, buf, size, hasRead_, uid);
    if (res < 0) {
        DLP_LOG_ERROR(LABEL, "Read link file failed, res %{public}d.", res);
    }
    return res;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
