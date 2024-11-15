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
#include "dlp_link_manager.h"

#include "dlp_file.h"
#include "dlp_fuse_fd.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpLinkManager"};
static const int MAX_FILE_NAME_LEN = 256;
static constexpr uint32_t MAX_DLP_LINK_SIZE = 1000; // max open link file
std::mutex instanceMutex_;
}

DlpLinkManager::DlpLinkManager()
{
    FuseDaemon::InitFuseFs();
}

DlpLinkManager::~DlpLinkManager()
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end();) {
        DlpLinkFile* tmp = iter->second;
        if (tmp != nullptr) {
            iter = dlpLinkFileNameMap_.erase(iter);
            delete tmp;
        } else {
            iter++;
        }
    }
    CloseDlpFuseFd();
}

static bool IsLinkNameValid(const std::string& linkName)
{
    size_t size = linkName.size();
    return !(size == 0 || size > MAX_FILE_NAME_LEN);
}

int32_t DlpLinkManager::AddDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Add link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    if (!IsLinkNameValid(dlpLinkName)) {
        DLP_LOG_ERROR(LABEL, "Add link file fail, link file name %{public}s invalid", dlpLinkName.c_str());
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    if (dlpLinkFileNameMap_.size() >= MAX_DLP_LINK_SIZE) {
        DLP_LOG_ERROR(LABEL, "Add link file fail, too many links");
        return DLP_FUSE_ERROR_TOO_MANY_LINK_FILE;
    }

    auto iter = dlpLinkFileNameMap_.find(dlpLinkName);
    if (iter != dlpLinkFileNameMap_.end()) {
        DLP_LOG_ERROR(LABEL, "Add link file fail, link file %{public}s exist", dlpLinkName.c_str());
        return DLP_FUSE_ERROR_LINKFILE_EXIST;
    }

    for (auto it = dlpLinkFileNameMap_.begin(); it != dlpLinkFileNameMap_.end(); it++) {
        DlpLinkFile* linkFileNode = it->second;
        if ((linkFileNode != nullptr) && (filePtr == linkFileNode->GetDlpFilePtr())) {
            DLP_LOG_ERROR(LABEL, "Add link file fail, this dlp file already has link file");
            return DLP_FUSE_ERROR_LINKFILE_EXIST;
        }
    }

    DlpLinkFile *node = new (std::nothrow) DlpLinkFile(dlpLinkName, filePtr);
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "Add link file fail, alloc link file %{public}s fail", dlpLinkName.c_str());
        return DLP_FUSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    DLP_LOG_INFO(LABEL, "Add link file succ, file name %{public}s", dlpLinkName.c_str());
    dlpLinkFileNameMap_[dlpLinkName] = node;
    filePtr->SetLinkStatus();
    return DLP_OK;
}

int32_t DlpLinkManager::StopDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Stop link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); iter++) {
        DlpLinkFile* node = iter->second;
        if (node == nullptr) {
            DLP_LOG_ERROR(LABEL, "Stop link file fail, file ptr is null");
            return DLP_FUSE_ERROR_DLP_FILE_NULL;
        }
        if (filePtr == node->GetDlpFilePtr()) {
            node->stopLink();
            filePtr->RemoveLinkStatus();
            DLP_LOG_INFO(LABEL, "Stop link file success, file name %{public}s", node->GetLinkName().c_str());
            return DLP_OK;
        }
    }
    DLP_LOG_ERROR(LABEL, "Stop link file fail, link file not exist");
    return DLP_FUSE_ERROR_LINKFILE_NOT_EXIST;
}

int32_t DlpLinkManager::RestartDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Restart link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); iter++) {
        DlpLinkFile* node = iter->second;
        if (node == nullptr) {
            DLP_LOG_ERROR(LABEL, "Restart link file fail, file ptr is null");
            return DLP_FUSE_ERROR_DLP_FILE_NULL;
        }
        if (filePtr == node->GetDlpFilePtr()) {
            node->restartLink();
            filePtr->SetLinkStatus();
            DLP_LOG_INFO(LABEL, "Restart link file success, file name %{public}s", node->GetLinkName().c_str());
            return DLP_OK;
        }
    }
    DLP_LOG_ERROR(LABEL, "Restart link file fail, link file not exist");
    return DLP_FUSE_ERROR_LINKFILE_NOT_EXIST;
}

int32_t DlpLinkManager::ReplaceDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Replace link file fail, dlp file is null");
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }
    if (!IsLinkNameValid(dlpLinkName)) {
        DLP_LOG_ERROR(LABEL, "Replace link file fail, link file name %{public}s invalid", dlpLinkName.c_str());
        return DLP_FUSE_ERROR_VALUE_INVALID;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); iter++) {
        if (dlpLinkName == iter->first) {
            DlpLinkFile *node = iter->second;
            if (node == nullptr) {
                DLP_LOG_ERROR(
                    LABEL, "Replace link file fail, file %{public}s found but file ptr is null", dlpLinkName.c_str());
                return DLP_FUSE_ERROR_DLP_FILE_NULL;
            }
            node->setDlpFilePtr(filePtr);
            DLP_LOG_INFO(LABEL, "Replace link file success, file name %{public}s", dlpLinkName.c_str());
            return DLP_OK;
        }
    }
    DLP_LOG_ERROR(LABEL, "Replace link file fail, file %{public}s not exist", dlpLinkName.c_str());
    return DLP_FUSE_ERROR_LINKFILE_NOT_EXIST;
}

int32_t DlpLinkManager::DeleteDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        return DLP_FUSE_ERROR_DLP_FILE_NULL;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); iter++) {
        DlpLinkFile* tmp = iter->second;
        if (tmp != nullptr && filePtr == tmp->GetDlpFilePtr()) {
            filePtr->RemoveLinkStatus();
            dlpLinkFileNameMap_.erase(iter);
            if (tmp->SubAndCheckZeroRef(1)) {
                DLP_LOG_INFO(LABEL, "Delete link file %{private}s ok", tmp->GetLinkName().c_str());
                delete tmp;
            } else {
                DLP_LOG_INFO(LABEL, "Link file %{private}s is still referenced by kernel, only remove it from map",
                    tmp->GetLinkName().c_str());
            }
            return DLP_OK;
        }
    }
    DLP_LOG_ERROR(LABEL, "Delete link file fail, it does not exist.");
    return DLP_FUSE_ERROR_LINKFILE_NOT_EXIST;
}

DlpLinkFile* DlpLinkManager::LookUpDlpLinkFile(const std::string& dlpLinkName)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); ++iter) {
        if (dlpLinkName == iter->first) {
            DlpLinkFile* node = iter->second;
            if (node == nullptr) {
                DLP_LOG_ERROR(LABEL, "Look up link file fail, file %{public}s found but file ptr is null",
                    dlpLinkName.c_str());
                return nullptr;
            }
            node->IncreaseRef();
            return node;
        }
    }
    DLP_LOG_ERROR(LABEL, "Look up link file fail, file %{public}s not exist", dlpLinkName.c_str());
    return nullptr;
}

void DlpLinkManager::DumpDlpLinkFile(std::vector<DlpLinkFileInfo>& linkList)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(dlpLinkMapLock_);
    for (auto iter = dlpLinkFileNameMap_.begin(); iter != dlpLinkFileNameMap_.end(); iter++) {
        DlpLinkFile* filePtr = iter->second;
        if (filePtr == nullptr) {
            continue;
        }
        DlpLinkFileInfo info;
        info.dlpLinkName = filePtr->GetLinkName();
        info.fileStat = filePtr->GetLinkStat();
        linkList.emplace_back(info);
    }
}

DlpLinkManager& DlpLinkManager::GetInstance()
{
    static DlpLinkManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex_);
        if (instance == nullptr) {
            instance = new DlpLinkManager();
        }
    }
    return *instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
