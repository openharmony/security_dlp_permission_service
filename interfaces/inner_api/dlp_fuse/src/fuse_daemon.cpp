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

#include "fuse_daemon.h"

#include <pthread.h>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "dlp_link_file.h"
#include "dlp_link_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "FuseDaemon"};
static constexpr int ROOT_INODE = 1;
static constexpr int DEFAULT_ATTR_TIMEOUT = 10000;
static constexpr int MAX_FILE_NAME_LEN = 256;
static constexpr int ROOT_INODE_ACCESS = 0711;
static constexpr uint32_t MAX_READ_DIR_BUF_SIZE = 100 * 1024;  // 100K
static constexpr const char* CUR_DIR = ".";
static constexpr const char* UPPER_DIR = "..";
static constexpr const char* THREAD_OS_DLP_FUSE = "OS_DLP_FUSE";
}  // namespace

std::condition_variable FuseDaemon::daemonEnableCv_;
enum DaemonStatus FuseDaemon::daemonStatus_;
std::mutex FuseDaemon::daemonEnableMtx_;
struct stat FuseDaemon::rootFileStat_;
bool FuseDaemon::init_ = false;

// caller need to check ino == ROOT_INODE
static DlpLinkFile* GetFileNode(fuse_ino_t ino)
{
    return reinterpret_cast<DlpLinkFile*>(static_cast<uintptr_t>(ino));
}

fuse_ino_t GetFileInode(DlpLinkFile* node)
{
    return static_cast<fuse_ino_t>(reinterpret_cast<uintptr_t>(node));
}

static void FuseDaemonLookup(fuse_req_t req, fuse_ino_t parent, const char* name)
{
    if (name == nullptr) {
        DLP_LOG_ERROR(LABEL, "Look up link file fail, name is null");
        fuse_reply_err(req, ENOENT);
        return;
    }
    DLP_LOG_DEBUG(LABEL, "Look up link file, name=%{private}s", name);

    if (parent != ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "Look up link file fail, parent is not root inode");
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct fuse_entry_param fep;
    (void)memset_s(&fep, sizeof(struct fuse_entry_param), 0, sizeof(struct fuse_entry_param));
    if (!strcmp(name, ".") || !strcmp(name, "..")) {
        fep.ino = ROOT_INODE;
        fep.attr = *(FuseDaemon::GetRootFileStat());
        fuse_reply_entry(req, &fep);
        return;
    }

    std::string nameStr = name;
    DlpLinkFile* node = DlpLinkManager::GetInstance().LookUpDlpLinkFile(nameStr);
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "Look up link file fail, file %{public}s can not found", name);
        fuse_reply_err(req, ENOENT);
    } else {
        DLP_LOG_DEBUG(LABEL, "Look up link file succ, file %{public}s found", name);
        fep.ino = GetFileInode(node);
        fep.attr = node->GetLinkStat();
        fuse_reply_entry(req, &fep);
    }
}

void UpdateCurrTimeStat(struct timespec* ts)
{
    clock_gettime(CLOCK_REALTIME, ts);
}

static void FuseDaemonGetattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    (void)fi;

    if (ino == ROOT_INODE) {
        struct stat* fileStat = FuseDaemon::GetRootFileStat();
        fuse_reply_attr(req, fileStat, DEFAULT_ATTR_TIMEOUT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "Get link file attr fail, wrong ino");
        fuse_reply_err(req, ENOENT);
        return;
    }

    struct stat fileStat = dlp->GetLinkStat();
    fuse_reply_attr(req, &fileStat, DEFAULT_ATTR_TIMEOUT);
}

// we will handle open flag later
static void FuseDaemonOpen(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info* fi)
{
    if (ino == ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "Open link file fail, can not open root dir");
        fuse_reply_err(req, ENOENT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "Open link file fail, wrong ino");
        fuse_reply_err(req, ENOENT);
        return;
    }
    if ((fi != nullptr) && (static_cast<uint32_t>(fi->flags) & O_TRUNC) != 0) {
        int32_t ret = dlp->Truncate(0);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Open link file with truncate fail, ret=%{public}d", ret);
            fuse_reply_err(req, EINVAL);
            return;
        }
        DLP_LOG_INFO(LABEL, "Open link file with truncate succ");
    }

    fuse_reply_open(req, fi);
    dlp->UpdateAtimeStat();
}

static DlpLinkFile* GetValidFileNode(fuse_req_t req, fuse_ino_t ino)
{
    if (ino == ROOT_INODE) {
        fuse_reply_err(req, ENOENT);
        return nullptr;
    }
    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        fuse_reply_err(req, EBADF);
        return nullptr;
    }
    return dlp;
}

static void FuseDaemonRead(fuse_req_t req, fuse_ino_t ino, size_t size, off_t offset, struct fuse_file_info* fi)
{
    (void)fi;
    if (offset < 0 || offset > DLP_MAX_CONTENT_SIZE) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    if (size > DLP_FUSE_MAX_BUFFLEN) {
        DLP_LOG_ERROR(LABEL, "Read link file fail, read size %{public}zu too large", size);
        fuse_reply_err(req, EINVAL);
        return;
    }
    DlpLinkFile* dlp = GetValidFileNode(req, ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read link file fail, wrong ino");
        return;
    }

    char* buf = reinterpret_cast<char*>(malloc(size));
    if (buf == nullptr) {
        DLP_LOG_ERROR(LABEL, "Read link file fail, malloc %{public}zu buff fail", size);
        fuse_reply_err(req, EINVAL);
        return;
    }
    (void)memset_s(buf, size, 0, size);

    int32_t res = dlp->Read(static_cast<uint32_t>(offset), buf, static_cast<uint32_t>(size));
    if (res < 0) {
        fuse_reply_err(req, EIO);
    } else {
        fuse_reply_buf(req, buf, static_cast<size_t>(res));
    }
    DLP_LOG_DEBUG(LABEL, "Read file name %{private}s offset %{public}u size %{public}u res %{public}d",
        dlp->GetLinkName().c_str(), static_cast<uint32_t>(offset), static_cast<uint32_t>(size), res);
    free(buf);
}

static void FuseDaemonWrite(
    fuse_req_t req, fuse_ino_t ino, const char* buf, size_t size, off_t off, struct fuse_file_info* fi)
{
    (void)fi;
    if (off < 0 || off > DLP_MAX_CONTENT_SIZE) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    if (size > DLP_FUSE_MAX_BUFFLEN) {
        DLP_LOG_ERROR(LABEL, "Write link file fail, write size %{public}zu too large", size);
        fuse_reply_err(req, EINVAL);
        return;
    }
    DlpLinkFile* dlp = GetValidFileNode(req, ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "Write link file fail, wrong ino");
        return;
    }
    int32_t res = dlp->Write(static_cast<uint32_t>(off),
        const_cast<void *>(static_cast<const void *>(buf)), static_cast<uint32_t>(size));
    if (res < 0) {
        fuse_reply_err(req, EIO);
    } else {
        fuse_reply_write(req, static_cast<size_t>(res));
    }
    DLP_LOG_DEBUG(LABEL, "Write file name %{private}s offset %{public}u size %{public}u res %{public}d",
        dlp->GetLinkName().c_str(), static_cast<uint32_t>(off), static_cast<uint32_t>(size), res);
}

static void FuseDaemonForget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
    if (ino == ROOT_INODE) {
        DLP_LOG_WARN(LABEL, "Forget root dir is forbidden");
        fuse_reply_err(req, ENOENT);
        return;
    }

    DlpLinkFile* dlp = GetFileNode(ino);
    if (dlp == nullptr) {
        DLP_LOG_ERROR(LABEL, "Forgot link file fail, wrong ino");
        fuse_reply_err(req, EBADF);
        return;
    }
    DLP_LOG_DEBUG(LABEL, "Forget link file name %{private}s nlookup %{public}u",
        dlp->GetLinkName().c_str(), static_cast<uint32_t>(nlookup));
    if (dlp->SubAndCheckZeroRef(nlookup)) {
        DLP_LOG_INFO(LABEL, "Link file reference is less than 0, delete link file ok");
        delete dlp;
    }
}

static int AddDirentry(DirAddParams& param)
{
    size_t shouldSize = fuse_add_direntry(param.req, nullptr, 0, param.entryName.c_str(), nullptr, 0);
    if (shouldSize > param.bufLen) {
        return -1;
    }
    param.curOff = param.nextOff;
    size_t addSize = fuse_add_direntry(param.req, param.directBuf, param.bufLen,
        param.entryName.c_str(), param.entryStat, param.curOff);
    param.directBuf += addSize;
    param.bufLen -= addSize;
    param.nextOff += static_cast<int>(addSize);
    return 0;
}

static int AddRootDirentry(DirAddParams& params)
{
    struct stat* rootStat = FuseDaemon::GetRootFileStat();
    params.entryName = CUR_DIR;
    params.entryStat = rootStat;

    if (AddDirentry(params) != 0) {
        fuse_reply_err(params.req, EINVAL);
        return -1;
    }

    params.entryName = UPPER_DIR;
    if (AddDirentry(params) != 0) {
        fuse_reply_err(params.req, EINVAL);
        return -1;
    }
    return 0;
}

static int AddLinkFilesDirentry(DirAddParams& params)
{
    std::vector<DlpLinkFileInfo> linkList;
    DlpLinkManager::GetInstance().DumpDlpLinkFile(linkList);
    int listSize = static_cast<int>(linkList.size());
    for (int i = 0; i < listSize; i++) {
        params.entryName = linkList[i].dlpLinkName;
        params.entryStat = &linkList[i].fileStat;
        if (AddDirentry(params) != 0) {
            fuse_reply_err(params.req, EINVAL);
            return -1;
        }
    }
    return 0;
}

static void FuseDaemonReadDir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    if (off < 0 || off > DLP_MAX_CONTENT_SIZE) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }

    if (ino != ROOT_INODE) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    if (size > MAX_READ_DIR_BUF_SIZE) {
        fuse_reply_err(req, EINVAL);
        return;
    }

    char* readBuf = reinterpret_cast<char*>(malloc(size));
    if (readBuf == nullptr) {
        fuse_reply_err(req, EFAULT);
        return;
    }
    (void)memset_s(readBuf, size, 0, size);

    struct DirAddParams params;
    params.req = req;
    params.directBuf = readBuf;
    params.bufLen = size;
    params.nextOff = 0;

    if (AddRootDirentry(params) != 0) {
        free(readBuf);
        return;
    }

    if (AddLinkFilesDirentry(params) != 0) {
        free(readBuf);
        return;
    }

    if (params.curOff <= off) {
        fuse_reply_buf(req, nullptr, 0);
    } else {
        fuse_reply_buf(req, readBuf + off, params.nextOff - off);
    }
    free(readBuf);
}

bool FuseDaemonUpdateTime(fuse_req_t req, int toSet, DlpLinkFile* dlpLink)
{
    DLP_LOG_DEBUG(LABEL, "Set link file update time, type %{public}d", toSet);
    bool isUpdateTime = false;
    struct stat fileStat = dlpLink->GetFileStat();
    if ((static_cast<uint32_t>(toSet) & FUSE_SET_ATTR_MTIME) != 0) {
        UpdateCurrTimeStat(&fileStat.st_mtim);
        isUpdateTime = true;
    }
    if ((static_cast<uint32_t>(toSet) & FUSE_SET_ATTR_CTIME) != 0) {
        UpdateCurrTimeStat(&fileStat.st_ctim);
        isUpdateTime = true;
    }
    if ((static_cast<uint32_t>(toSet) & FUSE_SET_ATTR_ATIME) != 0) {
        UpdateCurrTimeStat(&fileStat.st_atim);
        isUpdateTime = true;
    }
    if (isUpdateTime && (static_cast<uint32_t>(toSet) & FUSE_SET_ATTR_SIZE) == 0) {
        fuse_reply_attr(req, &fileStat, DEFAULT_ATTR_TIMEOUT);
        return false;
    }
    return true;
}

void FuseDaemonSetAttr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int toSet, struct fuse_file_info *fi)
{
    (void)fi;
    if (attr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, attr invalid");
        fuse_reply_err(req, EINVAL);
        return;
    }

    if (ino == ROOT_INODE) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, cannot set attr on root inode");
        fuse_reply_err(req, EACCES);
        return;
    }

    DlpLinkFile* dlpLink = GetFileNode(ino);
    if (dlpLink == nullptr) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, wrong ino");
        fuse_reply_err(req, ENOENT);
        return;
    }

    if (!FuseDaemonUpdateTime(req, toSet, dlpLink)) {
        return;
    }

    if ((static_cast<uint32_t>(toSet) & FUSE_SET_ATTR_SIZE) == 0) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, type %{public}d not support", toSet);
        fuse_reply_err(req, EACCES);
        return;
    }

    if (attr->st_size < 0 || attr->st_size > DLP_MAX_CONTENT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, file size too large");
        fuse_reply_err(req, EINVAL);
        return;
    }
    int32_t ret = dlpLink->Truncate(static_cast<uint32_t>(attr->st_size));
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Set link file attr fail, errno is %{public}d", ret);
        fuse_reply_err(req, EINVAL);
        return;
    }

    DLP_LOG_INFO(LABEL, "Set link file attr succ");
    struct stat fileStat = dlpLink->GetLinkStat();
    fuse_reply_attr(req, &fileStat, DEFAULT_ATTR_TIMEOUT);
}

static void FuseDaemonInit(void *userdata, struct fuse_conn_info *conn)
{
    (void)userdata;
    if (conn == nullptr) {
        DLP_LOG_ERROR(LABEL, "Fuse init, fuse conn info is null");
        return;
    }
    conn->want |= FUSE_CAP_WRITEBACK_CACHE;
}

struct fuse_lowlevel_ops FuseDaemon::fuseDaemonOper_ = {
    .init = FuseDaemonInit,
    .lookup = FuseDaemonLookup,
    .forget = FuseDaemonForget,
    .getattr = FuseDaemonGetattr,
    .setattr = FuseDaemonSetAttr,
    .open = FuseDaemonOpen,
    .read = FuseDaemonRead,
    .write = FuseDaemonWrite,
    .readdir = FuseDaemonReadDir,
};

struct stat* FuseDaemon::GetRootFileStat()
{
    return &FuseDaemon::rootFileStat_;
}

void FuseDaemon::InitRootFileStat(void)
{
    (void)memset_s(&rootFileStat_, sizeof(rootFileStat_), 0, sizeof(rootFileStat_));
    rootFileStat_.st_ino = ROOT_INODE;
    rootFileStat_.st_mode = S_IFDIR | ROOT_INODE_ACCESS;
    rootFileStat_.st_nlink = 1;
    rootFileStat_.st_uid = getuid();
    rootFileStat_.st_gid = getgid();
    UpdateCurrTimeStat(&rootFileStat_.st_atim);
    UpdateCurrTimeStat(&rootFileStat_.st_mtim);
    UpdateCurrTimeStat(&rootFileStat_.st_ctim);
}

void FuseDaemon::NotifyDaemonEnable(void)
{
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    daemonStatus_ = DAEMON_ENABLE;
    daemonEnableCv_.notify_all();
}

void FuseDaemon::NotifyDaemonDisable(void)
{
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    daemonStatus_ = DAEMON_DISABLE;
    daemonEnableCv_.notify_all();
}

int FuseDaemon::WaitDaemonEnable(void)
{
    DLP_LOG_INFO(LABEL, "Wait fuse fs daemon enable");
    std::unique_lock<std::mutex> lck(daemonEnableMtx_);
    if (daemonStatus_ == DAEMON_UNDEF) {
        daemonEnableCv_.wait_for(lck, std::chrono::seconds(1));
    }

    if (daemonStatus_ == DAEMON_ENABLE) {
        DLP_LOG_INFO(LABEL, "Wait fuse fs daemon enable succ");
        return 0;
    }

    DLP_LOG_INFO(LABEL, "Wait fuse fs daemon enable fail, time out");
    return -1;
}

void FuseDaemon::FuseFsDaemonThread(int fuseFd)
{
    struct stat fileStat;
    if (fstat(fuseFd, &fileStat) < 0) {
        DLP_LOG_ERROR(LABEL, "Fuse fs daemon exit, %{public}d is wrong fd, errno %{public}d", fuseFd, errno);
        NotifyDaemonDisable();
        return;
    }

    char mountPoint[MAX_FILE_NAME_LEN] = {0};
    int ret = snprintf_s(mountPoint, sizeof(mountPoint), MAX_FILE_NAME_LEN, "/dev/fd/%d", fuseFd);
    if (ret <= 0) {
        DLP_LOG_ERROR(LABEL, "Fuse fs daemon exit, snprintf_s fail");
        NotifyDaemonDisable();
        return;
    }

    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, mountPoint);

    struct fuse_session* se = fuse_session_new(&args, &fuseDaemonOper_, sizeof(fuseDaemonOper_), NULL);
    if (se == NULL) {
        DLP_LOG_ERROR(LABEL, "Fuse fs daemon exit, create fuse session fail");
        NotifyDaemonDisable();
        fuse_opt_free_args(&args);
        return;
    }

    if (fuse_session_mount(se, mountPoint) != 0) {
        DLP_LOG_ERROR(LABEL, "Fuse fs daemon exit, mount fuse session fail");
        NotifyDaemonDisable();
        fuse_session_destroy(se);
        fuse_opt_free_args(&args);
        return;
    }

    InitRootFileStat();
    NotifyDaemonEnable();

    if (fuse_session_loop(se) != 0) {
        DLP_LOG_ERROR(LABEL, "Fuse fs daemon exit, fuse session loop end");
    }

    fuse_session_destroy(se);
    fuse_opt_free_args(&args);
}

int FuseDaemon::InitFuseFs(int fuseDevFd)
{
    if (init_) {
        DLP_LOG_ERROR(LABEL, "Fuse fs has init already!");
        return -1;
    }
    init_ = true;

    if (fuseDevFd < 0) {
        DLP_LOG_ERROR(LABEL, "Init fuse fs fail: dev fd is error");
        return -1;
    }
    daemonStatus_ = DAEMON_UNDEF;

    std::thread daemonThread(FuseFsDaemonThread, fuseDevFd);
    pthread_setname_np(daemonThread.native_handle(), THREAD_OS_DLP_FUSE);
    daemonThread.detach();
    return WaitDaemonEnable();
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
