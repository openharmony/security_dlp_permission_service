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

#ifndef FUSE_DAEMON_H
#define FUSE_DAEMON_H

#include <condition_variable>
#include <fuse_lowlevel.h>
#include <mutex>
#include <string>
#include "dlp_link_file.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
typedef struct DirAddParams {
    fuse_req_t req;
    char *directBuf;
    size_t bufLen;
    std::string entryName;
    struct stat* entryStat;
    off_t nextOff;
    off_t curOff;
} DirAddParams;

enum DaemonStatus {
    DAEMON_UNDEF,
    DAEMON_ENABLE,
    DAEMON_DISABLE,
};

fuse_ino_t GetFileInode(struct DlpFuseFileNode* node);
void UpdateCurrTimeStat(struct timespec* ts);
fuse_ino_t GetFileInode(DlpLinkFile* node);

class FuseDaemon {
public:
    static int InitFuseFs(int fuseDevFd);
    static struct stat* GetRootFileStat();
    static int WaitDaemonEnable(void);
    static void NotifyDaemonEnable(void);
    static void NotifyDaemonDisable(void);
    static void InitRootFileStat(void);
    static void FuseFsDaemonThread(int fuseFd);

    static std::condition_variable daemonEnableCv_;
    static enum DaemonStatus daemonStatus_;
    static std::mutex daemonEnableMtx_;
    static struct stat rootFileStat_;
    static bool init_;
    static struct fuse_lowlevel_ops fuseDaemonOper_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif
