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

#ifndef DLP_LINK_FILE_H
#define DLP_LINK_FILE_H

#include <mutex>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dlp_file.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
typedef struct DlpLinkFileInfo {
    std::string dlpLinkName;
    struct stat fileStat;
} DlpLinkFileInfo;

class DlpLinkFile final {
public:
    DlpLinkFile(std::string dlpLinkName, std::shared_ptr<DlpFile> dlpFile);
    ~DlpLinkFile();
    bool SubAndCheckZeroRef(int ref);
    void IncreaseRef();
    struct stat GetLinkStat();
    void UpdateAtimeStat();
    void UpdateMtimeStat();
    int32_t Write(uint32_t offset, void* buf, uint32_t size);
    int32_t Read(uint32_t offset, void* buf, uint32_t size, uint32_t uid);
    std::shared_ptr<DlpFile> GetDlpFilePtr()
    {
        return dlpFile_;
    };

    void setDlpFilePtr(std::shared_ptr<DlpFile> dlpFile)
    {
        dlpFile_ = dlpFile;
    };

    std::string& GetLinkName()
    {
        return dlpLinkName_;
    }

    int32_t Truncate(uint32_t modifySize);

    void stopLink()
    {
        stopLinkFlag_ = true;
    };

    void restartLink()
    {
        stopLinkFlag_ = false;
    };

    struct stat GetFileStat()
    {
        return fileStat_;
    };

private:
    std::string dlpLinkName_;
    std::shared_ptr<DlpFile> dlpFile_;
    struct stat fileStat_;
    std::atomic<int> refcount_;
    std::mutex refLock_;
    bool stopLinkFlag_;
    bool hasRead_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif
