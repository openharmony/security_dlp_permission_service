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

#ifndef DLP_LINK_MANAGER_H
#define DLP_LINK_MANAGER_H
#include <unordered_map>
#include <string>
#include "dlp_file.h"
#include "dlp_link_file.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

class DlpLinkManager final {
public:
    static DlpLinkManager* GetInstance();
    ~DlpLinkManager();

    int32_t AddDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName);
    int32_t StopDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr);
    int32_t RestartDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr);
    int32_t ReplaceDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName);
    int32_t DeleteDlpLinkFile(const std::shared_ptr<DlpFile>& filePtr);
    DlpLinkFile* LookUpDlpLinkFile(const std::string& dlpLinkName);
    void DumpDlpLinkFile(std::vector<DlpLinkFileInfo>& linkList);

private:
    DlpLinkManager();
    DISALLOW_COPY_AND_MOVE(DlpLinkManager);

    OHOS::Utils::RWLock dlpLinkMapLock_;
    std::unordered_map<std::string, DlpLinkFile*> dlpLinkFileNameMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif
