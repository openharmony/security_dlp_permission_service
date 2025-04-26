/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef INTERFACES_INNER_API_DLP_FILE_OPERATOR_H
#define INTERFACES_INNER_API_DLP_FILE_OPERATOR_H

#include <mutex>
#include <string>
#include "dlp_file.h"
#include "permission_policy.h"
namespace OHOS {
namespace Security {
namespace DlpPermission {

class EnterpriseSpaceDlpPermissionKit {
private:
    EnterpriseSpaceDlpPermissionKit();
    int32_t EnterpriseSpaceParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr, bool needCheckCustomProperty);
    int32_t EnterpriseSpacePrepareWorkDir(int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr, std::string& workDir);
    int32_t EnterpriseSpaceParseDlpFileProperty(std::shared_ptr<DlpFile>& filePtr, PermissionPolicy& policy,
        bool needCheckCustomProperty);
public:
    static EnterpriseSpaceDlpPermissionKit* GetInstance();
    ~EnterpriseSpaceDlpPermissionKit();
    int32_t EncryptDlpFile(DlpProperty property, CustomProperty customProperty, int32_t plainFileFd, int32_t dlpFileFd);
    int32_t DecryptDlpFile(int32_t plainFileFd, int32_t dlpFileFd);
    int32_t QueryDlpFileProperty(int32_t dlpFileFd, std::string &policyJsonString);
};

}
}
}

#endif