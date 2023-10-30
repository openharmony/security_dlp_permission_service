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

#ifndef INTERFACES_INNER_API_DLP_ZIP_H
#define INTERFACES_INNER_API_DLP_ZIP_H

#include "contrib/minizip/unzip.h"
#include "contrib/minizip/zip.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
    int32_t AddBuffToZip(const void *buf, uint32_t size, const char *nameInZip, const char *zipName);
    int32_t AddFileContextToZip(int32_t fd, const char *nameInZip, const char *zipName);
    int32_t UnzipSpecificFile(int32_t fd, const char *nameInZip, const char *unZipName);
    bool IsZipFile(int32_t fd);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_FILE_H */
