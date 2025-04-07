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

#ifndef DLP_IPC_INTERFACE_CODE_H
#define DLP_IPC_INTERFACE_CODE_H

/* SAID: 3521 */
namespace OHOS {
namespace Security {
namespace DlpPermission {
enum DlpPermissionCallbackInterfaceCode {
    ON_GENERATE_DLP_CERTIFICATE = 0,
    ON_PARSE_DLP_CERTIFICATE,
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_IPC_INTERFACE_CODE_H