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
enum DlpPermissionServiceInterfaceCode {
    GENERATE_DLP_CERTIFICATE = 0,
    PARSE_DLP_CERTIFICATE,
    INSTALL_DLP_SANDBOX,
    UNINSTALL_DLP_SANDBOX,
    GET_SANDBOX_EXTERNAL_AUTH,
    QUERY_DLP_FILE_ACCESS,
    IS_IN_DLP_SANDBOX,
    GET_DLP_SUPPORT_FILE_TYPE,
    QUERY_DLP_FILE_ACCESS_BY_TOKEN_ID,
    REGISTER_DLP_SANDBOX_CHANGE_CALLBACK,
    UNREGISTER_DLP_SANDBOX_CHANGE_CALLBACK,
    GET_DLP_GATHERING_POLICY,
    SET_RETENTION_STATE,
    SET_NOT_RETENTION_STATE,
    GET_RETENTION_SANDBOX_LIST,
    CLEAR_UNRESERVED_SANDBOX,
    GET_VISTI_FILE_RECORD_LIST,
    REGISTER_OPEN_DLP_FILE_CALLBACK,
    UN_REGISTER_OPEN_DLP_FILE_CALLBACK,
    SET_MDM_POLICY,
    GET_MDM_POLICY,
    REMOVE_MDM_POLICY,
    SET_SANDBOX_APP_CONFIG,
    CLEAN_SANDBOX_APP_CONFIG,
    GET_SANDBOX_APP_CONFIG,
    IS_DLP_FEATURE_PROVIDED,
};

enum DlpPermissionCallbackInterfaceCode {
    ON_GENERATE_DLP_CERTIFICATE = 0,
    ON_PARSE_DLP_CERTIFICATE,
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_IPC_INTERFACE_CODE_H