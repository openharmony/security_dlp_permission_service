/*
 * Copyright (c) Huawei Device Co., Ltd. 2025-2025
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

#ifndef NAPI_DIA_LOG_ADAPTER_H
#define NAPI_DIA_LOG_ADAPTER_H
#define LOG_DOMAINID 0xD002F33

#include "hilog/log.h"

#ifdef __FILE_NAME__
#define LOG_FILE_NAME __FILE_NAME__
#else
#define LOG_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

constexpr OHOS::HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, LOG_DOMAINID, "IdentifySensitiveContentNapi"};

#define LOG_DEBUG(fmt, ...) \
    ((void)HILOG_IMPL(LOG_LABEL.type, LOG_DEBUG, LOG_LABEL.domain, LOG_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))

#define LOG_INFO(fmt, ...) \
    ((void)HILOG_IMPL(LOG_LABEL.type, LOG_INFO, LOG_LABEL.domain, LOG_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))

#define LOG_WARN(fmt, ...) \
    ((void)HILOG_IMPL(LOG_LABEL.type, LOG_WARN, LOG_LABEL.domain, LOG_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))

#define LOG_ERROR(fmt, ...) \
    ((void)HILOG_IMPL(LOG_LABEL.type, LOG_ERROR, LOG_LABEL.domain, LOG_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))

#define LOG_FATAL(fmt, ...) \
    ((void)HILOG_IMPL(LOG_LABEL.type, LOG_FATAL, LOG_LABEL.domain, LOG_LABEL.tag, \
    "[%{public}s@%{public}s:%{public}d] " fmt, __FUNCTION__, LOG_FILE_NAME, __LINE__, ##__VA_ARGS__))


#endif  // NAPI_DIA_LOG_ADAPTER_H
