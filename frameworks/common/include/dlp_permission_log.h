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

#ifndef DLP_LOG_H
#define DLP_LOG_H

#ifdef HILOG_ENABLE

#include "hilog/log.h"

#ifndef __cplusplus

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD005A04

#define DLP_LOG_DEBUG(fmt, ...) HILOG_DEBUG(LOG_CORE, "[%{public}s:%{public}d]:" fmt, \
    __func__, __LINE__, ##__VA_ARGS__)
#define DLP_LOG_INFO(fmt, ...) HILOG_INFO(LOG_CORE, "[%{public}s:%{public}d]:" fmt, \
    __func__, __LINE__, ##__VA_ARGS__)
#define DLP_LOG_WARN(fmt, ...) HILOG_WARN(LOG_CORE, "[%{public}s:%{public}d]:" fmt, \
    __func__, __LINE__, ##__VA_ARGS__)
#define DLP_LOG_ERROR(fmt, ...) HILOG_ERROR(LOG_CORE, "[%{public}s:%{public}d]:" fmt, \
    __func__, __LINE__, ##__VA_ARGS__)
#define DLP_LOG_FATAL(fmt, ...) HILOG_FATAL(LOG_CORE, "[%{public}s:%{public}d]:" fmt, \
    __func__, __LINE__, ##__VA_ARGS__)

#else

static constexpr unsigned int SECURITY_DOMAIN_DLP_PERMISSION = 0xD005A04;

#define DLP_LOG_FATAL(label, fmt, ...)            \
    ((void)HILOG_IMPL(label.type, LOG_FATAL, label.domain, label.tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define DLP_LOG_ERROR(label, fmt, ...)            \
    ((void)HILOG_IMPL(label.type, LOG_ERROR, label.domain, label.tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define DLP_LOG_WARN(label, fmt, ...)            \
    ((void)HILOG_IMPL(label.type, LOG_WARN, label.domain, label.tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define DLP_LOG_INFO(label, fmt, ...)            \
    ((void)HILOG_IMPL(label.type, LOG_INFO, label.domain, label.tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#define DLP_LOG_DEBUG(label, fmt, ...)            \
    ((void)HILOG_IMPL(label.type, LOG_DEBUG, label.domain, label.tag, \
    "[%{public}s:%{public}d]" fmt, __FUNCTION__, __LINE__, ##__VA_ARGS__))
#endif  // __cplusplus

#else

#include <cstdio>

#undef LOG_TAG

#define DLP_LOG_DEBUG(fmt, ...) printf("[%s] debug: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define DLP_LOG_INFO(fmt, ...) printf("[%s] info: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define DLP_LOG_WARN(fmt, ...) printf("[%s] warn: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define DLP_LOG_ERROR(fmt, ...) printf("[%s] error: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)
#define DLP_LOG_FATAL(fmt, ...) printf("[%s] fatal: %s: " fmt "\n", LOG_TAG, __func__, ##__VA_ARGS__)

#endif  // HILOG_ENABLE

#endif  // DLP_LOG_H
