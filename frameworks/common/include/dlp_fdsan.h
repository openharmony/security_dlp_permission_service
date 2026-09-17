/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 
#ifndef DLP_FDSAN_H
#define DLP_FDSAN_H
 
#include <cstdio>
 
#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0xD005A04
#endif
 
static const uint64_t DLP_FDSAN_OWNER_TAG = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN);
static inline void DlpFdsanMark(int fd)
{
    fdsan_exchange_owner_tag(fd, 0, DLP_FDSAN_OWNER_TAG);
}
static inline int DlpFdsanClose(int fd)
{
    return fdsan_close_with_tag(fd, DLP_FDSAN_OWNER_TAG);
}

#endif // DLP_FDSAN_H