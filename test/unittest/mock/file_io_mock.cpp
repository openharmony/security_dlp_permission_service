/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "c_mock_common.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef off_t (*LseekFuncT)(int fd, off_t offset, int whence);
typedef ssize_t (*WriteFuncT)(int fd, const void *buf, size_t count);
typedef int (*FtruncateFuncT)(int fd, off_t length);
typedef errno_t (*MemcpyFuncT)(void *dest, size_t destMax, const void *src, size_t count);

off_t lseek(int fd, off_t offset, int whence)
{
    if (IsFuncNeedMock("lseek")) {
        return -1;
    }

    LseekFuncT func = reinterpret_cast<LseekFuncT>(dlsym(RTLD_NEXT, "lseek"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(fd, offset, whence);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    if (IsFuncNeedMock("write")) {
        return -1;
    }

    WriteFuncT func = reinterpret_cast<WriteFuncT>(dlsym(RTLD_NEXT, "write"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(fd, buf, count);
}

int ftruncate(int fd, off_t length)
{
    if (IsFuncNeedMock("ftruncate")) {
        return -1;
    }

    FtruncateFuncT func = reinterpret_cast<FtruncateFuncT>(dlsym(RTLD_NEXT, "ftruncate"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(fd, length);
}


errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (IsFuncNeedMock("memcpy_s")) {
        return -1;
    }

    MemcpyFuncT func = reinterpret_cast<MemcpyFuncT>(dlsym(RTLD_NEXT, "memcpy_s"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(dest, destMax, src, count);
}
#ifdef __cplusplus
}
#endif
