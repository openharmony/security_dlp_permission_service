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
#include <fuse_lowlevel.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

static const std::string LIBFUSE_LIB_PATH = "libfuse.z.so";

typedef int (*AddArgsT)(struct fuse_args *args, const char *arg);
typedef void (*FreeArgsT)(struct fuse_args *args);
typedef struct fuse_session *(*NewSessionT)(struct fuse_args *args,
    const struct fuse_lowlevel_ops *op, size_t op_size, void *userdata);
typedef int (*MountSessionT)(struct fuse_session *se, const char *mountpoint);
typedef void (*DestorySessionT)(struct fuse_session *se);
typedef int (*LoopSessionT)(struct fuse_session *se);
typedef int (*FuseReplyErrT)(fuse_req_t req, int err);
typedef int (*FuseReplyEntryT)(fuse_req_t req, const struct fuse_entry_param *e);
typedef int (*FuseReplyAttrT)(fuse_req_t req, const struct stat *attr, double attr_timeout);
typedef int (*FuseReplyOpenT)(fuse_req_t req, const struct fuse_file_info *f);
typedef int (*FuseReplyBufT)(fuse_req_t req, const char *buf, size_t size);
typedef int (*FuseReplyWriteT)(fuse_req_t req, size_t count);
typedef size_t (*FuseAddDirentryT)(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off);

static void *g_libfuseHandle = nullptr;
static void *GetLibfuseLibFunc(const char *funcName)
{
    if (g_libfuseHandle == nullptr) {
        g_libfuseHandle = dlopen(LIBFUSE_LIB_PATH.c_str(), RTLD_LAZY);
        if (g_libfuseHandle == nullptr) {
            return nullptr;
        }
    }

    void *func = dlsym(g_libfuseHandle, funcName);
    return func;
}

int fuse_opt_add_arg(struct fuse_args *args, const char *arg)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<AddArgsT>(rawFunc))(args, arg);
        }
        return -1;
    }

    AddArgsT func = reinterpret_cast<AddArgsT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(args, arg);
}

void fuse_opt_free_args(struct fuse_args *args)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            (*reinterpret_cast<FreeArgsT>(rawFunc))(args);
        }
        return;
    }

    FreeArgsT func = reinterpret_cast<FreeArgsT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return;
    }
    (*func)(args);
}

struct fuse_session *fuse_session_new(struct fuse_args *args, const struct fuse_lowlevel_ops *op,
    size_t op_size, void *userdata)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<NewSessionT>(rawFunc))(args, op, op_size, userdata);
        }
        return nullptr;
    }
    NewSessionT func = reinterpret_cast<NewSessionT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)(args, op, op_size, userdata);
}

int fuse_session_mount(struct fuse_session *se, const char *mountpoint)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<MountSessionT>(rawFunc))(se, mountpoint);
        }
        return -1;
    }

    MountSessionT func = reinterpret_cast<MountSessionT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(se, mountpoint);
}

void fuse_session_destroy(struct fuse_session *se)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            (*reinterpret_cast<DestorySessionT>(rawFunc))(se);
        }
        return;
    }

    DestorySessionT func = reinterpret_cast<DestorySessionT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return;
    }
    (*func)(se);
}

int fuse_session_loop(struct fuse_session *se)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<LoopSessionT>(rawFunc))(se);
        }
        return -1;
    }

    LoopSessionT func = reinterpret_cast<LoopSessionT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(se);
}

int fuse_reply_err(fuse_req_t req, int err)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyErrT>(rawFunc))(req, err);
        }
        return -1;
    }

    FuseReplyErrT func = reinterpret_cast<FuseReplyErrT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, err);
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyEntryT>(rawFunc))(req, e);
        }
        return -1;
    }

    FuseReplyEntryT func = reinterpret_cast<FuseReplyEntryT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, e);
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double attr_timeout)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyAttrT>(rawFunc))(req, attr, attr_timeout);
        }
        return -1;
    }

    FuseReplyAttrT func = reinterpret_cast<FuseReplyAttrT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, attr, attr_timeout);
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyOpenT>(rawFunc))(req, f);
        }
        return -1;
    }

    FuseReplyOpenT func = reinterpret_cast<FuseReplyOpenT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, f);
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyBufT>(rawFunc))(req, buf, size);
        }
        return -1;
    }

    FuseReplyBufT func = reinterpret_cast<FuseReplyBufT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, buf, size);
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseReplyWriteT>(rawFunc))(req, count);
        }
        return -1;
    }

    FuseReplyWriteT func = reinterpret_cast<FuseReplyWriteT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(req, count);
}

size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize,
    const char *name, const struct stat *stbuf, off_t off)
{
    if (IsFuncNeedMock(__func__)) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<FuseAddDirentryT>(rawFunc))(req, buf, bufsize, name, stbuf, off);
        }
        return 0;
    }

    FuseAddDirentryT func = reinterpret_cast<FuseAddDirentryT>(GetLibfuseLibFunc(__func__));
    if (func == nullptr) {
        return 0;
    }
    return (*func)(req, buf, bufsize, name, stbuf, off);
}

#ifdef __cplusplus
}
#endif
