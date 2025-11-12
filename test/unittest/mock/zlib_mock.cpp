/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "contrib/minizip/unzip.h"
#include "contrib/minizip/zip.h"
#include "contrib/minizip/ioapi.h"

#ifdef __cplusplus
extern "C" {
#endif

static const std::string ZLIB_PATH = "libshared_libz.z.so";

typedef int (*ZipWriteInFileInZipFuncT)(zipFile file, const void* buf, unsigned int len);
typedef int (*ZipCloseFileInZipFunT)(zipFile file);
typedef int (*ZipCloseFuncT)(zipFile file, const char* global_comment);
typedef zipFile (*ZipOpen64FuncT)(const void *pathname, int append);
typedef int (*ZipOpenNewFileInZip3_64)(zipFile file, const char *filename, const zip_fileinfo *zipfi,
                                        const void *extrafield_local, uInt size_extrafield_local,
                                        const void *extrafield_global, uInt size_extrafield_global,
                                        const char *comment, int method, int level, int raw,
                                        int windowBits, int memLevel, int strategy,
                                        const char *password, uLong crcForCrypting, int zip64);
typedef unzFile (*UnzOpen2FuncT)(const char *path, zlib_filefunc_def* pzlib_filefunc_def);
typedef int (*UnzGetGlobalInfo64FuncT)(unzFile file, unz_global_info64* pglobal_info);
typedef int (*UnzGetCurrentFileInfo64FuncT)(unzFile file,
                                            unz_file_info64* pfile_info,
                                            char* szFileName, uLong fileNameBufferSize,
                                            void* extraField, uLong extraFiledBufferSize,
                                            char* szComment, uLong commentBufferSize);
typedef int (*UnzGoToNextFileFuncT)(unzFile file);
typedef int (*UnzLocateFileFuncT)(unzFile file, const char *filename, int iCaseSensitivity);
typedef int (*UnzOpenCurrentFileFuncT)(unzFile file);
typedef int (*UnzReadCurrentFileFuncT)(unzFile file, void *buf, uint32_t size);
typedef int (*UnzCloseCurrentFileFuncT)(unzFile file);
typedef int (*UnzCloseFuncT)(zipFile file);

static void *g_ZlibHandle = nullptr;

static void *GetZibFunc(const char *funcName)
{
    if (g_ZlibHandle == nullptr) {
        g_ZlibHandle = dlopen(ZLIB_PATH.c_str(), RTLD_LAZY);
        if (g_ZlibHandle == nullptr) {
            return nullptr;
        }
    }

    return dlsym(g_ZlibHandle, funcName);
}

int zipWriteInFileInZip(zipFile file, const void* buf, unsigned int len)
{
    if (IsFuncNeedMock("zipWriteInFileInZip")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<ZipWriteInFileInZipFuncT>(rawFunc))(file, buf, len);
        }
        return -1;
    }

    ZipWriteInFileInZipFuncT func = 
        reinterpret_cast<ZipWriteInFileInZipFuncT>(GetZibFunc("zipWriteInFileInZip"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, buf, len);
}

int zipCloseFileInZip(zipFile file)
{
    if (IsFuncNeedMock("zipCloseFileInZip")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<ZipCloseFileInZipFunT>(rawFunc))(file);
        }
        return -1;
    }

    ZipCloseFileInZipFunT func = 
        reinterpret_cast<ZipCloseFileInZipFunT>(GetZibFunc("zipCloseFileInZip"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file);
}

int zipClose(zipFile file, const char* global_comment)
{
    if (IsFuncNeedMock("zipClose")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<ZipCloseFuncT>(rawFunc))(file, global_comment);
        }
        return -1;
    }

    ZipCloseFuncT func = 
        reinterpret_cast<ZipCloseFuncT>(GetZibFunc("zipClose"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, global_comment);
}

zipFile zipOpen64(const void *pathname, int append)
{
    if (IsFuncNeedMock("zipOpen64")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<ZipOpen64FuncT>(rawFunc))(pathname, append);
        }
        return nullptr;
    }

    ZipOpen64FuncT func = 
        reinterpret_cast<ZipOpen64FuncT>(GetZibFunc("zipOpen64"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)(pathname, append);
}

int zipOpenNewFileInZip3_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
                                        const void *extrafield_local, uInt size_extrafield_local,
                                        const void *extrafield_global, uInt size_extrafield_global,
                                        const char *comment, int method, int level, int raw,
                                        int windowBits, int memLevel, int strategy,
                                        const char *password, uLong crcForCrypting, int zip64)
{
    if (IsFuncNeedMock("zipOpenNewFileInZip3_64")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<ZipOpenNewFileInZip3_64>(rawFunc))(
                file, filename, zipfi, extrafield_local, size_extrafield_local,
                extrafield_global, size_extrafield_global, comment, method,
                level, raw, windowBits, memLevel, strategy, password, crcForCrypting, zip64);
        }
        return -1;
    }

    ZipOpenNewFileInZip3_64 func = 
        reinterpret_cast<ZipOpenNewFileInZip3_64>(GetZibFunc("zipOpenNewFileInZip3_64"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method,
        level, raw, windowBits, memLevel, strategy, password, crcForCrypting, zip64);
}

unzFile unzOpen2(const char *path, zlib_filefunc_def* pzlib_filefunc_def)
{
    if (IsFuncNeedMock("unzOpen2")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzOpen2FuncT>(rawFunc))(path, pzlib_filefunc_def);
        }
        return nullptr;
    }

    UnzOpen2FuncT func = 
        reinterpret_cast<UnzOpen2FuncT>(GetZibFunc("unzOpen2"));
    if (func == nullptr) {
        return nullptr;
    }
    return (*func)(path, pzlib_filefunc_def);
}

int unzGetGlobalInfo64(unzFile file, unz_global_info64* pglobal_info)
{
    if (IsFuncNeedMock("unzGetGlobalInfo64")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzGetGlobalInfo64FuncT>(rawFunc))(file, pglobal_info);
        }
        return -1;
    }

    UnzGetGlobalInfo64FuncT func = 
        reinterpret_cast<UnzGetGlobalInfo64FuncT>(GetZibFunc("unzGetGlobalInfo64"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, pglobal_info);
}

int unzGetCurrentFileInfo64(unzFile file,
                            unz_file_info64* pfile_info,
                            char* szFileName, uLong fileNameBufferSize,
                            void* extraField, uLong extraFiledBufferSize,
                            char* szComment, uLong commentBufferSize)
{
    if (IsFuncNeedMock("unzGetCurrentFileInfo64")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzGetCurrentFileInfo64FuncT>(rawFunc))(
                file, pfile_info, szFileName, fileNameBufferSize,
                extraField, extraFiledBufferSize, szComment, commentBufferSize);
        }
        return -1;
    }

    UnzGetCurrentFileInfo64FuncT func = 
        reinterpret_cast<UnzGetCurrentFileInfo64FuncT>(GetZibFunc("unzGetCurrentFileInfo64"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, pfile_info, szFileName, fileNameBufferSize,
        extraField, extraFiledBufferSize, szComment, commentBufferSize);
}

int unzGoToNextFile(unzFile file)
{
    if (IsFuncNeedMock("unzGoToNextFile")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzGoToNextFileFuncT>(rawFunc))(file);
        }
        return -1;
    }

    UnzGoToNextFileFuncT func = 
        reinterpret_cast<UnzGoToNextFileFuncT>(GetZibFunc("unzGoToNextFile"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file);
}

int unzLocateFile(unzFile file, const char *filename, int iCaseSensitivity)
{
    if (IsFuncNeedMock("unzLocateFile")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzLocateFileFuncT>(rawFunc))(file, filename, iCaseSensitivity);
        }
        return -1;
    }

    UnzLocateFileFuncT func = 
        reinterpret_cast<UnzLocateFileFuncT>(GetZibFunc("unzLocateFile"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, filename, iCaseSensitivity);
}

int unzOpenCurrentFile(unzFile file)
{
    if (IsFuncNeedMock("unzOpenCurrentFile")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzOpenCurrentFileFuncT>(rawFunc))(file);
        }
        return -1;
    }

    UnzOpenCurrentFileFuncT func = 
        reinterpret_cast<UnzOpenCurrentFileFuncT>(GetZibFunc("unzOpenCurrentFile"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file);
}

int unzReadCurrentFile(unzFile file, void *buf, uint32_t size)
{
    if (IsFuncNeedMock("unzReadCurrentFile")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzReadCurrentFileFuncT>(rawFunc))(file, buf, size);
        }
        return -1;
    }

    UnzReadCurrentFileFuncT func = 
        reinterpret_cast<UnzReadCurrentFileFuncT>(GetZibFunc("unzReadCurrentFile"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file, buf, size);
}

int unzCloseCurrentFile(unzFile file)
{
    if (IsFuncNeedMock("unzCloseCurrentFile")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzCloseCurrentFileFuncT>(rawFunc))(file);
        }
        return -1;
    }

    UnzCloseCurrentFileFuncT func = 
        reinterpret_cast<UnzCloseCurrentFileFuncT>(GetZibFunc("unzCloseCurrentFile"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file);
}

int unzClose(zipFile file)
{
    if (IsFuncNeedMock("unzClose")) {
        CommonMockFuncT rawFunc = GetMockFunc(__func__);
        if (rawFunc != nullptr) {
            return (*reinterpret_cast<UnzCloseFuncT>(rawFunc))(file);
        }
        return -1;
    }

    UnzCloseFuncT func = 
        reinterpret_cast<UnzCloseFuncT>(GetZibFunc("unzClose"));
    if (func == nullptr) {
        return -1;
    }
    return (*func)(file);
}
#ifdef __cplusplus
}
#endif
