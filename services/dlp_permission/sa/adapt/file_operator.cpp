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

#include "file_operator.h"
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "directory_ex.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "FileOperator" };
}
FileOperator::FileOperator() {}

FileOperator::~FileOperator() {}

int32_t FileOperator::InputFileByPathAndContent(const std::string& path, const std::string& content)
{
    std::string str = path;
    str.erase(str.rfind('/'));
    if (!IsExistDir(str)) {
        DLP_LOG_INFO(LABEL, "dir not exist, str = %{public}s errCode %{public}d.", str.c_str(), errno);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }

    char realPath[PATH_MAX] = {0};
    (void)realpath(str.c_str(), realPath);

    if (str.compare(realPath) != 0) {
        DLP_LOG_INFO(LABEL, "path need to be canonical, str %{public}s realPath %{public}s.", str.c_str(), realPath);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }

    FILE* fp = fopen(path.c_str(), "wb");
    if (fp == nullptr) {
        DLP_LOG_INFO(LABEL, "failed to open %{public}s, errno %{public}d.", path.c_str(), errno);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    size_t num = fwrite(content.c_str(), sizeof(char), content.length(), fp);
    if (num != content.length()) {
        DLP_LOG_INFO(LABEL, "failed to fwrite %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    if (fflush(fp) != 0) {
        DLP_LOG_INFO(LABEL, "failed to fflush %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    if (fsync(fileno(fp)) != 0) {
        DLP_LOG_INFO(LABEL, "failed to fsync %{public}s, errno %{public}d.", path.c_str(), errno);
        fclose(fp);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    fclose(fp);
    // change mode
    if (!ChangeModeFile(path, S_IRUSR | S_IWUSR)) {
        DLP_LOG_INFO(LABEL, "failed to change mode for file %{public}s, errno %{public}d.", path.c_str(), errno);
    }

    return DLP_OK;
}

int32_t FileOperator::GetFileContentByPath(const std::string& path, std::string& content)
{
    char realPath[PATH_MAX] = {0};
    if ((realpath(path.c_str(), realPath) == nullptr) && (errno != ENOENT)) {
        DLP_LOG_ERROR(LABEL, "Realpath %{private}s failed, %{public}s.", path.c_str(), strerror(errno));
        return DLP_RETENTION_FILE_FIND_FILE_ERROR;
    }
    if (!IsExistFile(realPath)) {
        DLP_LOG_INFO(LABEL, "cannot find file, path = %{public}s", realPath);
        return DLP_RETENTION_FILE_FIND_FILE_ERROR;
    }
    std::stringstream buffer;
    std::ifstream i(realPath);
    if (!i.is_open()) {
        DLP_LOG_INFO(LABEL, "cannot open file %{public}s, errno %{public}d.", realPath, errno);
        return DLP_RETENTION_COMMON_FILE_OPEN_FAILED;
    }
    buffer << i.rdbuf();
    content = buffer.str();
    i.close();
    return DLP_OK;
}

bool FileOperator::IsExistFile(const std::string& path)
{
    if (path.empty()) {
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        return false;
    }

    return S_ISREG(buf.st_mode);
}

bool FileOperator::IsExistDir(const std::string& path)
{
    if (path.empty()) {
        DLP_LOG_INFO(LABEL, "path.empty");
        return false;
    }

    struct stat buf = {};
    if (stat(path.c_str(), &buf) != 0) {
        DLP_LOG_INFO(LABEL, " errno %{public}d.", errno);
        return false;
    }

    return S_ISDIR(buf.st_mode);
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
