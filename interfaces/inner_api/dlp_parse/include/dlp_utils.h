/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_DLP_UTILS_H
#define INTERFACES_INNER_API_DLP_UTILS_H

#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "file_operator.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

static const std::string DLP_AUTH_POLICY = "/system/etc/dlp_auth_policy.json";
static const std::string DLP_DEFAULT_AUTH_POLICY = "default";
static const uint32_t MIN_REALY_TYPE_LENGTH = 2;
static const uint32_t MAX_REALY_TYPE_LENGTH = 5;

static const std::unordered_map<std::string, std::string> FILE_TYPE_MAP = {
    {"txt", "support_txt_dlp"},
    {"pdf", "support_pdf_dlp"},
    {"doc", "support_office_dlp"},
    {"docx", "support_office_dlp"},
    {"ppt", "support_office_dlp"},
    {"pptx", "support_office_dlp"},
    {"xls", "support_office_dlp"},
    {"xlsx", "support_office_dlp"},
    {"bmp", "support_photo_dlp"},
    {"bm", "support_photo_dlp"},
    {"dng", "support_photo_dlp"},
    {"gif", "support_photo_dlp"},
    {"heic", "support_photo_dlp"},
    {"heics", "support_photo_dlp"},
    {"heif", "support_photo_dlp"},
    {"heifs", "support_photo_dlp"},
    {"hif", "support_photo_dlp"},
    {"jpg", "support_photo_dlp"},
    {"jpeg", "support_photo_dlp"},
    {"jpe", "support_photo_dlp"},
    {"png", "support_photo_dlp"},
    {"webp", "support_photo_dlp"},
    {"cur", "support_photo_dlp"},
    {"raf", "support_photo_dlp"},
    {"ico", "support_photo_dlp"},
    {"nrw", "support_photo_dlp"},
    {"rw2", "support_photo_dlp"},
    {"pef", "support_photo_dlp"},
    {"srw", "support_photo_dlp"},
    {"svg", "support_photo_dlp"},
    {"arw", "support_photo_dlp"},
    {"3gpp2", "support_video_dlp"},
    {"3gp2", "support_video_dlp"},
    {"3g2", "support_video_dlp"},
    {"3gpp", "support_video_dlp"},
    {"3gp", "support_video_dlp"},
    {"avi", "support_video_dlp"},
    {"m4v", "support_video_dlp"},
    {"f4v", "support_video_dlp"},
    {"mp4v", "support_video_dlp"},
    {"mpeg4", "support_video_dlp"},
    {"mp4", "support_video_dlp"},
    {"m2ts", "support_video_dlp"},
    {"mts", "support_video_dlp"},
    {"ts", "support_video_dlp"},
    {"vt", "support_video_dlp"},
    {"wrf", "support_video_dlp"},
    {"mpeg", "support_video_dlp"},
    {"mpeg2", "support_video_dlp"},
    {"mpv2", "support_video_dlp"},
    {"mp2v", "support_video_dlp"},
    {"m2v", "support_video_dlp"},
    {"m2t", "support_video_dlp"},
    {"mpeg1", "support_video_dlp"},
    {"mpv1", "support_video_dlp"},
    {"mp1v", "support_video_dlp"},
    {"m1v", "support_video_dlp"},
    {"mpg", "support_video_dlp"},
    {"mov", "support_video_dlp"},
    {"mkv", "support_video_dlp"},
    {"webm", "support_video_dlp"},
    {"h264", "support_video_dlp"},
};

class DlpUtils {
public:
    static sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy(void);
    static bool GetAuthPolicyWithType(const std::string &cfgFile, const std::string &type,
        std::vector<std::string> &authPolicy);
    static std::string GetFileTypeBySuffix(const std::string& suffix);
    static std::string GetDlpFileRealSuffix(const std::string& dlpFileName);
    static int32_t GetFileNameWithFd(const int32_t& fd, std::string& srcFileName);
    static int32_t GetFilePathWithFd(const int32_t& fd, std::string& srcFilePath);
    static std::string ToLowerString(const std::string& str);
    static std::string GetRealTypeWithFd(const int32_t& fd);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_UTILS_H */
