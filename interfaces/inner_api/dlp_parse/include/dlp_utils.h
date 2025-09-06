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
static const std::string DLP_HIAE_TYPE = "mkv";
static const uint32_t MIN_REALY_TYPE_LENGTH = 2;
static const uint32_t MAX_REALY_TYPE_LENGTH = 5;

static const std::unordered_map<std::string, uint32_t> TYPE_TO_NUM_MAP = {
    {"txt", 1},
    {"pdf", 2},
    {"doc", 3},
    {"docx", 4},
    {"ppt", 5},
    {"pptx", 6},
    {"xls", 7},
    {"xlsx", 8},
    {"bmp", 9},
    {"bm", 10},
    {"dng", 11},
    {"gif", 12},
    {"heic", 13},
    {"heics", 14},
    {"heif", 15},
    {"heifs", 16},
    {"hif", 17},
    {"jpg", 18},
    {"jpeg", 19},
    {"jpe", 20},
    {"png", 21},
    {"webp", 22},
    {"cur", 23},
    {"raf", 24},
    {"ico", 25},
    {"nrw", 26},
    {"rw2", 27},
    {"pef", 28},
    {"srw", 29},
    {"svg", 30},
    {"arw", 31},
    {"3gpp2", 32},
    {"3gp2", 33},
    {"3g2", 34},
    {"3gpp", 35},
    {"3gp", 36},
    {"avi", 37},
    {"m4v", 38},
    {"f4v", 39},
    {"mp4v", 40},
    {"mpeg4", 41},
    {"mp4", 42},
    {"m2ts", 43},
    {"mts", 44},
    {"ts", 45},
    {"vt", 46},
    {"wrf", 47},
    {"mpeg", 48},
    {"mpeg2", 49},
    {"mpv2", 50},
    {"mp2v", 51},
    {"m2v", 52},
    {"m2t", 53},
    {"mpeg1", 54},
    {"mpv1", 55},
    {"mp1v", 56},
    {"m1v", 57},
    {"mpg", 58},
    {"mov", 59},
    {"mkv", 60},
    {"webm", 61},
    {"h264", 62},
    {"wbmp", 63},
    {"nef", 64},
    {"cr2", 65},
};

static const std::unordered_map<uint32_t, std::string> NUM_TO_TYPE_MAP = {
    {1, "txt"},
    {2, "pdf"},
    {3, "doc"},
    {4, "docx"},
    {5, "ppt"},
    {6, "pptx"},
    {7, "xls"},
    {8, "xlsx"},
    {9, "bmp"},
    {10, "bm"},
    {11, "dng"},
    {12, "gif"},
    {13, "heic"},
    {14, "heics"},
    {15, "heif"},
    {16, "heifs"},
    {17, "hif"},
    {18, "jpg"},
    {19, "jpeg"},
    {20, "jpe"},
    {21, "png"},
    {22, "webp"},
    {23, "cur"},
    {24, "raf"},
    {25, "ico"},
    {26, "nrw"},
    {27, "rw2"},
    {28, "pef"},
    {29, "srw"},
    {30, "svg"},
    {31, "arw"},
    {32, "3gpp2"},
    {33, "3gp2"},
    {34, "3g2"},
    {35, "3gpp"},
    {36, "3gp"},
    {37, "avi"},
    {38, "m4v"},
    {39, "f4v"},
    {40, "mp4v"},
    {41, "mpeg4"},
    {42, "mp4"},
    {43, "m2ts"},
    {44, "mts"},
    {45, "ts"},
    {46, "vt"},
    {47, "wrf"},
    {48, "mpeg"},
    {49, "mpeg2"},
    {50, "mpv2"},
    {51, "mp2v"},
    {52, "m2v"},
    {53, "m2t"},
    {54, "mpeg1"},
    {55, "mpv1"},
    {56, "mp1v"},
    {57, "m1v"},
    {58, "mpg"},
    {59, "mov"},
    {60, "mkv"},
    {61, "webm"},
    {62, "h264"},
    {63, "wbmp"},
    {64, "nef"},
    {65, "cr2"},
};

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
    {"wbmp", "support_photo_dlp"},
    {"nef", "support_photo_dlp"},
    {"cr2", "support_photo_dlp"},
};

class DlpUtils {
public:
    static sptr<AppExecFwk::IBundleMgr> GetBundleMgrProxy(void);
    static bool GetAuthPolicyWithType(const std::string &cfgFile, const std::string &type,
        std::vector<std::string> &authPolicy);
    static std::string GetFileTypeBySuffix(const std::string& suffix, const bool isFromUriName);
    static std::string GetDlpFileRealSuffix(const std::string& dlpFileName, bool& isFromUriName);
    static int32_t GetFileNameWithFd(const int32_t& fd, std::string& srcFileName);
    static int32_t GetFileNameWithDlpFd(const int32_t &fd, std::string &srcFileName);
    static std::string GetRealTypeWithRawFile(const int32_t& fd);
    static int32_t GetFilePathWithFd(const int32_t& fd, std::string& srcFilePath);
    static std::string ToLowerString(const std::string& str);
    static std::string GetRealTypeWithFd(const int32_t& fd, bool& isFromUriName);
    static bool GetBundleInfoWithBundleName(const std::string &bundleName, int32_t flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId);
    static bool GetFileType(const std::string& realFileType);
    static bool GetAppIdFromToken(std::string& appId);
    static bool GetUserIdByForegroundAccount(int32_t &userId);
    static std::string GetRealTypeForEnterpriseWithFd(const int32_t& fd, bool& isFromUriName);
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif /*  INTERFACES_INNER_API_DLP_UTILS_H */
