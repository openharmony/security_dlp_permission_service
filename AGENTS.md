# DLP 权限管理服务组件指引

## DLP 服务概述

数据防泄漏（DLP: Data Loss Prevention）权限管理服务是 OpenHarmony 安全子系统下的文档权限保护部件，为终端用户提供对文档的权限保护能力：给原始文件添加权限保护、为指定终端用户授予只读/编辑权限，生成 DLP 权限保护文件（简称 DLP 文件）；只有经授权的终端用户才能通过系统能力访问解密内容。本仓负责 DLP 文件的生成、打开、权限管理，以及沙箱（sandbox）应用的生命周期管理。底层加解密依赖 HUKS（OpenHarmony Universal KeyStore）与外部 DLP 凭证服务（credential 仓），本仓通过适配层调用，不自行实现证书签发，也不直接使用密钥。HUKS 与凭证服务不在本仓职责范围内。

## 项目定位

本仓库对应 OpenHarmony `base/security/dlp_permission_service`。SA ID = 3521，进程名 `dlp_permission_service`，UID `dlp_permission`，APL `system_basic`，SysCap `SystemCapability.Security.DataLossPrevention`。仅支持 `standard` 系统。优先按这些目录定位问题：

- `interfaces/`：对外接口层。C API（`kits/c`）、NAPI JS API（`kits/dlp_permission/napi`、`kits/identify_sensitive_content/napi`）、NAPI 公共（`kits/napi_common`）、内部 SDK（`inner_api/dlp_permission`、`inner_api/dlp_parse`、`inner_api/dlp_fuse`、`inner_api/dlp_set_config`）。`inner_api/dlp_permission` 下的 `IDlpPermissionService.idl` 与 `DlpPermissionTypes.idl` 是 IPC 生成源，禁止手改生成产物。
- `frameworks/`：框架层，被 interfaces 与 services 共用。`common/` 是跨模块公共合约（权限策略、错误码、cert_parcel、retention/visited 信息、DFX 定义、hex_string、random）；`dlp_permission/` 是 SDK 侧 parcel 封装与 IPC 接口码定义（`dlp_permission_service_ipc_interface_code.h`）；`access_config/` 是 DLP 应用 clone 权限配置（`clone_app_permission.json`）。
- `services/dlp_permission/sa/`：服务层（SA 3521）。`sa_main/` 是主服务（证书生成/解析、沙箱安装/卸载、访问档位查询、保留状态管理、MDM/企业策略、与外部 DLP 凭证服务的通信客户端 `dlp_credential.*`）；`sa_common/` 是服务侧公共层（token/bundle/权限适配器、策略序列化、沙箱信息、Ability 连接）；`adapt_utils/` 是系统适配（账号、算法/HUKS、文件管理、应用状态观察、关键句柄）；`callback/` 是跨进程回调（沙箱变更、打开 DLP 文件）；`storage/` 是 KV 持久化（DLP 数据存储、沙箱配置存储）；`sa_profile/` 是 SA 注册（`3521.json`）；`etc/` 是运行参数与配置（`dlp_config.json`、`dlp_permission.para(.dac)`）；`mock/` 是测试桩。
- `test/`：`unittest/`（按模块分组：`dlp_permission/`、`dlp_parse/`、`dlp_fuse/`、`sa/`、`mock/`）与 `fuzztest/dlp_permission/fuzzer/`（对每个服务方法与其 Stub 侧做 fuzz，40+ fuzzer 目标）。
- `config/`：公共编译选项与覆盖标志。
- `dlp_permission_service.gni`、`identify_sensitive_content.gni`：特性开关。`bundle.json`：部件声明与依赖。
- `hisysevent.yaml`、`hisysevent-DLP_UE.yaml`：DFX 事件定义（domain：`DLP` 故障、`DLP_UE` 用户行为），硬性合约。

### 按任务类型定位代码

| 任务类型　　　　　　　　　　　　　 | 先看　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 |
| ----------------------------------| -------------------------------------------------------------------------------------------------------------------------------- |
| 修改 NAPI JS API（dlpPermission） | `interfaces/kits/dlp_permission/napi/`：`include/napi_dlp_permission.h`、`napi_dlp_feature.h`、`napi_dlp_connection_plugin.h`、`napi_dlp_transparent_enc.h`、`dlp_transparent_enc_manager.h`、`src/*.cpp` |
| 修改 NAPI JS API（敏感内容识别） | `interfaces/kits/identify_sensitive_content/napi/`（dlopen 外部 DIA 能力库） |
| 修改 C API（ohdlp_permission）　| `interfaces/kits/c/`：`include/dlp_permission_api.h`、`src/*.cpp` |
| 修改内部 SDK 接口（权限管理）　| `interfaces/inner_api/dlp_permission/`：`include/dlp_permission_kit.h`、`dlp_permission_public_interface.h`、`dlp_permission_client.h`、`dlp_permission_callback.h`、`dlp_sandbox_change_callback*.h`、`open_dlp_file_callback*.h`、`dlp_permission_async_stub.h` |
| 修改 DLP 文件格式/加解密　　　　| `interfaces/inner_api/dlp_parse/`：`include/dlp_file.h`、`dlp_crypt.h`、`dlp_file_kits.h`、`dlp_file_manager.h`、`dlp_raw_file.h`、`dlp_zip_file.h`、`dlp_zip.h`、`dlp_transparent_enc_policy.h`、`dlp_utils.h` |
| 修改沙箱文件视图/FUSE　　　　　| `interfaces/inner_api/dlp_fuse/`：`include/dlp_fuse_fd.h`、`dlp_fuse_helper.h`、`dlp_fuse_utils.h`、`dlp_link_file.h`、`dlp_link_manager.h`、`fuse_daemon.h` |
| 修改 SetDlpConfig 内部 SDK　　　| `interfaces/inner_api/dlp_set_config/`：`include/set_dlp_config.h`、`src/set_dlp_config.cpp` |
| 修改 SA 主服务（证书/沙箱/权限档位/MDM/企业） | `services/dlp_permission/sa/sa_main/`：`dlp_permission_service.h/.cpp`、`dlp_permission_service_ext.cpp`、`dlp_permission_service_common.h`、`dlp_credential.h/.cpp`、`dlp_permission_async_proxy.h/.cpp` |
| 修改服务侧公共适配（token/bundle/权限/Ability） | `services/dlp_permission/sa/sa_common/`：`access_token_adapter.*`、`bundle_manager_adapter.*`、`permission_manager_adapter.*`、`dlp_ability_adapter.*`、`dlp_ability_conn.*`、`dlp_ability_proxy.*`、`dlp_ability_stub.*`、`dlp_common_func.*`、`dlp_feature_info.*`、`dlp_permission_serializer.*`、`dlp_sandbox_info.h`、`water_mark_info.h` |
| 修改账号适配　　　　　　　　　　| `services/dlp_permission/sa/adapt_utils/account_adapt/` |
| 修改算法/HUKS 适配　　　　　　　| `services/dlp_permission/sa/adapt_utils/alg_adapt/`：`alg_manager/`、`huks_adapt_manager/`（本仓通过此层调用 HUKS，不直接使用密钥） |
| 修改沙箱文件管理（保留/访问记录/sandbox JSON） | `services/dlp_permission/sa/adapt_utils/file_manager/`：`retention_file_manager.*`、`visit_record_file_manager.*`、`visit_record_json_manager.*`、`sandbox_json_manager.*`、`file_operator.*` |
| 修改应用状态观察/卸载　　　　　| `services/dlp_permission/sa/adapt_utils/app_observer/`、`critical_handler/` |
| 修改沙箱变更回调　　　　　　　　| `services/dlp_permission/sa/callback/dlp_sandbox_change_callback/`：`*_manager.*`、`*_proxy.*`、`*_death_recipient.*` |
| 修改打开 DLP 文件回调　　　　　| `services/dlp_permission/sa/callback/open_dlp_file_callback/`：`*_manager.*`、`*_proxy.*`、`*_death_recipient.*` |
| 修改 KV 持久化　　　　　　　　　| `services/dlp_permission/sa/storage/`：`include/dlp_kv_data_storage.h`、`sandbox_config_kv_data_storage.h` |
| 修改 SA 注册（SA ID/进程/库路径） | `services/dlp_permission/sa/sa_profile/3521.json` |
| 修改运行参数与配置　　　　　　　| `services/dlp_permission/sa/etc/`：`dlp_config.json`（支持文件类型白名单）、`dlp_permission.para`（gathering 策略）、`dlp_permission.para.dac`（DAC 0774） |
| 修改 IPC 接口码（需安全/IPC 域 CODEOWNERS 评审） | `frameworks/dlp_permission/include/dlp_permission_service_ipc_interface_code.h`（见项目约束） |
| 修改权限策略/错误码/cert_parcel/retention/visited 公共合约 | `frameworks/common/include/`：`permission_policy.h`、`dlp_permission.h`、`cert_parcel.h`、`retention_sandbox_info.h`、`visited_dlp_file_info.h`、`dlp_dfx_define.h`、`dlp_permission_log.h`、`hex_string.h`、`random.h`、`i_json_operator.h`、`dlp_fdsan.h` |
| 修改 SDK 侧 parcel 封装　　　　 | `frameworks/dlp_permission/`：`auth_user_info_parcel.*`、`dlp_permission_info_parcel.*`、`dlp_policy_parcel.*`、`dlp_sandbox_callback_info_parcel.*`、`open_dlp_file_callback_info_parcel.*` |
| 修改 DLP 应用 clone 权限配置　　| `frameworks/access_config/clone_app_permission.json` |
| 修改特性开关　　　　　　　　　　| `dlp_permission_service.gni`、`identify_sensitive_content.gni`（见"构建开关"表） |
| 修改构建/部件声明　　　　　　　| `bundle.json`、`BUILD.gn`、`config/` |
| 修改 DFX 事件　　　　　　　　　| `hisysevent.yaml`（domain `DLP`，FAULT/CRITICAL）、`hisysevent-DLP_UE.yaml`（domain `DLP_UE`，BEHAVIOR/MINOR，preserve: true） |
| 修改单元测试　　　　　　　　　　| `test/unittest/dlp_permission/`、`test/unittest/dlp_parse/`、`test/unittest/dlp_fuse/`、`test/unittest/sa/`（见"关键测试目标"） |
| 修改 fuzz 目标　　　　　　　　　| `test/fuzztest/dlp_permission/fuzzer/`（40+ 目标，按服务方法/Stub 分组） |

### 嵌套指引

本仓库无目录级别的嵌套指引。所有任务级指导通过本文件和接口头文件中的注释提供。

## 知识索引

### 词汇型路由

当任务描述、issue、日志、API 或文件中出现以下术语时，先读对应文件再动手。
服务层路径以 `services/dlp_permission/sa/` 为根，省略前缀；框架层路径以 `frameworks/` 为根，省略前缀。

#### DLP 文件格式与加解密

共享链路：JS `interfaces/kits/dlp_permission/napi/src/napi_dlp_permission.cpp`（GenerateDlpFile / DecryptDlpFile）→ C API `interfaces/kits/c/src/` → inner SDK `interfaces/inner_api/dlp_permission/src/dlp_permission_kit.cpp` → IPC Proxy `dlp_permission_async_proxy.cpp` → SA 主服务 `sa_main/dlp_permission_service.cpp`（GenerateDlpCertificate / ParseDlpCertificate）→ 凭证客户端 `sa_main/dlp_credential.cpp` → 文件解析 `interfaces/inner_api/dlp_parse/src/dlp_file.cpp` → 加解密 `interfaces/inner_api/dlp_parse/src/dlp_crypt.cpp` → HUKS 适配 `sa/adapt_utils/alg_adapt/huks_adapt_manager/`

| 领域术语 | 实现位置 |
| --- | --- |
| DLP 文件（头区/证书区/密文区） | `interfaces/inner_api/dlp_parse/include/dlp_file.h`；解析 `dlp_file.cpp` |
| AES-CTR 加密 / HMAC 完整性 | `interfaces/inner_api/dlp_parse/include/dlp_crypt.h`；实现 `dlp_crypt.cpp` |
| 企业版文件头 / raw 文件 | `interfaces/inner_api/dlp_parse/include/dlp_raw_file.h`；实现 `dlp_raw_file.cpp` |
| DLP zip 容器 | `interfaces/inner_api/dlp_parse/include/dlp_zip_file.h`、`dlp_zip.h`；实现 `dlp_zip_file.cpp` |
| 透明加密策略 | `interfaces/inner_api/dlp_parse/include/dlp_transparent_enc_policy.h`；NAPI `napi_dlp_transparent_enc.cpp`、`dlp_transparent_enc_manager.cpp` |
| 文件管理器 | `interfaces/inner_api/dlp_parse/include/dlp_file_manager.h`、`dlp_file_kits.h` |
| HUKS 适配 | `sa/adapt_utils/alg_adapt/huks_adapt_manager/`（本仓通过此层调用 HUKS，不直接使用密钥） |
| 算法管理 | `sa/adapt_utils/alg_adapt/alg_manager/` |

#### 权限策略与档位

共享链路：策略结构定义 `frameworks/common/include/permission_policy.h` → 序列化 `sa/sa_common/dlp_permission_serializer.cpp` → parcel `frameworks/dlp_permission/src/dlp_policy_parcel.cpp` → IDL `interfaces/inner_api/dlp_permission/DlpPermissionTypes.idl`（`DLPFileAccess` 枚举）→ SA 主服务 `sa_main/dlp_permission_service.cpp`（QueryDlpFileAccess / 沙箱授权）→ SDK `interfaces/inner_api/dlp_permission/include/dlp_permission_kit.h`

| 领域术语 | 实现位置 |
| --- | --- |
| 权限策略 / Policy / 策略透传 | `frameworks/common/include/permission_policy.h`（owner/授权账号/everyonePerm + ActionFlags） |
| DLPFileAccess 档位 | `interfaces/inner_api/dlp_permission/DlpPermissionTypes.idl`：`NO_PERMISSION=0` < `READ_ONLY=1` < `CONTENT_EDIT=2` < `FULL_CONTROL=3`，判定以策略为上限 |
| ActionFlags / 动作位 | `frameworks/common/include/permission_policy.h`（保存/另存/编辑/截屏/录屏/复制/打印/导出等逐项开关） |
| AuthType / 认证类型 | `frameworks/common/include/permission_policy.h`（在线/离线认证判定，涉及离线证书场景） |
| DLP 凭证 / DLP 证书 / credential | `sa_main/dlp_credential.h`（与外部凭证服务通信客户端）+ `frameworks/common/include/cert_parcel.h` |
| cert_parcel | `frameworks/common/include/cert_parcel.h`；实现 `frameworks/common/src/cert_parcel.cpp` |
| 水印 / WaterMark | `sa_main/dlp_permission_service.h`（SetWaterMark / GetWaterMark）、`sa_common/water_mark_info.h` |

#### 沙箱生命周期

共享链路：JS `napi_dlp_permission.cpp`（InstallDlpSandbox / UninstallDlpSandbox / IsInDlpSandbox）→ inner SDK `dlp_permission_kit.cpp` → IPC Proxy → SA 主服务 `dlp_permission_service.cpp`（沙箱安装/卸载）→ 公共适配 `sa_common/bundle_manager_adapter.*`、`access_token_adapter.*`、`permission_manager_adapter.*`、`dlp_ability_conn.*` → 文件管理 `adapt_utils/file_manager/`（保留/访问记录/sandbox JSON）→ KV 存储 `sa/storage/`

| 领域术语 | 实现位置 |
| --- | --- |
| DLP 沙箱 / sandbox | `sa/sa_common/dlp_sandbox_info.h`（bundleName + appIndex + userId 三元组标识）+ `sa_main/dlp_permission_service.h` |
| 沙箱文件（dlp_fuse / link） | `interfaces/inner_api/dlp_fuse/include/`：`dlp_link_file.h`、`dlp_link_manager.h`、`fuse_daemon.h`、`dlp_fuse_helper.h`、`dlp_fuse_fd.h` |
| Retention / 沙箱保留 | `sa/adapt_utils/file_manager/retention_file_manager.h`；实现 `retention_file_manager.cpp` |
| 访问记录 / visit record | `sa/adapt_utils/file_manager/visit_record_file_manager.h`、`visit_record_json_manager.h`；公共合约 `frameworks/common/include/visited_dlp_file_info.h` |
| sandbox JSON 管理 | `sa/adapt_utils/file_manager/sandbox_json_manager.h` |
| KV 持久化 / 沙箱配置 | `sa/storage/include/dlp_kv_data_storage.h`、`sandbox_config_kv_data_storage.h` |
| 沙箱变更回调 | `sa/callback/dlp_sandbox_change_callback/`（manager + proxy + death_recipient）+ `interfaces/inner_api/dlp_permission/include/dlp_sandbox_change_callback*.h` |
| 打开 DLP 文件回调 | `sa/callback/open_dlp_file_callback/`（manager + proxy + death_recipient）+ `interfaces/inner_api/dlp_permission/include/open_dlp_file_callback*.h` |
| 沙箱外部授权 | `sa_main/dlp_permission_service.h`（GetSandboxExternalAuthorization） |
| 应用状态观察 / 卸载 | `sa/adapt_utils/app_observer/`、`sa/adapt_utils/critical_handler/` |

#### MDM / 企业策略

共享链路：JS `napi_dlp_permission_enterprise.cpp`（SetMDMPolicy / SetEnterprisePolicy / SetEnterpriseInfos / QueryOpenedEnterpriseDlpFiles / CloseOpenedEnterpriseDlpFiles）→ inner SDK → IPC Proxy → SA 主服务 `sa_main/dlp_permission_service_ext.cpp` → 凭证客户端 `sa_main/dlp_credential.h`（CheckMdmPermission）

| 领域术语 | 实现位置 |
| --- | --- |
| MDM / 企业策略 | `sa_main/dlp_credential.h`（SetMDMPolicy / GetMDMPolicy / RemoveMDMPolicy / SetEnterprisePolicy / CheckMdmPermission） |
| 企业文件 | `sa_main/dlp_permission_service_ext.cpp`（QueryOpenedEnterpriseDlpFiles / CloseOpenedEnterpriseDlpFiles / SetFileInfo） |

#### IPC 与回调

共享链路：IDL 生成源 `interfaces/inner_api/dlp_permission/IDlpPermissionService.idl`、`DlpPermissionTypes.idl` → `idl_gen_interface` 生成 Proxy/Stub（`dlp_permission_async_proxy.*`、`dlp_permission_async_stub.*`）→ 接口码 `frameworks/dlp_permission/include/dlp_permission_service_ipc_interface_code.h` → 客户端 `interfaces/inner_api/dlp_permission/src/dlp_permission_client.cpp` → 服务侧 `sa_main/dlp_permission_service.cpp`

| 领域术语 | 实现位置 |
| --- | --- |
| IDL / Proxy / Stub | `interfaces/inner_api/dlp_permission/IDlpPermissionService.idl`、`DlpPermissionTypes.idl`（生成源，禁止手改生成产物）；BUILD.gn 中 `idl_gen_interface` target `dlp_permission_interface` |
| IPC 接口码 | `frameworks/dlp_permission/include/dlp_permission_service_ipc_interface_code.h`（需安全/IPC 域 CODEOWNERS 评审） |
| Parcel 封装 | `frameworks/dlp_permission/src/`：`auth_user_info_parcel.*`、`dlp_permission_info_parcel.*`、`dlp_policy_parcel.*`、`dlp_sandbox_callback_info_parcel.*`、`open_dlp_file_callback_info_parcel.*` |
| 回调机制 | `sa/callback/`（服务侧 manager + proxy + death_recipient）+ `interfaces/inner_api/dlp_permission/include/`（接口侧 callback/stub） |

#### 配置与 DFX

| 领域术语 | 实现位置 |
| --- | --- |
| 支持文件类型白名单 | `sa/etc/dlp_config.json` 中 `support_file_type` 数组 |
| Gathering / 采集策略 | `dlp_permission_service.gni` 中 `dlp_permission_service_gathering_policy`；运行期参数 `sa/etc/dlp_permission.para`（`dlp.permission.gathering.policy`） |
| DAC 权限 | `sa/etc/dlp_permission.para.dac`（0774，修改需安全评审） |
| HiSysEvent domain DLP / DLP_UE | `hisysevent.yaml`（domain `DLP`，FAULT/CRITICAL）、`hisysevent-DLP_UE.yaml`（domain `DLP_UE`，BEHAVIOR/MINOR，preserve: true）—— 硬性合约 |
| DFX 定义 | `frameworks/common/include/dlp_dfx_define.h` |
| 日志宏 | `frameworks/common/include/dlp_permission_log.h` |
| SetDlpFeature / dlpSetDlpFeature | `interfaces/kits/dlp_permission/napi/include/napi_dlp_feature.h`（"是否具备 DLP 能力/是否启用"的系统级特性位设置） |
| DIA / 敏感内容识别 | `interfaces/kits/identify_sensitive_content/napi/`（dlopen 外部能力库）；开关 `identify_sensitive_content.gni` 中 `data_identify_anonymize_service_enable` |
| SA 3521 | `sa/sa_profile/3521.json`（进程 `dlp_permission_service`，库 `libdlp_permission_service.z.so`） |

### 任务型路由

当任务涉及多个"按任务类型定位代码"表中的类型时，按下表确定依次涉及的类型和顺序：

| 任务场景 | 依次涉及的任务类型 |
| --- | --- |
| 新增一个 SA 服务方法（含 JS 接口） | 修改 IDL（`IDlpPermissionService.idl`）→ 重新生成 Proxy/Stub → 修改 SA 主服务 → 修改 IPC 接口码 → 修改内部 SDK → 修改 NAPI JS 接口 + 修改 C API（如需）→ 补 fuzz 目标 |
| 修改 DLP 文件格式（新增版本/算法） | 修改 DLP 文件格式/加解密 → 修改权限策略/公共合约（如结构变化）→ 评估存量文件兼容性 → 修改单元测试 |
| 修改沙箱生命周期（安装/卸载/保留） | 修改 SA 主服务 → 修改服务侧公共适配 → 修改沙箱文件管理 → 修改 KV 持久化 → 修改沙箱变更回调（如需）→ 修改单元测试 |
| 修改权限档位判定 / 策略解析 | 修改权限策略/公共合约 → 修改 SA 主服务 → 修改 SDK 侧 parcel 封装 → 修改单元测试 |
| 修改 MDM/企业策略 | 修改 SA 主服务（`dlp_permission_service_ext.cpp`）→ 修改凭证客户端（`dlp_credential.*`）→ 修改 NAPI JS 接口（企业版）→ 修改单元测试 |
| 新增/修改 DFX 事件 | 修改 DFX 事件（`hisysevent*.yaml`）→ 修改 DFX 定义（`dlp_dfx_define.h`）→ 评估事件 preserve 与上报时机 |
| 修改特性开关默认值 | 修改特性开关（`.gni`）→ 同步 `bundle.json` features → 评估所有下游产品影响 |

通用规则：
- 修改 IDL：改 `*.idl` → 重新生成 Proxy/Stub → 客户端、Stub、服务侧成对修改并核对全部调用点（包括回调）→ 修改 IPC 接口码（如新增事务码）
- 修改公共 API：NAPI 与 C 实现同步，做兼容性评估
- 修改文件格式：`dlp_parse`、service、SDK 任何一侧改变格式认知都会破坏既有 DLP 文件，必须三方同步
- 修改沙箱回收/清理：KV 配置与文件残留必须同步清理并校验一致性

### 开始编辑前

在修改代码前，按以下顺序确认：
1. 确认任务类别（API / 内部 SDK / SA 主服务 / 沙箱/保留 / 文件解析/加解密 / FUSE / IPC / KV 存储 / 回调 / DFX / 配置 / 构建 / 测试）
2. 根据上表确定需要阅读的源码头文件与配置
3. 根据"项目约束"确认不违反任何约束
4. 声明："将修改 X，已阅读 Y 文档，遵循 Z 约束"

## 构建和验证

### 构建方式 1 - 基于 OpenHarmony 项目构建
构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
# 构建整个 DLP 权限管理部件（fwk + service + inner_api + kits）
./build.sh --product-name rk3568 --build-target dlp_permission_build_module --ccache

# 仅构建主服务
./build.sh --product-name rk3568 --build-target dlp_permission_service

# 构建并运行单元测试
./build.sh --product-name rk3568 --build-target dlp_permission_build_module_test

# 构建 fuzz 目标（fuzz 需要 cfi/thin_lto 关闭）
./build.sh --product-name rk3568 --build-target dlp_permission_build_fuzz_test --gn-args use_cfi=false use_thin_lto=false
```

部件库目标：主服务 `libdlp_permission_service.z.so`、内部 SDK `libdlp_permission_sdk`、`libdlp_permission_common_interface`、`libdlpparse`、`libdlpparse_inner`、`libdlp_fuse`、`libdlp_setconfig_sdk`、C API `ohdlp_permission`、NAPI `cryptoframework_napi`（实际命名见 `bundle.json`）。

### 构建方式 2 - 设备端运行测试

```sh
# 单元测试
run -t UT -tp dlp_permission_service

# Fuzz 测试
run -t FUZZ -tp dlp_permission_service
```

### 静态检查
修改 C/C++ 文件后，执行本地代码检查，确认无新增告警再提交。

检查命令从 OpenHarmony 源码根目录执行，不在本子目录执行。
```sh
./build.sh --product-name rk3568 --build-target dlp_permission_build_module --gn-args enable_cpp_static_check=true
```

### 关键测试目标（test/unittest/）

| 测试目标 | 路径 | 覆盖 |
| --- | --- | --- |
| `dlp_permission_service_test` | `test/unittest/sa/src/dlp_permission_service_test.cpp` | SA 主服务逻辑（沙箱安装/卸载/权限档位/MDM/企业策略） |
| `dlp_permission_service_ext_test` | `test/unittest/sa/src/dlp_permission_service_ext_test.cpp` | SA 扩展服务（MDMPolicy/EnterprisePolicy/企业文件） |
| `dlp_permission_serializer_test` | `test/unittest/sa/src/dlp_permission_serializer_test.cpp` | 策略序列化 |
| `permission_policy_test` | `test/unittest/sa/src/permission_policy_test.cpp` | 权限策略结构与档位判定 |
| `retention_file_manager_test` | `test/unittest/sa/src/retention_file_manager_test.cpp` | 沙箱保留 |
| `sandbox_json_manager_test` | `test/unittest/sa/src/sandbox_json_manager_test.cpp` | 沙箱 JSON 管理 |
| `dlp_kv_storage_test` | `test/unittest/sa/src/dlp_kv_storage_test.cpp` | KV 持久化 |
| `dlp_credential_test` | `test/unittest/sa/src/dlp_credential_test.cpp` | 与外部凭证服务交互 |
| `huks_adapt_manager_test` | `test/unittest/sa/src/huks_adapt_manager_test.cpp` | HUKS 适配 |
| `dlp_callback_test` | `test/unittest/sa/src/dlp_callback_test.cpp` | 跨进程回调 |
| `dlp_permission_kit_test` | `test/unittest/dlp_permission/dlp_permission_kit_test.cpp` | 内部 SDK 客户端 |
| `dlp_permission_proxy_test` | `test/unittest/dlp_permission/dlp_permission_proxy_test.cpp` | IPC Proxy |
| `dlp_permission_async_stub_test` | `test/unittest/dlp_permission/dlp_permission_async_stub_test.cpp` | IPC Stub |
| `dlp_sandbox_change_callback_stub_test` | `test/unittest/dlp_permission/dlp_sandbox_change_callback_stub_test.cpp` | 沙箱变更回调 Stub |
| `open_dlp_file_callback_stub_test` | `test/unittest/dlp_permission/open_dlp_file_callback_stub_test.cpp` | 打开文件回调 Stub |
| `dlp_set_config_test` | `test/unittest/dlp_permission/dlp_set_config_test.cpp` | SetDlpConfig SDK |
| `dlp_transparent_enc_manager_test` | `test/unittest/dlp_permission/dlp_transparent_enc_manager_test.cpp` | 透明加密管理 |
| `dlp_parse_test`（含 `dlp_file_test`/`dlp_crypt_test`/`dlp_raw_file_test`/`dlp_zip_file_test`/`dlp_file_manager_test`/`dlp_file_kits_test`/`dlp_utils_test`） | `test/unittest/dlp_parse/` | DLP 文件格式与加解密 |
| `dlp_fuse_test`（含 `dlp_file_test`/`fuse_daemon_test`） | `test/unittest/dlp_fuse/` | FUSE 与 link 文件 |
| `fuzztest`（40+ 目标，按服务方法分组） | `test/fuzztest/dlp_permission/fuzzer/` | 服务方法与 Stub 侧 fuzz |

### 构建开关（dlp_permission_service.gni、identify_sensitive_content.gni、bundle.json features）

| 开关 | 默认 | 说明 |
| --- | --- | --- |
| `dlp_permission_service_gathering_policy` | `false` | 是否采集 DLP 使用信息（运行期通过 `dlp.permission.gathering.policy` 参数控制） |
| `dlp_permission_service_credential_connection_enable` | `true` | 是否启用与外部 DLP 凭证服务的连接 |
| `dlp_permission_service_pc_feature` | `false` | PC 特性分支 |
| `dlp_parse_inner` | `true`（依赖 `account_os_account` 部件存在） | 是否编译 dlp_parse 内部库 |
| `dlp_credential_enable` | `true`（依赖 `security_dlp_credential_service` 部件存在） | 是否启用凭证服务联动 |
| `security_guard_flag` | `true`（依赖 `security_security_guard` 部件存在） | 是否联动 security_guard |
| `dlp_file_version_inner` | `true` | 文件版本特性 |
| `data_identify_anonymize_service_enable` | `false`（依赖 `security_data_identify_anonymize_service` 部件存在） | 敏感内容识别/匿名化联动 |

> `bundle.json` 的 `features` 数组同步声明这些开关，修改默认值需两者一致并评估对所有下游产品的影响。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已提交** - 使用 `git commit -s`，多代理协作时添加 `Co-Authored-By: Agent`
2. **本地构建通过** - 执行上述构建命令，至少 `dlp_permission_build_module` 构建通过
3. **相关测试通过** - 按改动区域选择对应测试目标（改 SA 主服务跑 `dlp_permission_service_test`；改序列化跑 `dlp_permission_serializer_test` + `permission_policy_test`；改 KV 跑 `dlp_kv_storage_test`；改沙箱/保留跑 `retention_file_manager_test` + `sandbox_json_manager_test`；改 dlp_parse 跑 `dlp_parse_test` + `dlp_utils_test`；改 FUSE 跑 `dlp_fuse_test` + `dlp_file_test`；改 IPC 跑 `dlp_permission_kit_test` + `dlp_permission_proxy_test` + `dlp_permission_async_stub_test`；改 kits 公共 API 跑全量单测并做兼容性评估）
4. **BUILD.gn 同步** - 新增/删除源文件必须同步对应 BUILD.gn 与 `.gni` 源文件列表
5. **公共 API/IPC/文件格式兼容性确认（如适用）** - 见项目约束
6. **DFX 事件未被破坏（如适用）** - `hisysevent*.yaml` 事件名/参数/级别未变更
7. **板侧/真机验证（如适用）** - 涉及沙箱拉起、DLP 文件打开、保留回收、HUKS 集成的改动需提供板侧证据（日志、HiSysEvent 输出）
8. **静态检查通过** - `enable_cpp_static_check=true` 构建无新增告警

### 如果无法运行验证

明确说明无法运行的原因，列出推荐的验证步骤供人工执行，标记需要人工验证的部分。若本地无 OpenHarmony 源码树，至少保证改动文件可独立编译（`gn gen` + `ninja` 单文件目标）。离线环境可使用 `services/dlp_permission/sa/mock/` 与 `test/unittest/mock/` 中的桩构建链路验证。

### 完成报告格式

报告应包含：改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、影响评估（公共 API、IPC、DLP 文件格式、权限语义、DFX 事件兼容性）、风险评估（安全边界、跨账号隔离、密钥材料处理、性能风险）、技能加载回执（实际调用了哪些 ohos-* 技能，或声明"未加载"及原因）、未完成事项。

## 项目约束

### 性能约束

- 沙箱安装/卸载、证书生成/解析是用户可感知路径，不要在热路径中增加全量扫描、字符串格式化或 INFO 日志
- FUSE 读写在沙箱内是高频路径，`dlp_fuse` 改动避免在每次 read/write 中做重计算或长锁
- KV 存储加锁路径避免长耗时操作阻塞并发访问

### 架构约束

- 权限判定以文件内策略为上限：沙箱打开/权限查询路径返回的档位与动作允许集必须落在策略（owner/授权账号/everyonePerm + ActionFlags）范围内；策略解析是判定的唯一输入源，不要在服务侧另开口子
- 策略经证书随文件透传：权限策略随证书在"生成—分发—打开"链路中传递，由 `ParseDlpCertificate` 解析后决定沙箱安装与访问档位，不是服务端按调用方实时下发的全局策略；改动判定前先追踪策略从生成到沙箱安装的完整链路
- 生成/打开 DLP 文件必须先做调用方校验：token/bundle/账号归属（`sa_common` 的 `access_token_adapter` / `bundle_manager_adapter` / `permission_manager_adapter`），沙箱外部授权（能否拉起 Ability 等）遵循配置，不可绕过
- 沙箱实例以 `bundleName + appIndex + userId` 三元组标识，安装/卸载/保留/回收路径必须一致使用同一标识规则
- DLP 文件格式（头区/证书区/密文区布局、magic、版本、算法类型）是跨模块共享理解：`dlp_parse`、service、SDK 任何一侧改变格式认知都会破坏既有 DLP 文件
- 本仓不自行签发凭证：与外部凭证服务的交互走 `dlp_credential.*`，单测/fuzz 使用 `sa/mock/` 桩；不要把 mock 当线上实现
- 本仓不直接使用密钥：所有密钥操作走 `sa/adapt_utils/alg_adapt/huks_adapt_manager/`，不绕过此层直接调用 HUKS
- 四层归属保持显式：API 契约在 `interfaces/`，跨模块公共合约在 `frameworks/common/`，SDK 侧 parcel 在 `frameworks/dlp_permission/`，服务管理在 `services/dlp_permission/sa/`。不要把服务逻辑塞进 SDK，也不要把 SDK 逻辑塞进服务

### 编码约定

- 本仓库以 C/C++ 为主。C/C++ 改动优先复用项目内已有的返回约定与宏（如 `DLP_OK`、`DLP_ERROR` 系列错误码、`DLP_LOG*` 宏），不要引入风格不一致的错误处理
- 内存分配优先使用项目既有封装，不要混用原生 `malloc`/`free` 与项目封装
- 返回值统一使用 `frameworks/common/include/dlp_permission.h` 中已定义的错误码，成功返回 `DLP_OK`，不要新增冗余错误码除非确认现有无法覆盖
- 日志使用 `frameworks/common/include/dlp_permission_log.h` 中的 `DLP_LOG*` 宏，不要使用 `printf` 等日志打印方式
- 字符串操作注意边界检查，依赖 `bounds_checking_function` 做边界检查
- napi 层一旦 C++ 对象通过 `napi_wrap` 成功绑定到 napi 对象，就不能主动释放该 C++ 对象。`napi_wrap` 绑定时已指定释放回调（finalizer），对象生命周期由 napi 托管，GC 时由回调负责 `delete`；主动释放会导致 double-free。仅在 `napi_wrap` 失败时才需手动 `delete`
- napi 层异步接口中，若未对参数数据进行拷贝（如零拷贝取 `uint8_array` 数据），必须通过 `napi_create_reference` 增加该 napi 参数的引用计数，否则异步任务执行期间 JS 侧参数对象可能被 GC 释放，导致 native 层访问到已释放的内存（use-after-free）。引用在异步上下文清理时通过 `napi_delete_reference` 释放
- napi 层异步接口中，当前操作对象（`thisVar`）同样必须通过 `napi_create_reference` 增加引用计数，否则异步任务执行期间 JS 侧 `this` 对象可能被 GC 释放，导致 native 层通过 unwrap 获取的 C++ 对象指针悬空
- napi 层不得将原生 C++ 对象指针以 `int64` 暴露给 JS——JS 层可伪造该指针值，导致 native 代码解引用任意地址
- JS 接口调用失败抛出异常时，`errMsg` 应尽可能详细，包含失败原因、关键参数值、调用者信息等上下文，便于应用开发者定位问题

### 公共 API 约束

**Do not（禁止）：**
- 修改已发布的 NAPI JS API（`interfaces/kits/dlp_permission/napi/`、`interfaces/kits/identify_sensitive_content/napi/`）的函数签名、参数类型、返回值类型
- 修改已发布的 C API（`interfaces/kits/c/include/dlp_permission_api.h`）的函数签名
- 修改内部 SDK 接口（`inner_api/dlp_permission/include/`、`inner_api/dlp_parse/include/`、`inner_api/dlp_fuse/include/`、`inner_api/dlp_set_config/include/`）的签名除非任务明确要求
- 修改已有 API 的错误码（`frameworks/common/include/dlp_permission.h`）除非明确标注为废弃
- 删除或重命名已有公共 API
- 修改已有 API 的行为语义（如异步变同步、默认档位变化、沙箱授权规则变化）
- 修改 NAPI 模块名
- 修改 `frameworks/dlp_permission/include/dlp_permission_service_ipc_interface_code.h` 中已发布的接口码值/顺序

**Ask before（修改前必须确认）：**
- 新增公共 API：确认是否需要权限检查、系统应用校验、DFX 日志、HiSysEvent 上报
- 修改内部 SDK 接口：评估是否影响跨组件兼容性
- 修改错误处理逻辑：确认是否影响应用层的错误码兼容性
- 新增 IPC 接口码：需在 `dlp_permission_service_ipc_interface_code.h` 新增（需安全/IPC 域 CODEOWNERS 评审），并确认跨版本兼容

### 安全与权限边界

**Do not（禁止）：**
- 绕过 `sa_common` 的 `access_token_adapter` / `bundle_manager_adapter` / `permission_manager_adapter` 中的调用方校验
- 绕过 `sa_main/dlp_credential.h` 中的 `CheckMdmPermission` 等 MDM/企业策略授权检查
- 关闭或弱化 NAPI 层的系统应用校验（如 `GenerateDlpFileForEnterprise` / `DecryptDlpFile` / `QueryDlpPolicy` / `RegisterPlugin` / `SetDlpFeature` 等）
- 在 NAPI 层将原生 C++ 对象指针以 int64 暴露给 JS
- 在未验证的情况下直接使用跨进程传递的文件描述符、Parcel 数据或字符串入参（特别是 docUri、bundleName、appId）
- 将密钥明文、密钥材料、证书内容、口令等敏感信息写入非安全日志或 HiSysEvent
- 修改 `dlp_permission.para.dac` 中的 DAC 权限（0774）而不经安全评审
- 在沙箱回收/清理逻辑里跳过 KV 配置与文件残留的同步清理
- 在沙箱外直接 `rm` 沙箱目录或 `reset` KV 存储——必须走服务侧 `UninstallDlpSandbox` / `CleanSandboxAppConfig` / `ClearUnreservedSandbox` 接口

**Ask before（修改前必须确认）：**
- 涉及 Access Token 集成（`sa_common/access_token_adapter.*`）改动
- 涉及账号适配（`adapt_utils/account_adapt/`）改动
- 涉及权限档位判定、策略解析语义或沙箱授权规则改动（安全边界）
- 涉及 MDM/企业策略授权改动
- 涉及 HUKS 适配层（`adapt_utils/alg_adapt/huks_adapt_manager/`）改动
- 涉及密钥材料处理（加解密、证书解析）改动
- 修改 `dlp_config.json` 中支持文件类型白名单
- 修改 `dlp_permission.para` 中 gathering 策略默认值

### 协议与数据格式兼容性

**Do not（禁止）：**
- 修改 IPC 序列化顺序或 Parcel 数据布局
- 修改 `frameworks/dlp_permission/include/dlp_permission_service_ipc_interface_code.h` 中的接口码值/顺序（需安全/IPC 域 CODEOWNERS 评审）
- 手改 IDL 生成产物（`idl_gen_interface` 生成的 Proxy/Stub）——改 `*.idl` 后重新生成
- 修改已发布 DLP 文件头结构的关键字段（magic / 偏移 / 算法标识 / 版本）而不评估存量文件兼容性
- 修改 KV 持久化数据结构布局而不提供升级迁移
- 修改沙箱 JSON 配置格式而不评估存量设备
- 修改 `hisysevent*.yaml` 已发布事件名/参数/级别/上报时机——`DLP_UE` 事件为 preserve 上报，不得改语义
- 修改 `sa_profile/3521.json` 中 SA ID/进程名/库路径

**Ask before（修改前必须确认）：**
- 修改 DLP 文件格式（magic / 版本 / 区块布局 / 算法类型）
- 修改 KV 存储或沙箱 JSON 字段
- 修改与外部凭证服务的交互协议

### 生成代码边界

**Do not（禁止）：**
- 手动编辑 IDL 编译器生成的 IPC Proxy/Stub 代码（`inner_api/dlp_permission/` 中由 `idl_gen_interface` 生成部分）

**正确做法：**
- 修改 `IDlpPermissionService.idl` / `DlpPermissionTypes.idl` 后重新运行 IDL 编译器生成代码
- 客户端、Stub、服务侧成对修改并核对全部调用点（包括回调）

### 第三方依赖

**Do not（禁止）：**
- 新增第三方依赖——必须先经 `bundle.json` 声明与 License 审查

**Ask before（修改前必须确认）：**
- 修改 `bundle.json` 中 `deps.components` 或 `deps.third_party`

### 设备操作约束

**涉及真实设备时的注意事项：**
- 不执行可能影响沙箱目录、KV 存储区或已安装沙箱的破坏性操作（如批量卸载沙箱、清空 KV）
- 涉及沙箱拉起、DLP 文件打开、保留回收的改动必须提供板侧证据（日志、HiSysEvent 输出）
- 涉及 HUKS 集成的改动需在支持 HUKS 的设备上验证
- KV 存储路径的访问需通过 `sa/storage/` 接口，不要直接读写

## 关键风险总结

改动前自检是否触及以下高风险项之一，若触及则升级评审：

1. **公共 API 签名 / 错误码 / NAPI 模块名** → 二进制兼容破坏
2. **IPC 接口码 / 序列化顺序 / `dlp_permission_service_ipc_interface_code.h`** → 跨进程兼容破坏（需 CODEOWNERS 评审）
3. **DLP 文件格式（magic / 版本 / 区块布局 / 算法标识）** → 存量 DLP 文件无法解析或被篡改
4. **KV 存储或沙箱 JSON 格式** → 存量设备数据无法迁移
5. **权限档位判定 / 策略解析语义 / 沙箱授权规则** → 安全边界被绕过
6. **`sa_common` 调用方校验 / MDM 授权 / 系统应用校验** → 越权访问
7. **密钥材料处理（加解密、证书解析、HUKS 适配）** → 密钥泄露或密码学正确性问题
8. **沙箱三元组（bundleName + appIndex + userId）一致性** → 沙箱错乱、保留/回收失败
9. **沙箱回收/清理的 KV 与文件同步** → 残留或泄漏
10. **DFX 事件定义（`hisysevent*.yaml`）** → 故障归因硬性合约破坏
11. **`sa_profile/3521.json` SA ID/进程/库路径** → 全系统拉起失败
12. **特性开关默认值（`dlp_permission_service.gni`、`identify_sensitive_content.gni`、`bundle.json` features）** → 所有下游产品行为变化
