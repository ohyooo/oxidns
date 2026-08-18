# OxiDNS v1.5.2

## 🚀 发布概览

- v1.5.2 是一次聚焦客户端 IP 还原、双栈探针隔离、大规则集加载效率与运行时生命周期安全的 Patch Release，并补齐 sequence mark 集合操作和发布链路可靠性。
- v1.5.1 YAML 配置可以直接升级；新增 `client_ip_from_ecs`、`dual_selector.probe_executor` 与 `set_mark` 均为可选能力，现有策略不会自动改变。

## ✨ 主要亮点

- 新增 `client_ip_from_ecs` 执行器：仅在原始 peer 命中可信白名单时采用 ECS，并只接受 IPv4 `/32` 或 IPv6 `/128` 完整主机前缀；缺省或空白名单只信任本机 loopback。该插件包含在 standard/full bundle 中。
- `prefer_ipv4` / `prefer_ipv6` 支持可选专用 `probe_executor`；未配置时保留原有 continuation 模式。原始查询与探针上下文相互隔离，所有完成路径会等待或取消后台任务，错误引用和依赖环在启动时拒绝。
- sequence 的 `mark` 可一次追加多个值，并新增 `set_mark` 完整替换 mark 集合；无效或溢出的值会在初始化阶段报错，WebUI 与依赖图同步支持。
- matcher、hosts、redirect、provider、RouterOS 持久化与 zone records 统一采用流式加载、容量预留和隔离构建；多轮编译会校验输入指纹，只发布完整成功的快照。
- provider reload 在调用方取消后仍保持串行 ownership，runtime teardown 会等待在途 reload 与构建完成；下载超时、取消或失败时会自动清理未完成临时文件。
- RouterOS 切换到含无损 response channel 修复的 `oxidns-mikrotik-rs 0.8.1`，移除临时 Git patch 和 crates.io `--no-verify`；发布 workflow 会按依赖顺序上传新版 support crates。
- 双语文档完成结构化重组并加入可复现 benchmark；Telegram 发布公告现在保留标题、列表、强调、行内代码和链接格式。

## ⚠️ 升级说明

- 现有 v1.5.1 配置可以直接升级，没有字段被重命名或删除，也没有现有插件默认策略变化。替换二进制前建议运行 `oxidns check -c <配置文件>`。
- 使用 `client_ip_from_ecs` 时，请放在相关 client-IP matcher 和记录器之前，只信任受控代理或本机转发器；不要信任客户端可直接访问的来源。网络前缀 ECS 会被忽略。
- `dual_selector.probe_executor` 未配置时行为不变；专用探针上下文不会回写 mark 或响应，但已经发生的外部副作用无法回滚，建议使用无副作用的解析链。
- 现有单值 `mark` 语法保持有效；只有显式使用 `set_mark` 才会清空原集合。规则文件应完整原子替换后再触发 reload，否则变化中的候选会被拒绝并继续使用旧快照。
- 根 crate 为 `1.5.2`，`oxidns-proto` 为 `0.1.5`，`oxidns-zoneparser` 为 `0.1.2`；release tag 应为 `v1.5.2`。

## 📦 下载与校验

- 根据平台和 bundle 选择对应 archive；常规部署使用 full 或 standard，最小能力部署使用 minimal。
- 替换生产环境二进制前，请使用 GitHub Release assets 提供的 digest 校验文件完整性。
