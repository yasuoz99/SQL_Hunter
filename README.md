# SQL_Hunter

SQL_Hunter 是 **Java 8 Burp 插件**（适配 IDEA 打包），用于增强 SQL 注入检测流程。

## 功能增强

1. **并发模型（回退到双层）**
   - 扫描任务线程池（请求级）
   - 参数线程池（参数级）
   - 不再使用 payload 级第三层线程池。

2. **自动检测（无需点击主动检测）**
   - 流量被插件收集后会自动进入检测。
   - 来自实时监听、Proxy History、右键发送到插件的请求都会自动开始检测。

3. **漏洞类型分色显示**
   - 时间盲注：红色背景。
   - 布尔盲注：橙黄色背景。
   - 报错注入：紫色背景。
   - 排序注入：蓝色背景。

4. **每一个发包可点击查看 + 清理历史**
   - 点击任意日志可在下方查看请求/响应。
   - 新增“清除检测历史”按钮，可清空日志与消息查看器。

5. **请求方法差异化处理**
   - GET 请求：发送 payload 前自动进行 URL 编码。
   - POST 请求：报错注入阶段不再测试双引号（`"`）报错 payload。

6. **基线响应判定优化与多参数全量测试**
   - 仅当等待超过 3 秒仍无响应时，才判定“基线响应为空”。
   - 对同一请求中的多个参数会逐个执行发包测试，不因某个参数命中而跳过其它参数。

7. **时间盲注阈值调整**
   - 时间盲注判定阈值调整为约 2.5 秒（`elapsed >= 2500ms`）。

8. **新增排序注入检测（ORDER BY）**
   - 对每个参数发送“合法 ORDER BY”与“越界 ORDER BY”payload 对。
   - 通过合法/越界响应错误特征、状态码或响应长度差异识别排序注入。

---

## 项目结构

- `src/main/java/com/sqlhunter/BurpExtender.java`：插件主类（Burp 入口类）。
- `pom.xml`：Maven 构建文件，编译目标 Java 8。

## 在 IDEA 中打包（Java 8）

1. 使用 IDEA 打开本项目（Maven 项目）。
2. 确保 Project SDK 和 Maven 编译版本是 **Java 8**。
3. 执行 Maven 打包：
   - `mvn clean package`
4. 产物路径：
   - `target/sql-hunter-burp-1.0.0.jar`

## 在 Burp 中加载

1. Burp -> `Extender` -> `Extensions` -> `Add`。
2. `Extension type` 选择 **Java**。
3. `Extension file` 选择 `target/sql-hunter-burp-1.0.0.jar`。
4. 加载后打开 `SQL Hunter` 标签页开始使用。

## 使用说明

- 勾选 `被动监听实时流量`：自动收集并自动检测实时流量。
- 点击 `扫描 Proxy History`：批量导入并自动检测历史流量。
- 在 HTTP 历史/请求上右键：`Send to SQL Hunter (Auto SQLi Check)`。
- 如需清理界面历史记录，点击 `清除检测历史`。
