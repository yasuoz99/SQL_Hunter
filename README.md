# SQL_Hunter

SQL_Hunter 现已改为 **Java 8 Burp 插件**（适配 IDEA 打包），用于增强 SQL 注入检测流程：

1. **可控被动收集 + 手动主动检测**
   - 开关控制是否监听实时流量（被动）。
   - 可手动扫描 Burp `Proxy History`。
   - 可通过右键 `Send to SQL Hunter (Active SQLi Check)` 把流量送入插件。
   - 只有在你点击“主动检测选中请求”时才发起主动 SQLi 验证请求。

2. **确认注入后自动高亮**
   - 确认存在 SQL 注入后，为对应消息设置高亮与注释。
   - 同时生成 Burp Issue 记录，方便复测和报告。

3. **检测类型覆盖（低误报优化）**
   - 报错注入（Error-based）
   - 布尔盲注（Boolean-based Blind，采用多轮投票+相似度判定）
   - 时间盲注（Time-based Blind，采用基线采样+动态阈值）
   - 内置基础绕 WAF payload 变体（内联注释、括号闭合、多数据库延时语句）

4. **主动检测任务控制**
   - 支持暂停检测 / 恢复检测。
   - 支持停止当前主动检测任务。

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

- 勾选 `被动监听实时流量`：自动收集经过 Burp 的候选请求。
- 点击 `扫描 Proxy History`：批量导入历史流量。
- 在 HTTP 历史/请求上右键：`Send to SQL Hunter (Active SQLi Check)`。
- 在 SQL Hunter 表格中选中目标，点击 `主动检测选中请求` 触发主动验证。
- 点击 `暂停检测` 可挂起后续 payload 请求；点击 `恢复检测` 继续执行。
- 点击 `停止检测` 可中断当前主动检测任务。

## 说明

- 默认时间盲注 payload 使用 `WAITFOR DELAY`（SQL Server 风格）。
- 如需覆盖 MySQL/PostgreSQL/Oracle 等，可在 `BurpExtender.java` 中扩展 payload 与判定逻辑。
