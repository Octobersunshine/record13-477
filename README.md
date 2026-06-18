# Security Group IP Rule Management API (Go)

Go 语言开发的安全组 IP 规则管理接口，支持创建、修改安全组放行与拦截 IP 规则，**规则即刻生效**（通过操作系统防火墙实时应用）。

## 项目特性

- **规则 CRUD**：创建、查询、修改、删除安全组规则
- **即刻生效**：规则变更后立即应用到操作系统防火墙
- **多后端支持**：
  - Windows: `netsh advfirewall` (Windows 高级防火墙)
  - 跨平台: Mock 后端（用于测试和非 Windows 环境）
- **支持规则类型**：
  - 放行 (allow) / 拦截 (deny)
  - 入站 (inbound) / 出站 (outbound)
  - TCP / UDP / ANY 协议
  - 单 IP 或 CIDR 网段
  - 单个端口或端口范围
- **优先级管理**：支持 1-10000 优先级设置
- **启停控制**：规则可单独启用/禁用，无需删除
- **持久化存储**：SQLite 数据库持久化
- **全量同步**：支持手动/启动时自动同步所有规则到防火墙
- **批量操作**：支持批量创建、批量修改，全有或全无事务语义
- **回滚机制**：所有变更操作支持失败自动回滚，确保状态一致性
- **审批流**：高危规则变更需二级管理员审批后方可生效

## 项目结构

```
477/
├── main.go                    # 程序入口
├── go.mod                     # 依赖管理
├── config/
│   └── config.go             # 配置加载（命令行+环境变量）
├── models/
│   └── models.go             # 数据模型与请求/响应结构
├── repository/
│   └── repository.go         # 数据访问层（SQLite GORM）
├── firewall/
│   ├── firewall.go           # 防火墙管理器（核心调度逻辑）
│   ├── windows_netsh.go      # Windows netsh 后端实现
│   └── mock_backend.go       # Mock 后端（测试/跨平台）
├── service/
│   ├── service.go            # 业务逻辑层
│   └── service_test.go       # 业务逻辑单元测试
└── handlers/
    └── handlers.go           # REST API 处理器（Gin）
```

## 快速开始

### 环境要求

- Go 1.21+
- Windows 系统（使用 netsh 后端时需要管理员权限）

### 安装依赖

```bash
go mod tidy
go mod download
```

### 启动服务

```bash
# 默认启动（Windows 自动使用 netsh，其他平台使用 mock）
go run main.go

# 指定端口和数据库路径
go run main.go -port 8080 -db ./sg.db

# 强制使用 mock 后端（跨平台开发测试）
go run main.go -firewall mock

# 禁用启动时自动同步
go run main.go -autosync=false
```

### 环境变量配置

| 变量名 | 说明 | 默认值 |
|--------|------|--------|
| `SG_PORT` | HTTP 服务端口 | 8080 |
| `SG_DB_PATH` | SQLite 数据库路径 | securitygroup.db |
| `SG_FIREWALL_MODE` | 防火墙模式: auto/netsh/mock | auto |
| `SG_AUTO_SYNC` | 启动时自动同步: true/false | true |
| `SG_LOG_LEVEL` | 日志级别: debug/info/error | info |
| `SG_TRUSTED_PROXY` | 可信代理 CIDR | (空) |

## REST API 接口

### 基础信息

- Base URL: `http://localhost:8080/api`
- Content-Type: `application/json`

### 1. 健康检查

```
GET /api/health
```

响应示例：
```json
{
  "status": "ok",
  "backend": "windows-netsh"
}
```

### 2. 创建规则（即刻生效）

```
POST /api/rules
```

请求体：
```json
{
  "group_id": "web-sg-001",
  "group_name": "Web 服务器安全组",
  "description": "允许办公网络访问 HTTP",
  "action": "allow",
  "direction": "inbound",
  "protocol": "TCP",
  "ip_address": "192.168.1.0/24",
  "port_start": 80,
  "port_end": 80,
  "priority": 100
}
```

字段说明：

| 字段 | 必填 | 类型 | 说明 |
|------|------|------|------|
| `group_id` | ✅ | string | 安全组 ID |
| `group_name` | | string | 安全组名称 |
| `description` | | string | 规则描述 |
| `action` | ✅ | string | `allow`(放行) / `deny`(拦截) |
| `direction` | | string | `inbound`(入站,默认) / `outbound`(出站) |
| `protocol` | | string | `TCP` / `UDP` / `ANY`(默认) |
| `ip_address` | ✅ | string | IP 地址或 CIDR，如 `10.0.0.1` 或 `10.0.0.0/8` |
| `port_start` | | int | 起始端口 1-65535 |
| `port_end` | | int | 结束端口 1-65535，需 >= port_start |
| `priority` | | int | 优先级 1-10000，越小越优先，默认 100 |

响应示例（201 Created）：
```json
{
  "code": 0,
  "message": "created",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "group_id": "web-sg-001",
    "group_name": "Web 服务器安全组",
    "action": "allow",
    "direction": "inbound",
    "protocol": "TCP",
    "ip_address": "192.168.1.0/24",
    "port_start": 80,
    "port_end": 80,
    "priority": 100,
    "status": "active",
    "firewall_id": "SG_web-sg-001_550e8400",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
}
```

### 3. 查询规则列表

```
GET /api/rules?group_id=xxx&action=allow&status=active&page=1&page_size=20
```

查询参数：

| 参数 | 说明 |
|------|------|
| `group_id` | 按安全组 ID 过滤 |
| `action` | 按动作过滤: allow/deny |
| `status` | 按状态过滤: active/disabled/error |
| `page` | 页码，默认 1 |
| `page_size` | 每页数量，默认 20，最大 100 |

响应示例：
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "total": 2,
    "list": [
      {
        "id": "...",
        "group_id": "web-sg-001",
        "action": "allow",
        "ip_address": "192.168.1.0/24",
        "port_start": 80,
        "status": "active",
        "firewall_id": "SG_..."
      },
      {
        "id": "...",
        "group_id": "web-sg-001",
        "action": "deny",
        "ip_address": "10.0.0.5",
        "status": "active",
        "firewall_id": "SG_..."
      }
    ]
  }
}
```

### 4. 获取单个规则详情

```
GET /api/rules/:id
```

### 5. 修改规则（即刻生效）

```
PUT /api/rules/:id
```

请求体（所有字段可选，只传需要修改的字段）：
```json
{
  "action": "deny",
  "ip_address": "10.0.0.100",
  "port_start": 443,
  "port_end": 443,
  "description": "已修改为拦截 HTTPS 访问"
}
```

修改后规则会**立即重新应用到防火墙**（旧规则删除，新规则添加）。

### 6. 启用/禁用规则

```
PUT /api/rules/:id
```

禁用（从防火墙移除但保留在数据库）：
```json
{
  "status": "disabled"
}
```

重新启用（立即添加到防火墙）：
```json
{
  "status": "active"
}
```

### 7. 删除规则

```
DELETE /api/rules/:id
```

删除时会**自动从防火墙移除对应规则**。

### 8. 全量同步规则

```
POST /api/rules/sync
```

清理防火墙中所有由本系统管理的规则（前缀 `SG_`），然后根据数据库中的 active 规则重新构建。

适用于：
- 防火墙规则被意外修改后恢复
- 服务重启后需要强制对齐
- 数据库手动修改后同步

## 核心设计：规则即刻生效机制

### 架构分层

```
API 层 (handlers)
    ↓
业务层 (service)  ───→  事务协调：先操作防火墙，再落库
    ↓
防火墙管理器 (firewall.Manager)  ───→  状态机调度 + 回滚管理
    ↓
具体后端 (FirewallBackend)
    ├── WindowsNetshBackend → netsh advfirewall 命令
    └── MockBackend → 内存模拟（测试用，支持故障注入）
```

### 关键保证

1. **创建流程**：先 `netsh add rule` → 成功后写入 DB
   - 防火墙失败：不写入 DB，返回错误
   - DB 失败：自动 `netsh delete rule` 回滚

2. **修改流程**：对比差异 → 有变化则「删旧+加新」
   - 检测到规则关键字段（动作/方向/协议/IP/端口）变化才触发防火墙操作
   - 仅修改描述/名称等不触发防火墙变更
   - **新增**：删旧成功但加新失败时，自动回滚恢复旧规则

3. **启停切换**：
   - active→disabled: 从防火墙删除，保留 DB 记录
   - disabled→active: 重新添加到防火墙
   - **新增**：操作失败时自动恢复到切换前状态

4. **删除流程**：先从防火墙移除 → 再删除 DB 记录
   - **新增**：DB 删除失败时自动回滚，重新添加防火墙规则

5. **错误处理**：
   - 防火墙操作失败且成功回滚：返回 `ErrRollbackOccurred`，HTTP 409 Conflict
   - 防火墙操作失败且无法回滚：标记 `status=error` 并记录 `error_msg`
   - 所有操作返回 `RollbackInfo`，包含上一版本完整状态

## 回滚机制设计（新增）

### 回滚管理器（RollbackManager）

位于 [firewall/rollback.go](file:///e:/temp/record13/477/firewall/rollback.go)，实现备忘录（Memento）模式：

```
操作前：记录操作类型 + 完整快照
操作中：每成功一步，记录到回滚日志
操作失败：逆序执行回滚日志中的反向操作
操作成功：Commit() 清空回滚日志
```

支持的操作类型：

| 操作类型 | 正向操作 | 反向操作（回滚） |
|---------|---------|----------------|
| `OpAdd` | AddRule | DeleteRule |
| `OpDelete` | DeleteRule | AddRule |
| `OpUpdate` | Delete(old) + Add(new) | Delete(new) + Add(old) |

### 原子性操作矩阵

| 操作 | 成功路径 | 失败回滚路径 |
|-----|---------|-------------|
| 单条创建 | Add → DB 写入 | 已 Add 但 DB 失败 → Delete |
| 单条修改 | Delete(old) → Add(new) → DB 更新 | Delete(old) 成功但 Add(new) 失败 → Add(old) |
| 单条删除 | Delete → DB 删除 | Delete 成功但 DB 失败 → Add(old) |
| 启停切换 | Add/Disable → DB 更新 | 操作失败 → 恢复原始状态 |
| 批量创建 | N × (Add → DB 写入) | 第 M 条失败 → 回滚前 M-1 条的 Add + DB 删除 |
| 批量修改 | N × (Delete(old) → Add(new) → DB 更新) | 第 M 条失败 → 回滚前 M-1 条的 Update + DB 恢复 |
| 全量同步 | Delete(all) → N × Add → DB 更新 | 第 M 条失败 → 回滚所有已删除 + 已添加的规则 |

### 回滚信息（RollbackInfo）

所有变更操作返回 `RollbackInfo` 结构：

```json
{
  "success": false,
  "rollbacked": true,
  "rollback_errors": ["rollback executed"],
  "previous_state": {
    "id": "rule-uuid",
    "group_id": "web-sg-001",
    "action": "allow",
    "ip_address": "192.168.1.0/24",
    "port_start": 80,
    "status": "active",
    "firewall_id": "SG_web-sg-001_abc12345"
  }
}
```

字段说明：
- `success`: 操作是否最终成功
- `rollbacked`: 是否执行了回滚
- `rollback_errors`: 回滚过程中发生的错误（空表示回滚成功）
- `previous_state`: 操作前的完整规则快照，便于人工核查

### HTTP 状态码约定

| 场景 | HTTP 状态码 | 业务码 | 说明 |
|-----|-----------|--------|------|
| 操作成功 | 200/201 | 0 | 正常成功 |
| 部分验证失败 | 207 Multi-Status | 207xxx | 仅验证失败，无状态变更 |
| 操作失败但成功回滚 | 409 Conflict | 409xxx | 已恢复到操作前状态 |
| 操作失败无法回滚 | 424 Failed Dependency | 424xxx | 状态不一致，需人工干预 |

### 回滚测试覆盖

位于 [service/rollback_test.go](file:///e:/temp/record13/477/service/rollback_test.go)，包含 9 个专项测试：

- `TestUpdateRule_AddNewRuleFail_Rollback` - 修改时添加新规则失败，回滚恢复旧规则
- `TestUpdateRule_DeleteOldFail_Rollback` - 修改时删除旧规则失败，回滚
- `TestBatchCreate_ThirdItemFails_AllRollback` - 批量创建第3条失败，全部回滚
- `TestBatchUpdate_SecondItemFails_AllRollback` - 批量修改第2条失败，全部回滚
- `TestSyncAll_ThirdRuleFails_AllRollback` - 同步时第3条失败，全部回滚
- `TestToggleStatus_DisableFail_Rollback` - 禁用失败，回滚保持启用
- `TestRollbackInfo_PreviousStatePreserved` - 验证上一版本状态完整保留
- `TestBatchCreate_PartialValidationFail_NoRollbackNeeded` - 验证失败不触发回滚

## 审批流设计（新增）

### 设计目标

高危规则变更（如全网段 deny、高优先级规则、批量操作等）需要二级管理员审批后方可生效，防止误操作导致安全事故。

### 风险等级判定

系统自动评估每个操作的风险等级，**高风险（high）及以上**需要审批：

| 风险等级 | 判定条件 | 是否需要审批 |
|---------|---------|-------------|
| `low` | 普通 allow 规则，非全网段，正常优先级 | 否 |
| `medium` | 修改关键字段、启停 deny 规则、删除规则等 | 否 |
| `high` | deny 规则、全网段 allow、高优先级(≤20)、批量≥5条 | **是** |
| `critical` | deny + 全网段、极高优先级(≤5)、批量≥20条 | **是** |

### 高危操作场景

以下操作会自动进入审批流程：

1. **创建规则**：
   - `action = deny`
   - `priority ≤ 20`
   - `ip = 0.0.0.0/0` 且为 allow

2. **修改规则**：
   - 修改为 deny
   - 修改为全网段 IP
   - 优先级降低到 ≤ 20
   - 禁用的 deny 规则重新启用

3. **删除规则**：
   - 删除全网段 allow 规则

4. **批量操作**：
   - 批量创建 ≥ 5 条
   - 批量修改 ≥ 5 条
   - 或批量中包含高危规则

### 审批状态机

```
pending → approved → executed
   ↓         ↓
rejected  cancelled
```

| 状态 | 说明 | 可执行操作 |
|-----|------|-----------|
| `pending` | 待审批 | 批准 / 拒绝 / 撤销 |
| `approved` | 已批准，待执行 | 执行 / 撤销 |
| `rejected` | 已拒绝 | - |
| `executed` | 已执行 | - |
| `cancelled` | 已撤销 | - |
| `failed` | 执行失败 | - |

### 审批流 API

#### 1. 查询审批列表

```
GET /api/approvals?status=pending&operation_type=create&applicant=user1&page=1&page_size=20
```

#### 2. 获取审批详情

```
GET /api/approvals/{id}
```

#### 3. 批准审批

```
POST /api/approvals/{id}/approve
```

请求体：
```json
{
  "approver": "admin",
  "remark": "同意"
}
```

#### 4. 拒绝审批

```
POST /api/approvals/{id}/reject
```

请求体：
```json
{
  "approver": "admin",
  "remark": "风险太高，不同意"
}
```

#### 5. 执行已批准的审批

```
POST /api/approvals/{id}/execute
```

批准后需显式调用执行接口，规则才会真正生效。执行时会触发完整的回滚机制。

响应示例：
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "success": true,
    "result": { /* 执行结果，如创建的规则 */ },
    "rollback_info": { ... }
  }
}
```

#### 6. 撤销审批

```
POST /api/approvals/{id}/cancel
```

只能撤销待审批（pending）状态的审批单。

#### 7. 风险评估

```
POST /api/approvals/evaluate-risk
```

提交规则创建参数，预评估风险等级。

请求体：
```json
{
  "group_id": "test-sg",
  "action": "deny",
  "ip_address": "0.0.0.0/0",
  "priority": 10
}
```

响应：
```json
{
  "code": 0,
  "message": "success",
  "data": {
    "risk_level": "critical",
    "is_high_risk": true,
    "approval_needed": true
  }
}
```

### 规则接口集成审批

所有规则变更接口自动检测风险等级，高危操作**不直接执行**，而是创建审批单并返回 `202 Accepted`：

```
POST /api/rules          # 创建规则
PUT  /api/rules/{id}     # 修改规则
DELETE /api/rules/{id}   # 删除规则
POST /api/rules/batch    # 批量创建
PUT  /api/rules/batch    # 批量修改
```

**请求头**：通过 `X-Applicant` 头部指定申请人（默认 `anonymous`）

**高危操作响应示例**（HTTP 202 Accepted）：
```json
{
  "code": 20201,
  "message": "High-risk operation requires approval. Approval request created.",
  "data": {
    "approval_id": "550e8400-e29b-41d4-a716-446655440000",
    "risk_level": "high",
    "status": "pending",
    "approval": { ... 完整审批单 ... }
  }
}
```

**低风险操作**：正常执行，与原行为一致。

### 审批流测试覆盖

位于 [service/approval_test.go](file:///e:/temp/record13/477/service/approval_test.go)，包含 12+ 个专项测试：

- `TestEvaluateCreateRisk_DenyHighRisk` - deny 规则判定为高风险
- `TestEvaluateCreateRisk_DenyWildcardCritical` - deny + 全网段判定为极高风险
- `TestEvaluateCreateRisk_HighPriorityCritical` - 高优先级判定为极高风险
- `TestCreateApprovalForCreate_HighRisk` - 高危创建自动生成审批单
- `TestCreateApprovalForCreate_LowRiskNoApproval` - 低危操作无需审批
- `TestApproveApproval` - 批准审批单
- `TestRejectApproval` - 拒绝审批单
- `TestExecuteApprovedCreate` - 执行已批准的创建操作
- `TestExecuteApprovedUpdate` - 执行已批准的修改操作
- `TestCancelApproval` - 撤销待审批单
- `TestBatchCreateRisk_ManyItemsHighRisk` - 大批量操作判定为高风险

## Windows 防火墙命名约定

通过 netsh 创建的规则名称格式：`SG_{GroupID}_{RuleID前缀8位}`

例如：`SG_web-sg-001_550e8400`

这样可以识别哪些规则由本系统管理，同步时可安全清理。

## 运行测试

```bash
# 运行业务逻辑单元测试（使用 mock 后端，无需真实防火墙权限）
go test -v ./service/

# 运行全部测试
go test -v ./...

# 测试覆盖率
go test -cover ./...
```

测试覆盖场景：
- 创建放行/拦截规则并验证防火墙即刻生效
- 修改规则 IP/端口后验证旧规则删除、新规则添加
- 启用→禁用→重新启用的状态流转
- 删除规则同步清理防火墙
- 输入参数校验（无效端口范围、缺失必填项等）
- 规则过滤查询
- 全量同步清理重建

## 常见场景示例

### 场景 1：屏蔽某个恶意 IP（立即拦截）

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "blacklist",
    "action": "deny",
    "direction": "inbound",
    "ip_address": "203.0.113.45",
    "priority": 1
  }'
```

**生效时间**：毫秒级，立即被 Windows 防火墙拦截。

### 场景 2：开放办公网段访问 SSH

```bash
curl -X POST http://localhost:8080/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "ops-team",
    "group_name": "运维组访问",
    "description": "允许运维网段 SSH",
    "action": "allow",
    "direction": "inbound",
    "protocol": "TCP",
    "ip_address": "10.10.0.0/16",
    "port_start": 22,
    "priority": 50
  }'
```

### 场景 3：临时禁用某条规则（不删除）

```bash
curl -X PUT http://localhost:8080/api/rules/{rule-id} \
  -H "Content-Type: application/json" \
  -d '{"status": "disabled"}'
```

## 注意事项

1. **权限要求**：Windows 下需要以管理员身份运行，否则 netsh 命令会失败
2. **规则冲突**：Windows 防火墙本身的拦截优先级高于放行（deny 优先）
3. **规则前缀**：不要手动修改名称以 `SG_` 开头的 Windows 防火墙规则，会被同步时清理
4. **生产建议**：生产环境使用前先以 `-firewall mock` 模式验证 API 逻辑
