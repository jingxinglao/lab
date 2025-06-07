# 校园卡管理系统

## 项目介绍
本系统是一个基于 Node.js 和 Web 技术栈开发的校园卡管理系统，提供校园卡基本信息管理、余额充值、消费记录查询等功能。系统采用前后端分离架构，前端使用原生 JavaScript 开发，后端基于 Express 框架实现。

## 技术栈
- 前端：原生 HTML/CSS/JavaScript
- 后端：Node.js + Express
- 数据库：SQLite3
- 身份验证：JWT (JSON Web Token)
- 密码加密：bcrypt
- 跨域支持：cors

## 功能特性

### 用户功能
- [x] 用户登录/注册
- [x] 个人信息管理
  - 查看/修改个人资料
  - 修改密码
  - 查看账户余额
- [x] 校园卡功能
  - 在线充值
  - 查看消费记录
  - 查看充值记录
- [x] 实时余额显示

### 管理员功能
- [x] 用户管理
  - 创建新用户
  - 查看用户列表
  - 冻结/解冻用户
  - 删除用户
- [x] 数据管理
  - 用户信息搜索
  - 按院系筛选
- [x] 系统监控
  - 操作日志记录
  - 系统状态监控

## 项目结构
```
campus_card_system/
├─public/              # 前端静态文件
│  └─index.html        # 主页面
├─server.js           # 后端服务器代码
├─package.json        # 项目依赖配置
├─README.md           # 项目说明文档
└─campus_card.db      # SQLite数据库文件
```

## 数据库设计

### 主要数据表
1. users (用户表)
   - 基本信息：id, username, password, name, student_id
   - 卡片信息：card_number, balance, status
   - 附加信息：department, phone, email, role

2. consumption_records (消费记录表)
   - 交易信息：id, user_id, amount, merchant
   - 状态信息：status, created_at, balance_after

3. recharge_records (充值记录表)
   - 充值信息：id, user_id, amount, method
   - 交易状态：status, transaction_id, created_at

4. operation_logs (操作日志表)
   - 操作信息：id, user_id, action, target_user_id
   - 详细记录：details, ip_address, created_at

## 本地部署

### 环境要求
- Node.js 14.x 或更高版本
- SQLite3
- 现代浏览器（支持ES6+）

### 安装步骤
1. 安装依赖
```bash
npm install
```

2. 启动服务器
```bash
node server.js
```

3. 访问系统
- 打开浏览器访问：http://127.0.0.1:3000
- 默认管理员账号：admin / admin123
- 测试用户账号：zhangsan / 123456

## 安全特性
1. 密码加密
   - 使用 bcrypt 进行密码加密存储
   - 密码传输采用 HTTPS（生产环境）

2. 身份验证
   - 基于 JWT 的token认证
   - token有效期24小时
   - 角色权限控制

3. 操作审计
   - 记录所有关键操作
   - 包含操作时间、IP地址等信息

## 开发指南

### API文档

#### 用户接口
- POST /api/login - 用户登录
- GET /api/profile - 获取个人信息
- PUT /api/profile - 修改个人信息
- POST /api/recharge - 校园卡充值

#### 管理接口
- GET /api/admin/users - 获取用户列表
- POST /api/admin/users - 创建新用户
- DELETE /api/admin/users/:id - 删除用户
- PUT /api/admin/users/:id/status - 修改用户状态

### 代码规范
- 使用 ES6+ 语法
- 采用 RESTful API 设计
- 统一错误处理和响应格式
- 遵循 ESLint 规则（可选）

## 维护说明

### 日常维护
1. 数据库备份
   - 定期备份SQLite数据库文件
   - 建议每天进行增量备份

2. 日志管理
   - 定期清理过期日志
   - 监控系统异常日志

3. 性能优化
   - 定期检查数据库性能
   - 优化查询语句
   - 清理临时文件

### 常见问题
1. 连接问题
   - 检查服务器状态
   - 确认端口是否被占用
   - 验证数据库连接

2. 权限问题
   - 检查用户角色设置
   - 验证token有效性
   - 确认操作权限

## 版权说明
© 2024 School Project. All Rights Reserved.
仅用于学习和教育目的。

## 更新日志
- 2024-01-20: 初始版本发布
  - 实现基本功能
  - 完成用户和管理员界面
- 2024-01-21: 优化系统
  - 添加实时余额显示
  - 优化用户体验
  - 增强系统安全性
