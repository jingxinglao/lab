# 校园卡管理系统

## 项目结构

```shell
campus_card_system/
├─public/          # 前端静态文件
│  └─index.html    # 主页面
├─server.js        # 后端服务器代码
├─package-lock.json   # 项目依赖配置
└─campus_card.db      # SQLite数据库文件
```

## 后端本地部署运行

### 环境要求
- Node.js 14.x 或更高版本
- SQLite3

### 安装依赖
```bash
npm install
```

需要安装的主要依赖：
- express
- sqlite3
- bcrypt
- jsonwebtoken
- cors

### 数据库
- 系统使用 SQLite 数据库，无需额外配置
- 数据库文件会自动在根目录创建：`campus_card.db`
- 首次运行时会自动创建所需的表和测试数据

### 运行服务器
```bash
node server.js
```

服务器将在以下地址启动：
- 地址：http://127.0.0.1:3000
- 测试账号：
  - 管理员：admin / admin123
  - 普通用户：zhangsan / 123456

## 前端本地部署运行

### 环境要求
- 现代浏览器（支持ES6+）
- Node.js（如果需要本地开发）

### 开发模式运行
```bash
# 如果需要使用开发服务器
npm install -g http-server
http-server public
```

### 直接访问
- 可以直接通过浏览器访问 `public/index.html`
- 或通过后端服务器访问：http://127.0.0.1:3000

## 功能特性

### 用户功能
- 用户注册
- 登录认证
- 查看个人信息
- 修改个人信息
- 查看消费记录
- 查看充值记录
- 在线充值

### 管理员功能
- 用户管理
- 系统监控
- 操作日志
- 数据统计
- 记录导出

## 技术栈
- 前端：原生 HTML/CSS/JavaScript
- 后端：Node.js + Express
- 数据库：SQLite3
- 认证：JWT (JSON Web Token)
