// ================================
// 后端服务器代码 (server.js)
// ================================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'campus_card_secret_key_2024';

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const dbPath = path.resolve('./campus_card.db');
console.log('服务器数据库路径:', dbPath);

// 数据库初始化
const db = new sqlite3.Database(dbPath);

// 创建数据表
db.serialize(() => {
    // 用户表 - 添加角色权限字段
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        card_number VARCHAR(20) UNIQUE NOT NULL,
        username VARCHAR(50) NOT NULL,
        password VARCHAR(255) NOT NULL,
        student_id VARCHAR(20) UNIQUE NOT NULL,
        name VARCHAR(50) NOT NULL,
        department VARCHAR(100),
        phone VARCHAR(20),
        email VARCHAR(100),
        balance DECIMAL(10,2) DEFAULT 0.00,
        status VARCHAR(20) DEFAULT 'active',
        role VARCHAR(20) DEFAULT 'user',
        department_role VARCHAR(50),    /* 部门角色 */
        permissions TEXT,               /* JSON格式存储权限 */
        last_login DATETIME,           /* 上次登录时间 */
        login_ip VARCHAR(50),          /* 登录IP */
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 角色权限表 - 新增
    db.run(`CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name VARCHAR(50) UNIQUE NOT NULL,
        description TEXT,
        permissions TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 部门表 - 新增
    db.run(`CREATE TABLE IF NOT EXISTS departments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        parent_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (parent_id) REFERENCES departments(id)
    )`);

    // 系统配置表 - 新增
    db.run(`CREATE TABLE IF NOT EXISTS system_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_key VARCHAR(50) UNIQUE NOT NULL,
        config_value TEXT,
        description TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 充值记录表 - 补充字段
    //db.run(`DROP TABLE IF EXISTS recharge_records`);
    db.run(`CREATE TABLE IF NOT EXISTS recharge_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        from_user_id INTEGER,
        amount DECIMAL(10,2) NOT NULL,
        method VARCHAR(50) DEFAULT 'transfer',
        transaction_id VARCHAR(100),
        status VARCHAR(20) DEFAULT 'completed',
        remark TEXT,                    /* 备注信息 */
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (from_user_id) REFERENCES users(id)
    )`);

    // 消费记录表 - 补充字段
    db.run(`CREATE TABLE IF NOT EXISTS consumption_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount DECIMAL(10,2) NOT NULL,
        merchant VARCHAR(100),
        merchant_id INTEGER,            /* 商户ID */
        device_id VARCHAR(50),          /* 设备ID */
        transaction_type VARCHAR(50),   /* 交易类型 */
        description VARCHAR(200),
        balance_after DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'completed',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // 操作日志表 - 补充字段
    //db.run(`DROP TABLE IF EXISTS operation_logs`);
    db.run(`CREATE TABLE IF NOT EXISTS operation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        operator_name VARCHAR(50),
        action VARCHAR(100) NOT NULL,
        target_user_id INTEGER,
        details TEXT,
        ip_address VARCHAR(50),
        module VARCHAR(50),             /* 操作模块 */
        level VARCHAR(20),              /* 操作级别 */
        status VARCHAR(20),             /* 操作状态 */
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // 系统监控记录表 - 补充字段
    db.run(`CREATE TABLE IF NOT EXISTS system_monitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        monitor_type VARCHAR(50) NOT NULL,
        description TEXT,
        severity VARCHAR(20) DEFAULT 'info',
        details TEXT,
        resource_usage TEXT,           /* CPU/内存等资源使用情况 */
        alert_threshold TEXT,          /* 告警阈值 */
        is_resolved BOOLEAN,          /* 是否已解决 */
        resolved_at DATETIME,         /* 解决时间 */
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 插入初始数据
    const saltRounds = 10;
    
    // 创建管理员账户
    bcrypt.hash('admin123', saltRounds, (err, hashedPassword) => {
        if (err) return;
        db.run(`INSERT OR IGNORE INTO users 
            (card_number, username, password, student_id, name, department, role, balance) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            ['ADMIN001', 'admin', hashedPassword, 'ADMIN001', '系统管理员', '信息中心', 'admin', 10000.00]
        );
    });

    // 创建测试用户
    bcrypt.hash('123456', saltRounds, (err, hashedPassword) => {
        if (err) return;
        const testUsers = [
            ['2024001001', 'zhangsan', hashedPassword, '2024001001', '张三', '计算机学院', 'user', 500.00, '13800138001', 'zhangsan@campus.edu'],
            ['2024001002', 'lisi', hashedPassword, '2024001002', '李四', '经济管理学院', 'user', 300.00, '13800138002', 'lisi@campus.edu'],
            ['2024001003', 'wangwu', hashedPassword, '2024001003', '王五', '机械工程学院', 'user', 800.00, '13800138003', 'wangwu@campus.edu']
        ];

        testUsers.forEach(user => {
            db.run(`INSERT OR IGNORE INTO users 
                (card_number, username, password, student_id, name, department, role, balance, phone, email) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, user);
        });
    });

    // 插入示例消费记录
    setTimeout(() => {
        const consumptionRecords = [
            [2, 15.50, '食堂一楼', '午餐', 484.50],
            [2, 8.00, '超市', '日用品', 476.50],
            [3, 12.00, '食堂二楼', '晚餐', 288.00],
            [4, 25.30, '图书馆咖啡厅', '咖啡+点心', 774.70]
        ];

        consumptionRecords.forEach(record => {
            db.run(`INSERT OR IGNORE INTO consumption_records 
                (user_id, amount, merchant, description, balance_after) 
                VALUES (?, ?, ?, ?, ?)`, record);
        });
    }, 1000);
});

// JWT验证中间件
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: '访问令牌缺失' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: '令牌无效' });
        }
        req.user = user;
        next();
    });
};

// 管理员权限验证中间件
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: '需要管理员权限' });
    }
    next();
};

// 记录操作日志
const logOperation = (userId, action, targetUserId = null, details = null, ipAddress = null) => {
    db.run(`INSERT INTO operation_logs (user_id, action, target_user_id, details, ip_address) 
            VALUES (?, ?, ?, ?, ?)`,
        [userId, action, targetUserId, details, ipAddress]
    );
};

// 系统监控记录
const logSystemEvent = (type, description, severity = 'info', details = null) => {
    db.run(`INSERT INTO system_monitors (monitor_type, description, severity, details) 
            VALUES (?, ?, ?, ?)`,
        [type, description, severity, details]
    );
};

// ================================
// API 路由
// ================================

// 用户登录
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    db.get('SELECT * FROM users WHERE username = ? OR card_number = ?', 
        [username, username], 
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            if (!user) {
                return res.status(401).json({ error: '用户不存在' });
            }

            if (user.status !== 'active') {
                return res.status(401).json({ error: '账户已被冻结' });
            }

            bcrypt.compare(password, user.password, (err, result) => {
                if (err || !result) {
                    return res.status(401).json({ error: '密码错误' });
                }

                const token = jwt.sign(
                    { 
                        id: user.id, 
                        username: user.username, 
                        role: user.role,
                        card_number: user.card_number
                    },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );

                logOperation(user.id, '用户登录', null, null, req.ip);

                res.json({
                    token,
                    user: {
                        id: user.id,
                        username: user.username,
                        name: user.name,
                        role: user.role,
                        card_number: user.card_number
                    }
                });
            });
        }
    );
});

// 获取用户个人信息
app.get('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.id;

    db.get(`SELECT id, card_number, username, student_id, name, department, 
                   phone, email, balance, status, created_at 
            FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }

        // 获取最近充值记录
        db.get(`SELECT amount, created_at FROM recharge_records 
                WHERE user_id = ? ORDER BY created_at DESC LIMIT 1`,
            [userId], (err, lastRecharge) => {
                res.json({
                    ...user,
                    last_recharge: lastRecharge
                });
            }
        );
    });
});

// 获取消费记录
app.get('/api/consumption-records', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    db.all(`SELECT * FROM consumption_records 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?`,
        [userId, limit, offset], (err, records) => {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            // 获取总数
            db.get(`SELECT COUNT(*) as total FROM consumption_records WHERE user_id = ?`,
                [userId], (err, count) => {
                    res.json({
                        records,
                        total: count.total,
                        page: parseInt(page),
                        pages: Math.ceil(count.total / limit)
                    });
                }
            );
        }
    );
});

// 获取充值记录
app.get('/api/recharge-records', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;

    db.all(`SELECT * FROM recharge_records 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?`,
        [userId, limit, offset], (err, records) => {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            db.get(`SELECT COUNT(*) as total FROM recharge_records WHERE user_id = ?`,
                [userId], (err, count) => {
                    res.json({
                        records,
                        total: count.total,
                        page: parseInt(page),
                        pages: Math.ceil(count.total / limit)
                    });
                }
            );
        }
    );
});

// 在线充值
app.post('/api/recharge', authenticateToken, (req, res) => {
    const { amount, target_card, target_password } = req.body;
    const userId = req.user.id;

    if (!amount || amount <= 0) {
        return res.status(400).json({ error: '充值金额必须大于0' });
    }

    if (!target_card || !target_password) {
        return res.status(400).json({ error: '卡号和密码不能为空' });
    }

    // 验证目标卡号和密码是否匹配当前用户
    db.get('SELECT * FROM users WHERE id = ?', [userId], (err, currentUser) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (!currentUser || currentUser.card_number !== target_card) {
            return res.status(401).json({ error: '卡号与当前账户不匹配' });
        }

        bcrypt.compare(target_password, currentUser.password, (err, match) => {
            if (err || !match) {
                return res.status(401).json({ error: '密码错误' });
            }

            const transactionId = Date.now().toString();

            db.serialize(() => {
                db.run('BEGIN TRANSACTION');

                // 增加余额
                db.run(
                    'UPDATE users SET balance = balance + ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [amount, userId]
                );

                // 记录充值记录
                db.run(
                    `INSERT INTO recharge_records 
                     (user_id, from_user_id, amount, method, transaction_id, status) 
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [userId, userId, amount, 'recharge', transactionId, 'completed']
                );

                // 记录日志（可选）
                logOperation(userId, '在线充值', userId, `充值金额: ${amount}元`, req.ip);

                db.run('COMMIT', (err) => {
                    if (err) {
                        db.run('ROLLBACK');
                        return res.status(500).json({ error: '充值失败' });
                    }

                    db.get('SELECT balance FROM users WHERE id = ?', [userId], (err, updatedUser) => {
                        if (err) {
                            return res.status(500).json({ error: '无法获取更新后余额' });
                        }

                        res.json({
                            success: true,
                            message: '充值成功',
                            transaction_id: transactionId,
                            new_balance: updatedUser.balance,
                            to_user: currentUser.name
                        });

                        console.log(`[充值成功] 交易 ID: ${transactionId}, 用户 ID: ${userId}, 金额: ${amount}`);
                    });
                });
            });
        });
    });
});


// 修改个人信息
app.put('/api/profile', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { name, department, phone, email } = req.body;

    const updates = [];
    const values = [];

    if (name) {
        updates.push('name = ?');
        values.push(name);
    }
    if (department) {
        updates.push('department = ?');
        values.push(department);
    }
    if (phone) {
        updates.push('phone = ?');
        values.push(phone);
    }
    if (email) {
        updates.push('email = ?');
        values.push(email);
    }

    if (updates.length === 0) {
        return res.status(400).json({ error: '没有需要更新的信息' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    values.push(userId);

    const sql = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;

    db.run(sql, values, function(err) {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        logOperation(userId, '修改个人信息', null, 
            `更新字段: ${updates.slice(0, -1).join(', ')}`, req.ip);

        res.json({ success: true, message: '信息更新成功' });
    });
});

// 修改密码
app.put('/api/change-password', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const { old_password, new_password } = req.body;

    if (!old_password || !new_password) {
        return res.status(400).json({ error: '旧密码和新密码不能为空' });
    }

    if (new_password.length < 6) {
        return res.status(400).json({ error: '新密码长度至少6位' });
    }

    // 验证旧密码
    db.get('SELECT password FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        bcrypt.compare(old_password, user.password, (err, result) => {
            if (err || !result) {
                return res.status(401).json({ error: '旧密码错误' });
            }

            // 加密新密码
            bcrypt.hash(new_password, 10, (err, hashedPassword) => {
                if (err) {
                    return res.status(500).json({ error: '密码加密失败' });
                }

                db.run('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                    [hashedPassword, userId], (err) => {
                        if (err) {
                            return res.status(500).json({ error: '数据库错误' });
                        }

                        logOperation(userId, '修改密码', null, null, req.ip);
                        res.json({ success: true, message: '密码修改成功' });
                    }
                );
            });
        });
    });
});

// ================================
// 管理员 API
// ================================

// 获取所有用户列表
app.get('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const { page = 1, limit = 20, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let sql = `SELECT id, card_number, username, student_id, name, department, 
                      phone, email, balance, status, role, created_at, updated_at 
               FROM users`;
    let params = [];

    if (search) {
        sql += ` WHERE name LIKE ? OR card_number LIKE ? OR student_id LIKE ?`;
        params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }

    sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    db.all(sql, params, (err, users) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        // 获取总数
        let countSql = 'SELECT COUNT(*) as total FROM users';
        let countParams = [];

        if (search) {
            countSql += ` WHERE name LIKE ? OR card_number LIKE ? OR student_id LIKE ?`;
            countParams = [`%${search}%`, `%${search}%`, `%${search}%`];
        }

        db.get(countSql, countParams, (err, count) => {
            res.json({
                users,
                total: count.total,
                page: parseInt(page),
                pages: Math.ceil(count.total / limit)
            });
        });
    });
});

// 获取角色列表
app.get('/api/admin/roles', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT * FROM roles ORDER BY created_at DESC', [], (err, roles) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }
        res.json(roles);
    });
});

// 获取部门列表
app.get('/api/admin/departments', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT * FROM departments ORDER BY name', [], (err, departments) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }
        res.json(departments);
    });
});

// 获取系统实时状态
app.get('/api/admin/system-status', authenticateToken, requireAdmin, (req, res) => {
    const status = {
        cpu_usage: process.cpuUsage(),
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        connections: 0, // 实际项目中需要跟踪连接数
        last_error: null
    };
    
    logSystemEvent('status_check', '系统状态检查', 'info', JSON.stringify(status));
    res.json(status);
});

// 获取过滤后的日志
app.get('/api/admin/logs/filter', authenticateToken, requireAdmin, (req, res) => {
    const { startDate, endDate, level, module } = req.query;
    let sql = 'SELECT l.*, u.name as operator_name FROM operation_logs l LEFT JOIN users u ON l.user_id = u.id WHERE 1=1';
    const params = [];

    if (startDate) {
        sql += ' AND DATE(l.created_at) >= DATE(?)';
        params.push(startDate);
    }
    if (endDate) {
        sql += ' AND DATE(l.created_at) <= DATE(?)';
        params.push(endDate);
    }
    if (level) {
        sql += ' AND l.level = ?';
        params.push(level);
    }
    if (module) {
        sql += ' AND l.module = ?';
        params.push(module);
    }

    sql += ' ORDER BY l.created_at DESC';

    db.all(sql, params, (err, logs) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }
        res.json(logs);
    });
});

// 获取系统统计信息
app.get('/api/admin/statistics', authenticateToken, requireAdmin, (req, res) => {
    db.serialize(() => {
        const stats = {};

        // 用户总数
        db.get('SELECT COUNT(*) as total FROM users WHERE role = "user"', (err, result) => {
            stats.total_users = result.total;
        });

        // 今日新增用户
        db.get(`SELECT COUNT(*) as today FROM users 
                WHERE role = "user" AND DATE(created_at) = DATE('now')`, (err, result) => {
            stats.today_new_users = result.today;
        });

        // 总余额
        db.get('SELECT SUM(balance) as total FROM users WHERE role = "user"', (err, result) => {
            stats.total_balance = result.total || 0;
        });

        // 今日充值金额
        db.get(`SELECT SUM(amount) as today FROM recharge_records 
                WHERE DATE(created_at) = DATE('now')`, (err, result) => {
            stats.today_recharge = result.today || 0;
        });

        // 今日消费金额
        db.get(`SELECT SUM(amount) as today FROM consumption_records 
                WHERE DATE(created_at) = DATE('now')`, (err, result) => {
            stats.today_consumption = result.today || 0;

            res.json(stats);
        });
    });
});

// 获取操作日志
app.get('/api/admin/logs', authenticateToken, requireAdmin, (req, res) => {
    const { page = 1, limit = 50 } = req.query;
    const offset = (page - 1) * limit;

    db.all(`SELECT l.*, u.name as user_name, tu.name as target_user_name
            FROM operation_logs l
            LEFT JOIN users u ON l.user_id = u.id
            LEFT JOIN users tu ON l.target_user_id = tu.id
            ORDER BY l.created_at DESC
            LIMIT ? OFFSET ?`,
        [limit, offset], (err, logs) => {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            db.get('SELECT COUNT(*) as total FROM operation_logs', (err, count) => {
                res.json({
                    logs,
                    total: count.total,
                    page: parseInt(page),
                    pages: Math.ceil(count.total / limit)
                });
            });
        }
    );
});

// 冻结/解冻用户
app.put('/api/admin/users/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { status } = req.body;

    if (!['active', 'frozen'].includes(status)) {
        return res.status(400).json({ error: '状态值无效' });
    }

    db.run('UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        [status, userId], function(err) {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            if (this.changes === 0) {
                return res.status(404).json({ error: '用户不存在' });
            }

            logOperation(req.user.id, `${status === 'active' ? '解冻' : '冻结'}用户`, 
                userId, null, req.ip);

            res.json({ success: true, message: `用户${status === 'active' ? '解冻' : '冻结'}成功` });
        }
    );
});

// 管理员快捷操作
app.post('/api/admin/quick-actions', authenticateToken, requireAdmin, (req, res) => {
    const { action } = req.body;

    switch (action) {
        case 'freeze_inactive_cards':
            db.run(`UPDATE users 
                   SET status = 'frozen' 
                   WHERE role = 'user' 
                   AND status = 'active'
                   AND id NOT IN (
                       SELECT DISTINCT user_id 
                       FROM consumption_records 
                       WHERE created_at >= datetime('now', '-30 day')
                   )`, [], function(err) {
                if (err) return res.status(500).json({ error: '操作失败' });
                logOperation(req.user.id, '批量冻结卡片', null, 
                    `冻结 ${this.changes} 张长期未使用的卡片`, req.ip);
                res.json({ success: true, message: `已冻结 ${this.changes} 张卡片` });
            });
            break;

        case 'clear_expired_logs':
            db.run(`DELETE FROM operation_logs 
                   WHERE created_at < datetime('now', '-90 day')`, 
                [], function(err) {
                if (err) return res.status(500).json({ error: '操作失败' });
                logOperation(req.user.id, '清理过期日志', null, 
                    `清理 ${this.changes} 条过期日志`, req.ip);
                res.json({ success: true, message: `已清理 ${this.changes} 条日志` });
            });
            break;

        default:
            res.status(400).json({ error: '未知的操作类型' });
    }
});

// 启动服务器
app.listen(PORT, '127.0.0.1', () => {
    console.log(`校园卡管理系统服务器已启动`);
    console.log(`访问地址: http://127.0.0.1:${PORT}`);
    console.log(`管理员账号: admin / admin123`);
    console.log(`测试用户: zhangsan / 123456`);
});

// ================================
// 前端HTML代码 (保存为 public/index.html)
// ================================