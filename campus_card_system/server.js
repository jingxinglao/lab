// ================================
// 后端服务器代码 (server.js)
// ================================

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'campus_card_secret_key_2024';

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// 生成卡号函数
function generateCardNumber() {
    const year = new Date().getFullYear();
    const randomNum = Math.floor(Math.random() * 100000).toString().padStart(5, '0');
    return `${year}${randomNum}`;
}

// 数据库路径处理
const dbPath = path.resolve(__dirname, 'campus_card.db');
console.log('服务器数据库路径:', dbPath);

// 确保数据库目录存在
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// 数据库初始化
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('数据库连接错误:', err);
        process.exit(1);
    }
    console.log('数据库连接成功');
});

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
    db.run(`CREATE TABLE IF NOT EXISTS operation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action VARCHAR(100) NOT NULL,
        action_type VARCHAR(50),
        action_content TEXT,
        target_user_id INTEGER,
        details TEXT,
        ip_address VARCHAR(50),
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
            ['ADMIN001', 'admin', hashedPassword, 'ADMIN001', '系统管理员', '信息中心', 'admin', null]
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

// 更新日志记录函数
const logOperation = (userId, action, targetUserId = null, details = null, ipAddress = null) => {
    db.run(`INSERT INTO operation_logs (
        user_id, 
        action,
        action_type,
        action_content,
        target_user_id, 
        details, 
        ip_address
    ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, action, action, details, targetUserId, details, ipAddress]
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

// 用户注册
app.post('/api/register', async (req, res) => {
    const { username, password, student_id, name, department } = req.body;

    // 数据验证
    if (!username || !password || !student_id || !name || !department) {
        return res.status(400).json({ error: '所有字段都是必填的' });
    }

    if (username.length < 3) {
        return res.status(400).json({ error: '用户名至少需要3个字符' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: '密码至少需要6个字符' });
    }

    if (!/^\d{8,12}$/.test(student_id)) {
        return res.status(400).json({ error: '学号须为8-12位数字' });
    }

    try {
        // 检查重复用户
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT id FROM users WHERE username = ? OR student_id = ?', 
                [username, student_id], 
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        if (existingUser) {
            return res.status(400).json({ error: '用户名或学号已被注册' });
        }

        // 生成卡号（年份+5位序号）
        const year = new Date().getFullYear();
        const latestCard = await new Promise((resolve, reject) => {
            db.get('SELECT card_number FROM users WHERE card_number LIKE ? ORDER BY card_number DESC LIMIT 1',
                [`${year}%`],
                (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
        });

        let sequenceNum = '00001';
        if (latestCard) {
            const lastSeq = parseInt(latestCard.card_number.slice(-5));
            sequenceNum = String(lastSeq + 1).padStart(5, '0');
        }
        const cardNumber = `${year}${sequenceNum}`;

        // 密码加密
        const hashedPassword = await bcrypt.hash(password, 10);

        // 创建新用户
        await new Promise((resolve, reject) => {
            db.run(`INSERT INTO users (
                card_number, username, password, student_id, 
                name, department, role, balance
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [cardNumber, username, hashedPassword, student_id, name, department, 'user', 0.00],
            function(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });

        // 记录操作日志
        logOperation(null, '用户注册', null, 
            `新用户: ${username}, 学号: ${student_id}`, req.ip);

        res.status(201).json({ 
            success: true, 
            message: '注册成功',
            card_number: cardNumber
        });

    } catch (error) {
        console.error('注册错误:', error);
        res.status(500).json({ error: '注册失败，请稍后重试' });
    }
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
    const { page = 1, limit = 20, search = '', department = '' } = req.query;
    const offset = (page - 1) * limit;

    let sql = `SELECT id, card_number, username, student_id, name, department, 
                      phone, email, balance, status, role, created_at, updated_at 
               FROM users`;
    let params = [];
    let conditions = [];

    if (search) {
        conditions.push(`(name LIKE ? OR card_number LIKE ? OR student_id LIKE ? OR username LIKE ?)`);
        params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (department) {
        conditions.push(`department = ?`);
        params.push(department);
    }

    if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(' AND ')}`;
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

        if (conditions.length > 0) {
            countSql += ` WHERE ${conditions.join(' AND ')}`;
            countParams = params.slice(0, -2); // 移除 LIMIT 和 OFFSET 参数
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

// 创建新用户
app.post('/api/admin/users', authenticateToken, requireAdmin, (req, res) => {
    const { username, password, name, student_id, department } = req.body;

    if (!username || !password || !name || !student_id || !department) {
        return res.status(400).json({ error: '所有字段都是必填的' });
    }

    // 检查用户名是否已存在
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, existingUser) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (existingUser) {
            return res.status(400).json({ error: '用户名已存在' });
        }

        // 生成卡号
        const cardNumber = generateCardNumber();

        // 加密密码
        bcrypt.hash(password, 10, (err, hashedPassword) => {
            if (err) {
                return res.status(500).json({ error: '密码加密失败' });
            }

            // 创建用户
            db.run(`INSERT INTO users (username, password, name, student_id, department, card_number, role, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'user', 'active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [username, hashedPassword, name, student_id, department, cardNumber],
                function(err) {
                    if (err) {
                        return res.status(500).json({ error: '创建用户失败' });
                    }

                    // 记录操作日志
                    logOperation(
                        req.user.id,
                        '创建用户',
                        this.lastID,
                        `创建用户：${username}，姓名：${name}，学号：${student_id}，院系：${department}，卡号：${cardNumber}`,
                        req.ip
                    );

                    res.json({
                        success: true,
                        message: '用户创建成功',
                        user: {
                            id: this.lastID,
                            username,
                            name,
                            student_id,
                            department,
                            card_number: cardNumber
                        }
                    });
                }
            );
        });
    });
});

// 删除用户
app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;

    // 检查用户是否存在
    db.get('SELECT id, username, name, student_id, department, card_number, role FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }

        // 不允许删除管理员账户
        if (user.role === 'admin') {
            return res.status(403).json({ error: '不能删除管理员账户' });
        }

        // 删除用户
        db.run('DELETE FROM users WHERE id = ?', [userId], function(err) {
            if (err) {
                return res.status(500).json({ error: '删除用户失败' });
            }

            // 记录操作日志
            logOperation(
                req.user.id,
                '删除用户',
                userId,
                `删除用户：${user.username}，姓名：${user.name}，学号：${user.student_id}，院系：${user.department}，卡号：${user.card_number}`,
                req.ip
            );

            res.json({ message: '用户删除成功' });
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
    const { page = 1, limit = 10, search = '', operator = '' } = req.query;
    const offset = (page - 1) * limit;

    let countSql = 'SELECT COUNT(*) as total FROM operation_logs l LEFT JOIN users u ON l.user_id = u.id';
    let sql = `SELECT 
        l.*, 
        u.card_number as operator_card,
        u.name as operator_name,
        l.action as action_type,
        l.details as action_content
    FROM operation_logs l
    LEFT JOIN users u ON l.user_id = u.id`;
    
    const conditions = [];
    const params = [];

    if (search) {
        conditions.push(`(l.action LIKE ? OR l.details LIKE ? OR l.action_type LIKE ? OR l.action_content LIKE ?)`);
        params.push(`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`);
    }
    
    if (operator) {
        conditions.push(`u.card_number = ?`);
        params.push(operator);
    }

    if (conditions.length > 0) {
        sql += ` WHERE ${conditions.join(' AND ')}`;
        countSql += ` WHERE ${conditions.join(' AND ')}`;
    }

    // 查询总记录数
    db.get(countSql, params, (err, count) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        sql += ` ORDER BY l.created_at DESC LIMIT ? OFFSET ?`;
        const queryParams = [...params, limit, offset];

        db.all(sql, queryParams, (err, logs) => {
            if (err) {
                return res.status(500).json({ error: '数据库错误' });
            }

            const formattedLogs = logs.map(log => ({
                ...log,
                created_at: new Date(log.created_at).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
                operator: log.operator_name || log.operator_card || '-'
            }));

            res.json({
                logs: formattedLogs,
                total: count.total,
                page: parseInt(page),
                pages: Math.ceil(count.total / limit)
            });
        });
    });
});

// 获取所有操作人列表
app.get('/api/admin/operators', authenticateToken, requireAdmin, (req, res) => {
    const sql = `
        SELECT DISTINCT u.card_number, u.name 
        FROM users u
        INNER JOIN operation_logs l ON l.user_id = u.id
        WHERE u.card_number IS NOT NULL
        AND u.card_number != ''
        GROUP BY u.card_number, u.name
        ORDER BY u.name ASC
    `;
    
    db.all(sql, [], (err, operators) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }
        res.json(operators);
    });
});

// 创建操作日志
app.post('/api/admin/logs', authenticateToken, requireAdmin, (req, res) => {
    const { action_type, action_content, operator_card } = req.body;

    if (!action_type || !action_content) {
        return res.status(400).json({ error: '操作类型和内容不能为空' });
    }

    // 根据操作人卡号查找用户ID
    db.get('SELECT id FROM users WHERE card_number = ?', [operator_card], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (!user) {
            return res.status(404).json({ error: '操作人不存在' });
        }

        // 插入日志记录
        db.run(`INSERT INTO operation_logs (user_id, action, details, ip_address, created_at) 
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)`,
            [user.id, action_type, action_content, req.ip],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: '记录日志失败' });
                }
                res.json({ success: true, message: '日志记录成功' });
            }
        );
    });
});

// 冻结/解冻用户
app.put('/api/admin/users/:id/status', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    const { status } = req.body;

    if (!['active', 'frozen'].includes(status)) {
        return res.status(400).json({ error: '状态值无效' });
    }

    // 获取用户信息
    db.get('SELECT username, name, student_id, department, card_number FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }

        if (!user) {
            return res.status(404).json({ error: '用户不存在' });
        }

        db.run('UPDATE users SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [status, userId], function(err) {
                if (err) {
                    return res.status(500).json({ error: '数据库错误' });
                }

                if (this.changes === 0) {
                    return res.status(404).json({ error: '用户不存在' });
                }

                // 记录操作日志
                logOperation(
                    req.user.id,
                    `${status === 'active' ? '解冻' : '冻结'}用户`,
                    userId,
                    `${status === 'active' ? '解冻' : '冻结'}用户：${user.username}，姓名：${user.name}，学号：${user.student_id}，院系：${user.department}，卡号：${user.card_number}`,
                    req.ip
                );

                res.json({ success: true, message: `用户${status === 'active' ? '解冻' : '冻结'}成功` });
            }
        );
    });
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