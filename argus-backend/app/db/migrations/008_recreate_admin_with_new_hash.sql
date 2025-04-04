USE snake_skin;

-- 删除现有的admin用户
DELETE FROM users WHERE username = 'admin';

-- 重新创建admin用户（密码：admin123）
INSERT INTO users (
    username,
    email,
    hashed_password,
    is_active,
    is_superuser,
    login_attempts,
    created_at
) VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$jjnl/b11lgXnmyaKBy8uIOzn51ssxlGUUifJc98Mq3bGGC03W94kW',
    1,
    1,
    0,
    NOW()
); 