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
    '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyDAXxZxQqQK6e',
    1,
    1,
    0,
    NOW()
); 