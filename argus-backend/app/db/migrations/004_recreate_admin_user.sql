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
    created_at
) VALUES (
    'admin',
    'admin@example.com',
    '$2b$12$ZE5jA9Z0e3zB.bpcnvt3BO/Bzri6l7Bo8IORrkueYVWUQF7t.wki.',
    1,
    1,
    NOW()
); 