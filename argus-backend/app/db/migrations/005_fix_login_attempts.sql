USE snake_skin;

-- 更新现有用户的login_attempts值为0
UPDATE users SET login_attempts = 0 WHERE login_attempts IS NULL;

-- 修改login_attempts字段，确保不为空
ALTER TABLE users MODIFY COLUMN login_attempts INT NOT NULL DEFAULT 0; 