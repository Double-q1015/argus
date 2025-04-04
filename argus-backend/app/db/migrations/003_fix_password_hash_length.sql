USE snake_skin;

-- 修改密码哈希字段长度
ALTER TABLE users MODIFY COLUMN hashed_password VARCHAR(255); 