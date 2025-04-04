-- 添加用户表缺失字段
SET @dbname = 'snake_skin';
SET @tablename = 'users';

-- 检查并添加last_login列
SET @colname = 'last_login';
SET @coltype = 'DATETIME';
SET @sql = CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN IF NOT EXISTS ', @colname, ' ', @coltype, ' NULL AFTER created_at');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加login_attempts列
SET @colname = 'login_attempts';
SET @coltype = 'INT DEFAULT 0';
SET @sql = CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN IF NOT EXISTS ', @colname, ' ', @coltype, ' AFTER last_login');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;

-- 检查并添加last_login_attempt列
SET @colname = 'last_login_attempt';
SET @coltype = 'DATETIME';
SET @sql = CONCAT('ALTER TABLE ', @tablename, ' ADD COLUMN IF NOT EXISTS ', @colname, ' ', @coltype, ' NULL AFTER login_attempts');
PREPARE stmt FROM @sql;
EXECUTE stmt;
DEALLOCATE PREPARE stmt; 