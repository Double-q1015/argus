# 存储迁移工具

这个目录包含了一些用于在不同存储系统之间迁移数据的脚本。

## 可用脚本

### 1. 通用迁移脚本

`migrate_storage.py` 是一个通用的迁移脚本，可以在任何支持的存储系统之间迁移数据。

使用方法：

```bash
python migrate_storage.py \
  --name "迁移任务名称" \
  --description "迁移任务描述" \
  --source-storage minio \
  --source-config '{"endpoint": "localhost:9000", "access_key": "minioadmin", "secret_key": "minioadmin", "secure": false, "bucket_name": "argus-samples"}' \
  --target-storage local \
  --target-config '{"base_path": "/path/to/local/storage"}' \
  --file-patterns "*.exe,*.dll"
```

参数说明：

- `--name`: 迁移任务名称（必填）
- `--description`: 迁移任务描述（可选）
- `--source-storage`: 源存储类型，可选值：minio、s3、local（必填）
- `--source-config`: 源存储配置，JSON格式（必填）
- `--target-storage`: 目标存储类型，可选值：minio、s3、local（必填）
- `--target-config`: 目标存储配置，JSON格式（必填）
- `--file-patterns`: 文件匹配模式，逗号分隔的列表，例如：*.exe,*.dll（可选）

### 2. MinIO到本地存储的迁移脚本

`migrate_minio_to_local.py` 是一个专门用于从MinIO迁移到本地存储的脚本。

使用方法：

```bash
python migrate_minio_to_local.py
```

这个脚本会使用配置文件中的MinIO设置作为源存储，并将文件迁移到配置文件中指定的本地存储路径。

### 3. MinIO到本地存储的示例脚本

`migrate_minio_to_local_example.py` 是一个示例脚本，展示如何使用迁移服务从MinIO迁移到本地存储。

使用方法：

```bash
python migrate_minio_to_local_example.py
```

这个脚本会创建一个迁移任务，将MinIO中的.exe和.dll文件迁移到本地存储。

## 存储配置示例

### MinIO配置

```json
{
  "endpoint": "localhost:9000",
  "access_key": "minioadmin",
  "secret_key": "minioadmin",
  "secure": false,
  "bucket_name": "argus-samples"
}
```

### S3配置

```json
{
  "endpoint": "https://s3.amazonaws.com",
  "access_key": "your-access-key",
  "secret_key": "your-secret-key",
  "region": "us-east-1",
  "bucket_name": "your-bucket",
  "secure": true
}
```

### 本地存储配置

```json
{
  "base_path": "/path/to/local/storage"
}
```

## 注意事项

1. 确保在运行迁移脚本之前，已经正确配置了源存储和目标存储。
2. 对于本地存储，脚本会自动创建存储目录（如果不存在）。
3. 迁移过程是异步的，脚本会等待迁移完成并显示结果。
4. 如果迁移过程中出现错误，脚本会记录错误信息并返回失败状态。 