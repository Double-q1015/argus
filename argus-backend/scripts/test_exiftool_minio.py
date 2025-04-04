import asyncio
from minio import Minio
from app.core.exiftool_analyzer import perform_exiftool_analysis
from app.core.config import settings

async def test_minio_sample():
    """测试从MinIO获取样本元数据"""
    # 创建MinIO客户端
    minio_client = Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )

    # 指定要分析的对象
    bucket_name = "samples"
    object_name = "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"

    try:
        # 检查对象是否存在
        minio_client.stat_object(bucket_name, object_name)
        print(f"对象存在: {bucket_name}/{object_name}")
        print("正在获取对象元数据...\n")

        # 分析对象
        metadata = await perform_exiftool_analysis(
            minio_client=minio_client,  # 修改参数名以匹配函数定义
            bucket_name=bucket_name,
            object_name=object_name,
            file_path=None  # 添加 file_path 参数
        )

        # 打印分析结果
        print("分析结果:")
        print(f"文件类型: {metadata.file_type} ({metadata.mime_type})")
        print(f"文件大小: {metadata.file_size} 字节")
        print(f"架构: {metadata.get_architecture()}")
        print(f"编译时间: {metadata.get_compilation_timestamp()}")
        print(f"子系统: {metadata.get_subsystem_type()}")
        print("\n文件特征:")
        for char in metadata.image_file_characteristics_description:
            print(f"- {char}")
        
        print("\nPE文件信息:")
        print(f"类型: {metadata.pe_type_description}")
        print(f"入口点: {metadata.entry_point}")
        print(f"代码段大小: {metadata.code_size}")
        print(f"初始化数据大小: {metadata.initialized_data_size}")
        
        if metadata.object_size:
            print("\nMinIO对象信息:")
            print(f"对象大小: {metadata.object_size}")
            print(f"最后修改时间: {metadata.object_last_modified}")
            print(f"ETag: {metadata.object_etag}")

    except Exception as e:
        print(f"测试失败: {e}")

if __name__ == "__main__":
    asyncio.run(test_minio_sample()) 