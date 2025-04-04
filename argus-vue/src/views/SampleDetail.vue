<template>
  <div class="sample-detail">
    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <h2>样本详情</h2>
          <el-tag :type="getStatusType(sample?.analysis_status)">
            {{ sample?.analysis_status }}
          </el-tag>
        </div>
      </template>

      <!-- 基本信息 -->
      <el-descriptions title="基本信息" :column="2" border>
        <el-descriptions-item label="文件名">
          {{ sample?.file_name }}
        </el-descriptions-item>
        <el-descriptions-item label="SHA256">
          <span class="monospace">{{ sample?.sha256_digest }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="MD5">
          <span class="monospace">{{ sample?.md5_digest }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="SSDEEP">
          <span class="monospace">{{ sample?.ssdeep_hash }}</span>
        </el-descriptions-item>
        <el-descriptions-item label="文件大小">
          {{ formatFileSize(sample?.file_size || 0) }}
        </el-descriptions-item>
        <el-descriptions-item label="文件类型">
          {{ sample?.file_type }}
        </el-descriptions-item>
        <el-descriptions-item label="上传时间">
          {{ formatDate(sample?.upload_time) }}
        </el-descriptions-item>
        <el-descriptions-item label="分析时间">
          {{ formatDate(sample?.analysis_time) }}
        </el-descriptions-item>
      </el-descriptions>

      <!-- PE 信息 -->
      <template v-if="sample?.pe_info">
        <el-divider />
        <el-descriptions title="PE 信息" :column="2" border>
          <el-descriptions-item label="编译时间">
            {{ formatDate(sample.pe_info.compile_time) }}
          </el-descriptions-item>
          <el-descriptions-item label="入口点">
            {{ sample.pe_info.entry_point }}
          </el-descriptions-item>
          <el-descriptions-item label="平台">
            {{ sample.pe_info.platform }}
          </el-descriptions-item>
          <el-descriptions-item label="是否签名">
            {{ sample.pe_info.is_signed ? '是' : '否' }}
          </el-descriptions-item>
          <el-descriptions-item label="公司名称">
            {{ sample.pe_info.company_name }}
          </el-descriptions-item>
          <el-descriptions-item label="产品名称">
            {{ sample.pe_info.product_name }}
          </el-descriptions-item>
          <el-descriptions-item label="原始文件名">
            {{ sample.pe_info.original_filename }}
          </el-descriptions-item>
          <el-descriptions-item label="PDB 路径">
            {{ sample.pe_info.pdb_path }}
          </el-descriptions-item>
        </el-descriptions>

        <!-- 节信息 -->
        <el-divider />
        <h3>节信息</h3>
        <el-table :data="sample.pe_info.sections" style="width: 100%">
          <el-table-column prop="name" label="节名称" width="120" />
          <el-table-column prop="virtual_address" label="虚拟地址" width="120">
            <template #default="{ row }">
              {{ formatHex(row.virtual_address) }}
            </template>
          </el-table-column>
          <el-table-column prop="virtual_size" label="虚拟大小" width="120">
            <template #default="{ row }">
              {{ formatHex(row.virtual_size) }}
            </template>
          </el-table-column>
          <el-table-column prop="raw_size" label="原始大小" width="120">
            <template #default="{ row }">
              {{ formatHex(row.raw_size) }}
            </template>
          </el-table-column>
          <el-table-column prop="entropy" label="熵值" width="100">
            <template #default="{ row }">
              {{ row.entropy.toFixed(2) }}
            </template>
          </el-table-column>
          <el-table-column prop="characteristics" label="特征" />
        </el-table>

        <!-- 导入信息 -->
        <el-divider />
        <h3>导入信息</h3>
        <el-table :data="sample.pe_info.imports" style="width: 100%">
          <el-table-column prop="dll" label="DLL" min-width="150" />
          <el-table-column prop="functions" label="函数">
            <template #default="{ row }">
              <el-tag
                v-for="func in row.functions"
                :key="func"
                size="small"
                class="mr-1"
              >
                {{ func }}
              </el-tag>
            </template>
          </el-table-column>
        </el-table>
      </template>

      <!-- 资源信息 -->
      <template v-if="sample?.resources">
        <el-divider />
        <h3>资源信息</h3>
        <el-table :data="sample.resources" style="width: 100%">
          <el-table-column prop="type" label="类型" width="120" />
          <el-table-column prop="language" label="语言" width="120" />
          <el-table-column prop="size" label="大小" width="120">
            <template #default="{ row }">
              {{ formatFileSize(row.size) }}
            </template>
          </el-table-column>
          <el-table-column prop="offset" label="偏移" width="120">
            <template #default="{ row }">
              {{ formatHex(row.offset) }}
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import { getSample } from '@/api/samples'
import type { SampleDetail } from '@/api/samples'

const route = useRoute()
const loading = ref(false)
const sample = ref<SampleDetail | null>(null)

// 获取样本详情
const fetchSampleDetail = async () => {
  const sha256 = route.params.sha256 as string
  if (!sha256) {
    ElMessage.error('无效的样本 SHA256')
    return
  }

  loading.value = true
  try {
    sample.value = await getSample(sha256)
  } catch (error: any) {
    ElMessage.error('获取样本详情失败：' + (error.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

// 格式化文件大小
const formatFileSize = (size: number) => {
  const units = ['B', 'KB', 'MB', 'GB']
  let index = 0
  let fileSize = size

  while (fileSize >= 1024 && index < units.length - 1) {
    fileSize /= 1024
    index++
  }

  return `${fileSize.toFixed(2)} ${units[index]}`
}

// 格式化日期
const formatDate = (date: string | null) => {
  if (!date) return '-'
  return new Date(date).toLocaleString()
}

// 格式化十六进制
const formatHex = (value: number) => {
  return `0x${value.toString(16).toUpperCase()}`
}

// 获取状态标签类型
const getStatusType = (status: string | undefined) => {
  if (!status) return 'info'
  const types: Record<string, string> = {
    'pending': 'info',
    'processing': 'warning',
    'completed': 'success',
    'failed': 'danger'
  }
  return types[status] || 'info'
}

onMounted(() => {
  fetchSampleDetail()
})
</script>

<style scoped>
.sample-detail {
  padding: 20px;
  min-height: 100vh;
  background-color: var(--el-bg-color);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.monospace {
  font-family: monospace;
}

.mr-1 {
  margin-right: 4px;
}

:deep(.el-descriptions) {
  margin-bottom: 20px;
}

h3 {
  margin: 16px 0;
  color: var(--el-text-color-primary);
  font-size: 16px;
}
</style> 