<template>
  <div class="sample-list">
    <div class="header">
      <h2>样本列表</h2>
      <el-button type="primary" @click="handleCreate">
        <el-icon><plus /></el-icon>新建样本
      </el-button>
    </div>

    <el-table
      v-loading="loading"
      :data="samples"
      style="width: 100%"
      border
    >
      <el-table-column prop="sha256_digest" label="SHA256摘要" min-width="200">
        <template #default="{ row }">
          <router-link :to="`/samples/${row.sha256_digest}`">
            {{ row.sha256_digest }}
          </router-link>
        </template>
      </el-table-column>
      
      <el-table-column prop="timestamp" label="时间戳" width="180">
        <template #default="{ row }">
          {{ formatDate(row.timestamp) }}
        </template>
      </el-table-column>
      
      <el-table-column prop="mime" label="MIME类型" width="120">
        <template #default="{ row }">
          {{ formatMimeType(row.mime) }}
        </template>
      </el-table-column>
      
      <el-table-column prop="size" label="大小" width="120">
        <template #default="{ row }">
          {{ formatBytes(row.size) }}
        </template>
      </el-table-column>
      
      <el-table-column prop="submission_type" label="提交类型" width="120" />
      
      <el-table-column prop="name" label="名称" min-width="150" />
      
      <el-table-column label="标签" min-width="200">
        <template #default="{ row }">
          <el-tag
            v-for="tag in formatTags(row.tags)"
            :key="tag"
            class="mx-1"
            size="small"
          >
            {{ tag }}
          </el-tag>
        </template>
      </el-table-column>
      
      <el-table-column label="操作" width="280" fixed="right">
        <template #default="{ row }">
          <el-button-group>
            <el-button
              type="primary"
              size="small"
              @click="handleEdit(row)"
            >
              编辑
            </el-button>
            <el-button
              type="success"
              size="small"
              @click="handleEncryptedDownload(row)"
            >
              加密下载
            </el-button>
            <el-button
              type="danger"
              size="small"
              @click="handleDelete(row)"
            >
              删除
            </el-button>
          </el-button-group>
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination">
      <el-pagination
        v-model:current-page="currentPage"
        v-model:page-size="pageSize"
        :page-sizes="[10, 20, 50, 100]"
        :total="total"
        layout="total, sizes, prev, pager, next"
        @size-change="handleSizeChange"
        @current-change="handleCurrentChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { useSamplesStore } from '@/store/modules/samples'
import { useUserStore } from '@/store/modules/user'
import { formatBytes, formatTags, formatDate, formatMimeType } from '@/utils/format'

const router = useRouter()
const samplesStore = useSamplesStore()
const userStore = useUserStore()

const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const samples = ref([])

const fetchSamples = async () => {
  loading.value = true
  try {
    await samplesStore.fetchSamples({
      limit: pageSize.value,
      page: currentPage.value,
      order: -1,
      sort: 'timestamp'
    })
    samples.value = samplesStore.samples
    total.value = samplesStore.pagination?.total || 0
  } catch (error) {
    ElMessage.error('获取样本列表失败')
  } finally {
    loading.value = false
  }
}

const handleCreate = () => {
  router.push('/samples/create')
}

const handleEdit = (row: any) => {
  router.push(`/samples/${row.sha256_digest}/edit`)
}

const handleDelete = async (row: any) => {
  try {
    await ElMessageBox.confirm(
      '确定要删除这个样本吗？',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    )
    await samplesStore.deleteSample(row.sha256_digest)
    ElMessage.success('删除成功')
    fetchSamples()
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除失败')
    }
  }
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  fetchSamples()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  fetchSamples()
}

const handleEncryptedDownload = async (row: any) => {
  try {
    const response = await fetch(`/api/v1/samples/${row.sha256_digest}/download?password=infected`, {
      headers: {
        'Authorization': `Bearer ${userStore.token}`
      }
    })
    
    if (!response.ok) {
      throw new Error('下载请求失败')
    }
    
    const data = await response.json()
    if (!data.download_url) {
      throw new Error('未获取到下载URL')
    }
    
    // 创建一个临时的a标签来触发下载
    const link = document.createElement('a')
    link.href = data.download_url
    link.download = `${row.name || row.sha256_digest}.zip`
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    
    ElMessage.success('加密下载已开始')
  } catch (err: any) {
    console.error('加密下载失败:', err)
    ElMessage.error('加密下载失败: ' + (err.message || '未知错误'))
  }
}

onMounted(() => {
  fetchSamples()
})
</script>

<style scoped>
.sample-list {
  padding: 20px;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.header h2 {
  margin: 0;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.mx-1 {
  margin: 0 4px;
}
</style> 