<template>
  <div class="sample-detail">
    <el-card v-loading="store.detailLoading">
      <template #header>
        <div class="card-header">
          <span>样本详情</span>
          <div class="header-actions">
            <el-button type="primary" @click="handleEdit">编辑</el-button>
            <el-popconfirm
              title="确定要删除这个样本吗？"
              @confirm="handleDelete"
            >
              <template #reference>
                <el-button type="danger">删除</el-button>
              </template>
            </el-popconfirm>
          </div>
        </div>
      </template>

      <el-descriptions :column="2" border>
        <el-descriptions-item label="SHA256摘要">
          {{ sample?.sha256_digest }}
        </el-descriptions-item>
        <el-descriptions-item label="名称">
          {{ sample?.file_name }}
        </el-descriptions-item>
        <el-descriptions-item label="标签" :span="2">
          <el-tag
            v-for="tag in sample?.tags"
            :key="tag"
            class="mx-1"
          >
            {{ tag }}
          </el-tag>
        </el-descriptions-item>
      </el-descriptions>

      <el-tabs class="mt-4">
        <el-tab-pane label="基本信息">
          <el-descriptions :column="2" border>
          </el-descriptions>
        </el-tab-pane>

        <el-tab-pane label="行为分析">
          <el-collapse>
            <el-collapse-item title="进程活动" name="processes">
            </el-collapse-item>

            <el-collapse-item title="文件活动" name="files">
            </el-collapse-item>

          </el-collapse>
        </el-tab-pane>

        <el-tab-pane label="网络活动">
          <el-collapse>
            <el-collapse-item title="DNS请求" name="dns">
            </el-collapse-item>

            <el-collapse-item title="HTTP请求" name="http">
            </el-collapse-item>

            <el-collapse-item title="网络连接" name="connections">
            </el-collapse-item>
          </el-collapse>
        </el-tab-pane>

        <el-tab-pane label="静态分析">
          <el-collapse>
            <el-collapse-item title="字符串" name="strings">
              <el-input
                v-model="stringsFilter"
                placeholder="搜索字符串..."
                clearable
                class="mb-2"
              />
            </el-collapse-item>
          </el-collapse>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useSamplesStore } from '@/stores/samples'

const route = useRoute()
const router = useRouter()
const store = useSamplesStore()
const stringsFilter = ref('')

const sample = computed(() => store.currentSample)

const handleEdit = () => {
  router.push(`/samples/${route.params.id}/edit`)
}

const handleDelete = async () => {
  try {
    const success = await store.deleteSample(route.params.id as string)
    if (success) {
      router.push('/samples')
    }
  } catch (error) {
    console.error('删除样本失败:', error)
  }
}

onMounted(async () => {
  await store.fetchSampleDetail(route.params.id as string)
})

onBeforeUnmount(() => {
  store.clearCurrentSample()
})
</script>

<style scoped>
.sample-detail {
  padding: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 10px;
}

.mt-4 {
  margin-top: 1rem;
}

.mb-2 {
  margin-bottom: 0.5rem;
}

.mx-1 {
  margin: 0 0.25rem;
}

.headers-popover {
  max-width: 400px;
  max-height: 300px;
  overflow: auto;
}

:deep(.el-descriptions) {
  margin-bottom: 1rem;
}

:deep(.el-collapse-item__content) {
  padding: 1rem;
}

:deep(.el-table) {
  margin-bottom: 1rem;
}
</style> 