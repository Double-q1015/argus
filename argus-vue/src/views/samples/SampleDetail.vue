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
          {{ sample?.name }}
        </el-descriptions-item>
        <el-descriptions-item label="MIME类型">
          {{ sample?.mime }}
        </el-descriptions-item>
        <el-descriptions-item label="大小">
          {{ formatBytes(sample?.size || 0) }}
        </el-descriptions-item>
        <el-descriptions-item label="提交类型">
          {{ sample?.submission_type }}
        </el-descriptions-item>
        <el-descriptions-item label="时间戳">
          {{ formatDate(sample?.timestamp) }}
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
            <el-descriptions-item label="文件类型">
              {{ sample?.basic_info.file_type }}
            </el-descriptions-item>
            <el-descriptions-item label="文件大小">
              {{ formatBytes(sample?.basic_info.file_size || 0) }}
            </el-descriptions-item>
            <el-descriptions-item label="MD5">
              {{ sample?.basic_info.md5 }}
            </el-descriptions-item>
            <el-descriptions-item label="SHA1">
              {{ sample?.basic_info.sha1 }}
            </el-descriptions-item>
            <el-descriptions-item label="SHA256">
              {{ sample?.basic_info.sha256 }}
            </el-descriptions-item>
            <el-descriptions-item label="SSDEEP">
              {{ sample?.basic_info.ssdeep }}
            </el-descriptions-item>
          </el-descriptions>
        </el-tab-pane>

        <el-tab-pane label="行为分析">
          <el-collapse>
            <el-collapse-item title="进程活动" name="processes">
              <el-table :data="sample?.behavior_analysis.processes">
                <el-table-column prop="name" label="进程名" />
                <el-table-column prop="pid" label="PID" width="100" />
                <el-table-column prop="ppid" label="父PID" width="100" />
                <el-table-column prop="cmd_line" label="命令行" show-overflow-tooltip />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="文件活动" name="files">
              <el-table :data="sample?.behavior_analysis.files">
                <el-table-column prop="path" label="路径" show-overflow-tooltip />
                <el-table-column prop="operation" label="操作" width="120" />
                <el-table-column prop="timestamp" label="时间戳" width="180" />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="注册表活动" name="registry">
              <el-table :data="sample?.behavior_analysis.registry">
                <el-table-column prop="path" label="路径" show-overflow-tooltip />
                <el-table-column prop="operation" label="操作" width="120" />
                <el-table-column prop="value" label="值" show-overflow-tooltip />
              </el-table>
            </el-collapse-item>
          </el-collapse>
        </el-tab-pane>

        <el-tab-pane label="网络活动">
          <el-collapse>
            <el-collapse-item title="DNS请求" name="dns">
              <el-table :data="sample?.network_activity.dns_requests">
                <el-table-column prop="domain" label="域名" />
                <el-table-column prop="type" label="类型" width="100" />
                <el-table-column prop="answer" label="解析结果" show-overflow-tooltip />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="HTTP请求" name="http">
              <el-table :data="sample?.network_activity.http_requests">
                <el-table-column prop="method" label="方法" width="100" />
                <el-table-column prop="url" label="URL" show-overflow-tooltip />
                <el-table-column label="请求头" width="120">
                  <template #default="{ row }">
                    <el-popover trigger="hover" placement="right">
                      <template #reference>
                        <el-button link>查看</el-button>
                      </template>
                      <div class="headers-popover">
                        <pre>{{ JSON.stringify(row.headers, null, 2) }}</pre>
                      </div>
                    </el-popover>
                  </template>
                </el-table-column>
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="网络连接" name="connections">
              <el-table :data="sample?.network_activity.connections">
                <el-table-column prop="protocol" label="协议" width="100" />
                <el-table-column prop="src_ip" label="源IP" />
                <el-table-column prop="src_port" label="源端口" width="100" />
                <el-table-column prop="dst_ip" label="目标IP" />
                <el-table-column prop="dst_port" label="目标端口" width="100" />
              </el-table>
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
              <el-table :data="filteredStrings">
                <el-table-column prop="value" label="字符串" />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="导入表" name="imports">
              <el-table :data="sample?.static_analysis.imports">
                <el-table-column prop="value" label="导入函数" />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="导出表" name="exports">
              <el-table :data="sample?.static_analysis.exports">
                <el-table-column prop="value" label="导出函数" />
              </el-table>
            </el-collapse-item>

            <el-collapse-item title="节表" name="sections">
              <el-table :data="sample?.static_analysis.sections">
                <el-table-column prop="name" label="名称" />
                <el-table-column prop="size" label="大小">
                  <template #default="{ row }">
                    {{ formatBytes(row.size) }}
                  </template>
                </el-table-column>
                <el-table-column prop="entropy" label="熵值">
                  <template #default="{ row }">
                    {{ row.entropy.toFixed(2) }}
                  </template>
                </el-table-column>
              </el-table>
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
import { formatBytes } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const store = useSamplesStore()
const stringsFilter = ref('')

const sample = computed(() => store.currentSample)

const filteredStrings = computed(() => {
  if (!sample.value?.static_analysis.strings) return []
  if (!stringsFilter.value) return sample.value.static_analysis.strings
  return sample.value.static_analysis.strings.filter((str: string) =>
    str.toLowerCase().includes(stringsFilter.value.toLowerCase())
  )
})

const formatDate = (timestamp?: string) => {
  if (!timestamp) return ''
  return new Date(timestamp).toLocaleString()
}

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