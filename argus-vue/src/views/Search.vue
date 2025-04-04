<template>
  <div class="search-container">
    <el-card class="search-card">
      <template #header>
        <div class="card-header">
          <h2>搜索</h2>
          <el-tooltip content="查看搜索帮助" placement="top">
            <el-button
              type="primary"
              text
              class="help-button"
              @click="showHelp = true"
            >
              <el-icon class="help-icon"><QuestionFilled /></el-icon>
            </el-button>
          </el-tooltip>
        </div>
      </template>

      <div class="search-form">
        <el-input
          v-model="searchQuery"
          type="textarea"
          :rows="4"
          placeholder="输入搜索条件，例如：&#10;md5:d41d8cd98f00b204e9800998ecf8427e&#10;sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3&#10;filename:test.exe"
          class="search-input"
        />
        <div class="search-actions">
          <el-button type="primary" :loading="loading" @click="handleSearch">
            搜索
          </el-button>
        </div>
      </div>

      <!-- 搜索结果表格 -->
      <div v-if="searchResults.length > 0" class="search-results">
        <el-table
          :data="searchResults"
          style="width: 100%"
          v-loading="loading"
        >
          <el-table-column
            prop="sha256_digest"
            label="SHA256"
            width="280"
          >
            <template #default="{ row }">
              <span class="monospace">{{ row.sha256_digest }}</span>
            </template>
          </el-table-column>
          <el-table-column
            prop="file_name"
            label="文件名"
            min-width="200"
          >
            <template #default="{ row }">
              <el-link type="primary" @click="viewSample(row)">{{ row.file_name }}</el-link>
              <el-tag size="small" class="ml-2" :type="getStatusType(row.analysis_status)">
                {{ row.analysis_status }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column
            prop="description"
            label="描述"
            min-width="200"
            show-overflow-tooltip
          />
          <el-table-column
            prop="file_size"
            label="大小"
            width="120"
          >
            <template #default="{ row }">
              {{ formatFileSize(row.file_size) }}
            </template>
          </el-table-column>
          <el-table-column
            prop="file_type"
            label="类型"
            width="150"
            show-overflow-tooltip
          />
        </el-table>
      </div>
    </el-card>

    <!-- 搜索帮助对话框 -->
    <el-dialog
      v-model="showHelp"
      title="搜索帮助"
      width="700px"
    >
      <div class="search-help">
        <h4>基础搜索</h4>
        <p>支持以下基础搜索类型：</p>
        <div class="search-examples basic-search">
          <div class="example">
            <div class="example-title">SHA256 哈希搜索：</div>
            <code>sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</code>
          </div>
          <div class="example">
            <div class="example-title">文件名搜索：</div>
            <code>filename:test.exe</code>
          </div>
        </div>

        <el-divider />

        <h4>Hash 搜索</h4>
        <p>支持多种哈希值的搜索：</p>
        <div class="search-examples hash-search">
          <div class="example">
            <div class="example-title">MD5 哈希搜索：</div>
            <code>md5:d41d8cd98f00b204e9800998ecf8427e</code>
          </div>
          <div class="example">
            <div class="example-title">SHA256 哈希搜索：</div>
            <code>sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3</code>
          </div>
          <div class="example">
            <div class="example-title">SSDEEP 模糊哈希搜索：</div>
            <code>ssdeep:3:AXGBicFlgVNhEn:AXGHsN</code>
          </div>
        </div>

        <el-divider />

        <h4>PE 文件搜索</h4>
        <p>支持 PE 文件相关信息的搜索：</p>
        <div class="search-examples pe-search">
          <div class="example">
            <div class="example-title">编译时间搜索：</div>
            <code>compile_time:2024-03-20</code>
          </div>
          <div class="example">
            <div class="example-title">入口点搜索：</div>
            <code>entry_point:0x401000</code>
          </div>
          <div class="example">
            <div class="example-title">平台搜索：</div>
            <code>platform:x86</code>
          </div>
          <div class="example">
            <div class="example-title">节名称搜索：</div>
            <code>section_name:.text</code>
          </div>
          <div class="example">
            <div class="example-title">导入函数搜索：</div>
            <code>import_function:CreateFileW</code>
          </div>
          <div class="example">
            <div class="example-title">导入 DLL 搜索：</div>
            <code>import_dll:kernel32.dll</code>
          </div>
          <div class="example">
            <div class="example-title">版本信息搜索：</div>
            <code>version_info:1.0.0</code>
          </div>
          <div class="example">
            <div class="example-title">公司名称搜索：</div>
            <code>company_name:"Microsoft Corporation"</code>
          </div>
          <div class="example">
            <div class="example-title">产品名称搜索：</div>
            <code>product_name:"Windows"</code>
          </div>
          <div class="example">
            <div class="example-title">原始文件名搜索：</div>
            <code>original_filename:setup.exe</code>
          </div>
          <div class="example">
            <div class="example-title">PDB 路径搜索：</div>
            <code>pdb_path:C:\debug\app.pdb</code>
          </div>
          <div class="example">
            <div class="example-title">节熵范围搜索：</div>
            <code>section_entropy:>6.5</code>
          </div>
          <div class="example">
            <div class="example-title">签名状态搜索：</div>
            <code>is_signed:true</code>
          </div>
        </div>

        <el-divider />

        <h4>搜索语法说明</h4>
        <ul>
          <li>每次搜索最多支持10个搜索条件</li>
          <li>使用冒号分隔搜索类型和搜索值</li>
          <li>多个搜索条件会自动使用 OR 组合</li>
          <li>搜索结果按文件名排序，最多返回1000条结果</li>
          <li>对于字符串类型的搜索，支持使用双引号包含空格</li>
          <li>数值比较支持 >、<、>=、<=、= 等操作符</li>
          <li>布尔值支持 true、false、1、0</li>
        </ul>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { QuestionFilled } from '@element-plus/icons-vue'
import { searchSamples, type SearchResult } from '@/api/search'
import { useRouter } from 'vue-router'

const router = useRouter()
const searchQuery = ref('')
const searchResults = ref<SearchResult[]>([])
const total = ref(0)
const loading = ref(false)
const showHelp = ref(false)

// 处理搜索
const handleSearch = async () => {
  if (!searchQuery.value.trim()) {
    ElMessage.warning('请输入搜索条件')
    return
  }

  loading.value = true
  try {
    const response = await searchSamples(searchQuery.value)
    searchResults.value = response.results
    total.value = response.total
  } catch (error: any) {
    ElMessage.error('搜索失败：' + (error.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

// 查看样本详情
const viewSample = (sample: SearchResult) => {
  router.push(`/samples/${sample.sha256_digest}`)
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

// 获取状态标签类型
const getStatusType = (status: string) => {
  const types: Record<string, string> = {
    'pending': 'info',
    'processing': 'warning',
    'completed': 'success',
    'failed': 'danger'
  }
  return types[status] || 'info'
}
</script>

<style scoped>
.search-container {
  padding: 20px;
  min-height: 100vh;
  background-color: var(--el-bg-color);
}

.search-card {
  margin-bottom: 20px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.search-form {
  margin-bottom: 20px;
}

.search-input {
  margin-bottom: 16px;
}

.search-actions {
  display: flex;
  justify-content: flex-end;
}

.search-results {
  margin-top: 20px;
}

.monospace {
  font-family: monospace;
}

.search-help {
  h4 {
    margin: 16px 0 8px;
    color: var(--el-text-color-primary);
    font-size: 16px;
  }

  p {
    margin: 8px 0;
    color: var(--el-text-color-regular);
  }

  ul {
    margin: 8px 0;
    padding-left: 20px;
    color: var(--el-text-color-secondary);
  }
}

.search-examples {
  background-color: var(--el-fill-color-light);
  padding: 16px;
  border-radius: 4px;
  margin: 12px 0;

  &.basic-search {
    background-color: var(--el-color-success-light-9);
  }

  &.hash-search {
    background-color: var(--el-color-primary-light-9);
  }

  &.pe-search {
    background-color: var(--el-color-warning-light-9);
  }

  .example {
    margin-bottom: 12px;

    &:last-child {
      margin-bottom: 0;
    }
  }

  .example-title {
    color: var(--el-text-color-secondary);
    margin-bottom: 4px;
    font-weight: 500;
  }

  code {
    display: block;
    font-family: monospace;
    background-color: var(--el-bg-color);
    padding: 8px;
    border-radius: 4px;
    color: var(--el-text-color-primary);
    font-size: 14px;
  }
}

:deep(.el-collapse) {
  border: none;
  
  .el-collapse-item__header {
    font-size: 15px;
    color: var(--el-text-color-primary);
    font-weight: 500;
  }

  .el-collapse-item__content {
    padding-bottom: 16px;
  }
}

.help-button {
  padding: 8px;
  height: auto;
}

.help-icon {
  font-size: 20px;
  width: 20px;
  height: 20px;
}

.ml-2 {
  margin-left: 8px;
}
</style> 