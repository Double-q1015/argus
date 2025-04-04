<template>
  <div class="list-yara-container">
    <el-card class="yara-card">
      <template #header>
        <div class="card-header">
          <h2>Yara规则列表</h2>
          <el-button type="primary" @click="createRule">创建规则</el-button>
        </div>
      </template>
      
      <el-table :data="rules" style="width: 100%" v-loading="loading">
        <el-table-column prop="name" label="规则名称" width="180" />
        <el-table-column prop="description" label="描述" />
        <el-table-column prop="createTime" label="创建时间" width="180" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="scope">
            <el-tag :type="scope.row.status === 'active' ? 'success' : 'info'">
              {{ scope.row.status === 'active' ? '启用' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="scope">
            <el-button-group>
              <el-button size="small" @click="viewRule(scope.row)">查看</el-button>
              <el-button size="small" type="primary" @click="editRule(scope.row)">编辑</el-button>
              <el-button size="small" type="danger" @click="deleteRule(scope.row)">删除</el-button>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>
      
      <div class="pagination-container">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[10, 20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          :total="total"
          @size-change="handleSizeChange"
          @current-change="handleCurrentChange"
        />
      </div>
    </el-card>
    
    <!-- 查看规则对话框 -->
    <el-dialog
      v-model="viewDialogVisible"
      title="查看规则"
      width="60%"
    >
      <pre class="rule-content">{{ selectedRule?.content }}</pre>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { yaraApi } from '@/api/yara'
import type { YaraRule } from '@/api/yara'

const router = useRouter()
const loading = ref(false)
const currentPage = ref(1)
const pageSize = ref(10)
const total = ref(0)
const viewDialogVisible = ref(false)
const selectedRule = ref<YaraRule | null>(null)
const rules = ref<YaraRule[]>([])

const loadRules = async () => {
  loading.value = true
  try {
    const skip = (currentPage.value - 1) * pageSize.value
    const response = await yaraApi.getRules({ skip, limit: pageSize.value })
    console.log(response)
    rules.value = response.data
  } catch (error: any) {
    ElMessage.error('加载规则列表失败')
  } finally {
    loading.value = false
  }
}

const createRule = () => {
  router.push('/yara/create')
}

const viewRule = (rule: YaraRule) => {
  selectedRule.value = rule
  viewDialogVisible.value = true
}

const editRule = async (rule: YaraRule) => {
  // TODO: 实现编辑功能
  router.push(`/yara/edit/${rule.id}`)
}

const deleteRule = async (rule: YaraRule) => {
  try {
    await ElMessageBox.confirm(
      '确定要删除该规则吗？',
      '警告',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning',
      }
    )
    
    await yaraApi.deleteRule(rule.id)
    ElMessage.success('删除成功')
    await loadRules()
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('删除规则失败')
    }
  }
}

const handleSizeChange = (val: number) => {
  pageSize.value = val
  loadRules()
}

const handleCurrentChange = (val: number) => {
  currentPage.value = val
  loadRules()
}

onMounted(() => {
  loadRules()
})
</script>

<style scoped>
.list-yara-container {
  padding: 20px;
  height: 100%;
  background-color: var(--el-bg-color);
}

.yara-card {
  height: calc(100% - 40px);
  display: flex;
  flex-direction: column;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.card-header h2 {
  margin: 0;
  color: var(--el-text-color-primary);
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.rule-content {
  font-family: monospace;
  background-color: var(--el-bg-color-page);
  padding: 15px;
  border-radius: 4px;
  margin: 0;
  white-space: pre-wrap;
}
</style> 