<template>
  <div class="settings-container">
    <h2>系统设置</h2>

    <el-card class="settings-card mt-4">
      <template #header>
        <div class="card-header">
          <span>个人信息</span>
        </div>
      </template>
      
      <el-form
        ref="formRef"
        :model="userForm"
        :rules="userRules"
        label-width="100px"
      >
        <el-form-item label="用户名" prop="username">
          <el-input v-model="userForm.username" disabled />
        </el-form-item>
        
        <el-form-item label="邮箱" prop="email">
          <el-input v-model="userForm.email" />
        </el-form-item>

        <el-form-item label="创建时间">
          <el-input v-model="userForm.created_at" disabled />
        </el-form-item>

        <el-form-item label="最后登录">
          <el-input v-model="userForm.last_login" disabled />
        </el-form-item>
        
        <el-form-item label="新密码" prop="newPassword">
          <el-input
            v-model="userForm.newPassword"
            type="password"
            show-password
            placeholder="不修改请留空"
          />
        </el-form-item>
        
        <el-form-item label="确认密码" prop="confirmPassword">
          <el-input
            v-model="userForm.confirmPassword"
            type="password"
            show-password
            placeholder="不修改请留空"
          />
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="handleSubmit">
            保存修改
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- API密钥管理 -->
    <el-card class="settings-card mt-4">
      <template #header>
        <div class="card-header">
          <span>API密钥管理</span>
          <el-button type="primary" @click="showCreateKeyDialog">
            创建新密钥
          </el-button>
        </div>
      </template>
      
      <el-table :data="apiKeys" style="width: 100%">
        <el-table-column prop="name" label="名称" />
        <el-table-column prop="description" label="描述" />
        <el-table-column label="API密钥">
          <template #default="{ row }">
            <el-input
              v-if="row.showKey"
              v-model="row.key"
              readonly
              class="api-key-input"
            >
              <template #append>
                <el-button @click="toggleKeyVisibility(row)">
                  <el-icon><Hide /></el-icon>
                </el-button>
              </template>
            </el-input>
            <el-button
              v-else
              type="primary"
              link
              @click="toggleKeyVisibility(row)"
            >
              <el-icon><View /></el-icon>
              显示密钥
            </el-button>
          </template>
        </el-table-column>
        <el-table-column label="权限">
          <template #default="{ row }">
            <el-tag
              v-for="permission in row.permissions"
              :key="permission"
              size="small"
              class="mr-2"
            >
              {{ permission }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间">
          <template #default="{ row }">
            {{ formatDate(row.created_at) }}
          </template>
        </el-table-column>
        <el-table-column prop="last_used_at" label="最后使用">
          <template #default="{ row }">
            {{ row.last_used_at ? formatDate(row.last_used_at) : '从未使用' }}
          </template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间">
          <template #default="{ row }">
            {{ row.expires_at ? formatDate(row.expires_at) : '永不过期' }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button
              v-if="row.is_active"
              type="warning"
              size="small"
              @click="handleRevokeKey(row)"
            >
              撤销
            </el-button>
            <el-button
              v-else
              type="danger"
              size="small"
              @click="handleDeleteKey(row)"
            >
              删除
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 创建API密钥对话框 -->
    <el-dialog
      v-model="createKeyDialogVisible"
      title="创建新API密钥"
      width="500px"
    >
      <el-form
        ref="createKeyFormRef"
        :model="newKeyForm"
        :rules="createKeyRules"
        label-width="100px"
      >
        <el-form-item label="名称" prop="name">
          <el-input v-model="newKeyForm.name" />
        </el-form-item>
        <el-form-item label="描述" prop="description">
          <el-input
            v-model="newKeyForm.description"
            type="textarea"
            :rows="2"
          />
        </el-form-item>
        <el-form-item label="权限" prop="permissions">
          <el-checkbox-group v-model="newKeyForm.permissions">
            <el-checkbox label="read">读取</el-checkbox>
            <el-checkbox label="write">写入</el-checkbox>
            <el-checkbox label="analysis">分析</el-checkbox>
            <el-checkbox label="download">下载</el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="过期时间" prop="expires_at">
          <el-date-picker
            v-model="newKeyForm.expires_at"
            type="datetime"
            placeholder="选择过期时间"
            :disabled-date="disabledDate"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="createKeyDialogVisible = false">取消</el-button>
          <el-button type="primary" @click="handleCreateKey">
            创建
          </el-button>
        </span>
      </template>
    </el-dialog>

    <!-- 显示新密钥对话框 -->
    <el-dialog
      v-model="showNewKeyDialog"
      title="新API密钥"
      width="500px"
    >
      <el-alert
        title="请立即保存此API密钥，它只会显示一次！"
        type="warning"
        :closable="false"
        show-icon
      />
      <el-input
        v-model="newKey"
        readonly
        class="mt-4"
      />
      <template #footer>
        <span class="dialog-footer">
          <el-button @click="showNewKeyDialog = false">关闭</el-button>
        </span>
      </template>
    </el-dialog>

    <el-card class="settings-card mt-4">
      <template #header>
        <div class="card-header">
          <span>系统设置</span>
        </div>
      </template>
      
      <el-form label-width="100px">
        <el-form-item label="主题">
          <el-radio-group v-model="systemSettings.theme">
            <el-radio :value="'light'">浅色</el-radio>
            <el-radio :value="'dark'">深色</el-radio>
            <el-radio :value="'auto'">跟随系统</el-radio>
          </el-radio-group>
        </el-form-item>
        
        <el-form-item label="语言">
          <el-select v-model="systemSettings.language">
            <el-option label="简体中文" value="zh-CN" />
            <el-option label="English" value="en-US" />
          </el-select>
        </el-form-item>
        
        <el-form-item label="通知">
          <el-switch v-model="systemSettings.notifications" />
        </el-form-item>
        
        <el-form-item>
          <el-button type="primary" @click="saveSystemSettings">
            保存设置
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import type { FormInstance, FormRules } from 'element-plus'
import { useSettingsStore } from '../stores/settings'
import { useUserStore } from '@/stores/user'
import api from '@/utils/api'  // 使用配置好的axios实例
import dayjs from 'dayjs'
import { View, Hide } from '@element-plus/icons-vue'

const formRef = ref<FormInstance>()

const userStore = useUserStore()

// 定义接口
interface ApiKey {
  id: string
  name: string
  description: string
  permissions: string[]
  expires_at: string | null
  key: string
  is_active: boolean
  created_at: string
  last_used_at: string | null
  showKey: boolean
}

interface UserForm {
  username: string
  email: string
  newPassword: string
  confirmPassword: string
  oldPassword: string
  created_at: string
  last_login: string
}

interface UpdateData {
  email?: string
  password?: string
  old_password?: string
}

interface UserResponse {
  username: string
  email: string
  is_active: boolean
  created_at: string
  last_login: string
}

// 用户表单数据
const userForm = reactive<UserForm>({
  username: userStore.username,
  email: userStore.email,
  newPassword: '',
  confirmPassword: '',
  oldPassword: '',
  created_at: '',
  last_login: ''
})

// 表单验证规则
const userRules = {
  email: [
    { required: true, message: '请输入邮箱地址', trigger: 'blur' },
    { type: 'email', message: '请输入正确的邮箱地址', trigger: 'blur' }
  ],
  newPassword: [
    { 
      validator: (_rule: any, value: string, callback: (error?: Error) => void) => {
        if (value && value.length > 0) {
          if (value.length < 8) {
            callback(new Error('密码长度至少为8个字符'))
          } else if (!/[A-Z]/.test(value)) {
            callback(new Error('密码必须包含大写字母'))
          } else if (!/[a-z]/.test(value)) {
            callback(new Error('密码必须包含小写字母'))
          } else if (!/[0-9]/.test(value)) {
            callback(new Error('密码必须包含数字'))
          } else if (!/[!@#$%^&*(),.?":{}|<>]/.test(value)) {
            callback(new Error('密码必须包含特殊字符'))
          } else {
            callback()
          }
        } else {
          callback()
        }
      },
      trigger: 'blur'
    }
  ],
  confirmPassword: [
    {
      validator: (_rule: any, value: string, callback: (error?: Error) => void) => {
        if (userForm.newPassword && value !== userForm.newPassword) {
          callback(new Error('两次输入的密码不一致'))
        } else {
          callback()
        }
      },
      trigger: 'blur'
    }
  ]
}

const settingsStore = useSettingsStore()

const systemSettings = reactive({
  theme: settingsStore.theme,
  language: settingsStore.language,
  notifications: settingsStore.notifications
})

// 处理表单提交
const handleSubmit = async () => {
  if (!formRef.value) return
  
  try {
    await formRef.value.validate()
    
    // 如果要修改密码，需要先询问旧密码
    if (userForm.newPassword) {
      try {
        await ElMessageBox.prompt('请输入当前密码', '验证身份', {
          confirmButtonText: '确认',
          cancelButtonText: '取消',
          inputType: 'password',
          inputValidator: (value) => {
            if (!value) {
              return '请输入当前密码'
            }
            return true
          }
        }).then(({ value: oldPassword }) => {
          userForm.oldPassword = oldPassword
        })
      } catch (e) {
        return // 用户取消了操作
      }
    }
    
    // 准备更新数据
    const updateData: UpdateData = {}
    if (userForm.email !== userStore.email) {
      updateData.email = userForm.email
    }
    if (userForm.newPassword) {
      updateData.password = userForm.newPassword
      updateData.old_password = userForm.oldPassword
    }
    
    // 如果没有要更新的数据，直接返回
    if (Object.keys(updateData).length === 0) {
      ElMessage.info('没有需要更新的信息')
      return
    }
    
    // 调用API更新用户信息
    const response = await api.put('/api/v1/users/me', updateData)
    
    // 更新成功
    ElMessage.success('个人信息更新成功')
    
    // 更新store中的用户信息
    userStore.email = response.data.email
    
    // 清空密码字段
    userForm.newPassword = ''
    userForm.confirmPassword = ''
    userForm.oldPassword = ''
    
  } catch (error: any) {
    if (error.response?.data?.detail) {
      ElMessage.error(error.response.data.detail)
    } else {
      ElMessage.error('更新失败，请重试')
    }
    console.error('更新用户信息失败:', error)
  }
}

// 获取最新的用户信息
const fetchUserInfo = async () => {
  try {
    const response = await api.get('/api/v1/users/me')
    console.log('用户信息响应:', response)
    
    if (response) {
      const userData = response as unknown as UserResponse
      // 更新表单数据
      userForm.username = userData.username || ''
      userForm.email = userData.email || ''
      userForm.created_at = formatDate(userData.created_at)
      userForm.last_login = formatDate(userData.last_login)
      
      // 更新store
      userStore.username = userData.username || ''
      userStore.email = userData.email || ''
    } else {
      console.error('用户信息响应数据为空')
      ElMessage.warning('获取用户信息为空')
    }
  } catch (error: any) {
    console.error('获取用户信息失败:', error)
    ElMessage.error(error.response?.data?.detail || '获取用户信息失败')
  }
}

// API密钥相关
const apiKeys = ref<ApiKey[]>([])
const createKeyDialogVisible = ref(false)
const showNewKeyDialog = ref(false)
const newKey = ref('')
const createKeyFormRef = ref<FormInstance>()

const newKeyForm = reactive({
  name: '',
  description: '',
  permissions: ['read'],
  expires_at: null
})

const createKeyRules: FormRules = {
  name: [
    { required: true, message: '请输入密钥名称', trigger: 'blur' }
  ],
  permissions: [
    { required: true, message: '请至少选择一个权限', trigger: 'change' }
  ]
}

// 获取API密钥列表
const fetchApiKeys = async () => {
  try {
    console.log('开始获取API密钥列表')
    const response = await api.get('/api/v1/keys/')
    console.log('API密钥列表响应:', response)
    
    if (response && Array.isArray(response)) {
      // 为每个密钥添加showKey属性
      apiKeys.value = response.map(key => ({
        ...key,
        showKey: false
      }))
      console.log('API密钥列表更新成功:', apiKeys.value)
    } else {
      console.error('API响应数据格式不正确:', response)
      apiKeys.value = []
      ElMessage.warning('获取API密钥列表为空')
    }
  } catch (error: any) {
    console.error('获取API密钥列表失败:', error)
    apiKeys.value = []
    ElMessage.error(error.response?.data?.detail || '获取API密钥列表失败')
  }
}

// 切换密钥显示状态
const toggleKeyVisibility = (key: ApiKey) => {
  key.showKey = !key.showKey
}

// 创建新API密钥
const handleCreateKey = async () => {
  if (!createKeyFormRef.value) return
  
  try {
    await createKeyFormRef.value.validate()
    const response = await api.post('/api/v1/keys/', newKeyForm)
    console.log('API响应:', response)
    
    // 检查响应数据
    if (response && typeof response === 'object' && 'key' in response && 'id' in response) {
      const responseData = response as unknown as ApiKey
      // 刷新API密钥列表
      await fetchApiKeys()
      
      // 找到新创建的密钥并显示
      const newKeyItem = apiKeys.value.find(k => k.id === responseData.id)
      if (newKeyItem) {
        newKeyItem.showKey = true
      }
      
      createKeyDialogVisible.value = false
      newKeyForm.name = ''
      newKeyForm.description = ''
      newKeyForm.permissions = ['read']
      newKeyForm.expires_at = null
      ElMessage.success('API密钥创建成功')
    } else {
      console.error('API响应数据格式不正确:', response)
      ElMessage.error('创建API密钥失败：响应数据格式不正确')
    }
  } catch (error: any) {
    console.error('创建API密钥失败:', error)
    ElMessage.error(error.response?.data?.detail || '创建API密钥失败')
  }
}

// 撤销API密钥
const handleRevokeKey = async (key: ApiKey) => {
  try {
    await ElMessageBox.confirm('确定要撤销此API密钥吗？', '警告', {
      type: 'warning'
    })
    await api.post(`/api/v1/keys/${key.id}/revoke`)
    key.is_active = false
    ElMessage.success('API密钥已撤销')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('撤销API密钥失败')
    }
  }
}

// 删除API密钥
const handleDeleteKey = async (key: ApiKey) => {
  try {
    await ElMessageBox.confirm('确定要删除此API密钥吗？此操作不可恢复！', '警告', {
      type: 'warning'
    })
    await api.delete(`/api/v1/keys/${key.id}`)
    apiKeys.value = apiKeys.value.filter(k => k.id !== key.id)
    ElMessage.success('API密钥已删除')
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('删除API密钥失败')
    }
  }
}

// 显示创建密钥对话框
const showCreateKeyDialog = () => {
  createKeyDialogVisible.value = true
}

// 格式化日期
const formatDate = (date: string) => {
  return dayjs(date).format('YYYY-MM-DD HH:mm:ss')
}

// 禁用过去的日期
const disabledDate = (time: Date) => {
  return time.getTime() < Date.now()
}

const saveSystemSettings = () => {
  settingsStore.theme = systemSettings.theme
  settingsStore.language = systemSettings.language
  settingsStore.notifications = systemSettings.notifications
  ElMessage.success('设置已保存')
}

onMounted(() => {
  fetchApiKeys()
  fetchUserInfo()
})
</script>

<style scoped>
.settings-container {
  padding: 20px;
  background-color: var(--el-bg-color);
  min-height: 100vh;
}

.settings-card {
  max-width: 800px;
  margin: 0 auto;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.mt-4 {
  margin-top: 20px;
}

:root.dark h2 {
  color: var(--el-text-color-primary);
}

.mr-2 {
  margin-right: 8px;
}

.api-key-input {
  width: 300px;
}
</style> 