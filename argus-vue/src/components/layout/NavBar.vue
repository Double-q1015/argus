<template>
  <div class="nav-container">
    <div class="logo">
      <router-link to="/">
        <h1>Argus</h1>
      </router-link>
    </div>
    <el-menu
      mode="horizontal"
      :router="true"
      :default-active="route.path"
      class="nav-menu"
    >
      <el-menu-item index="/">
        <el-icon><House /></el-icon>
        首页
      </el-menu-item>
      <el-menu-item index="/search">
        <el-icon><Search /></el-icon>
        搜索
      </el-menu-item>
      <el-menu-item index="/samples">
        <el-icon><Document /></el-icon>
        样本管理
      </el-menu-item>
      <el-menu-item index="/analysis">
        <el-icon><Upload /></el-icon>
        分析
      </el-menu-item>
      <el-sub-menu index="yara">
        <template #title>
          <el-icon><Monitor /></el-icon>
          Yara
        </template>
        <el-menu-item index="/yara/create">创建Yara规则</el-menu-item>
        <el-menu-item index="/yara/list">查看Yara规则</el-menu-item>
      </el-sub-menu>
      <el-menu-item index="/scales">
        <el-icon><DataAnalysis /></el-icon>
        规模分析
      </el-menu-item>
    </el-menu>
    <div class="user-info">
      <el-dropdown @command="handleCommand">
        <span class="user-dropdown">
          {{ username }}
          <el-icon><arrow-down /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="profile">个人信息</el-dropdown-item>
            <el-dropdown-item command="logout">退出登录</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { ArrowDown, House, Document, DataAnalysis, Monitor, Upload, Search } from '@element-plus/icons-vue'

const router = useRouter()
const route = useRoute()
const username = ref(localStorage.getItem('username') || 'Admin')

const handleCommand = (command: string) => {
  switch (command) {
    case 'profile':
      router.push('/settings')
      break
    case 'logout':
      localStorage.removeItem('access_token')
      router.push('/login')
      break
  }
}
</script>

<style scoped>
.nav-container {
  display: flex;
  align-items: center;
  height: 100%;
  padding: 0 20px;
}

.logo {
  margin-right: 40px;
}

.logo a {
  text-decoration: none;
  color: #409eff;
}

.logo h1 {
  margin: 0;
  font-size: 20px;
}

.nav-menu {
  flex: 1;
  border-bottom: none;
}

.user-info {
  margin-left: 20px;
}

.user-dropdown {
  display: flex;
  align-items: center;
  cursor: pointer;
  color: #606266;
}

.user-dropdown .el-icon {
  margin-left: 4px;
}
</style> 