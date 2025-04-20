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
        {{ $t('nav.home') }}
      </el-menu-item>
      <el-menu-item index="/search">
        <el-icon><Search /></el-icon>
        {{ $t('nav.search') }}
      </el-menu-item>
      <el-menu-item index="/samples">
        <el-icon><Document /></el-icon>
        {{ $t('nav.samples') }}
      </el-menu-item>
      <el-menu-item index="/analysis">
        <el-icon><Upload /></el-icon>
        {{ $t('nav.analysis') }}
      </el-menu-item>
      <el-sub-menu index="yara">
        <template #title>
          <el-icon><Monitor /></el-icon>
          {{ $t('nav.yara') }}
        </template>
        <el-menu-item index="/yara/create">{{ $t('nav.createYara') }}</el-menu-item>
        <el-menu-item index="/yara/list">{{ $t('nav.listYara') }}</el-menu-item>
      </el-sub-menu>
      <el-menu-item index="/tasks">
        <el-icon><List /></el-icon>
        {{ $t('nav.tasks') }}
      </el-menu-item>
      <el-menu-item index="/migration">
        <el-icon><Connection /></el-icon>
        {{ $t('nav.migration') }}
      </el-menu-item>
    </el-menu>
    <div class="nav-right">
      <div class="database-status">
        <el-tooltip :content="statusTooltip" placement="bottom">
          <el-avatar
            :size="32"
            :style="{ backgroundColor: isDatabaseOnline ? '#52c41a' : '#eb2f96' }"
          >
            <el-icon><Monitor /></el-icon>
          </el-avatar>
        </el-tooltip>
      </div>
      <el-dropdown @command="handleLanguageChange">
        <span class="language-dropdown">
          {{ currentLanguage }}
          <el-icon><arrow-down /></el-icon>
        </span>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="zh-CN">中文</el-dropdown-item>
            <el-dropdown-item command="en-US">English</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </div>
    <!-- 增加间距 -->
     

    <el-dropdown @command="handleCommand">
      <span class="user-dropdown">
        {{ username }}
        <el-icon><arrow-down /></el-icon>
      </span>
      <template #dropdown>
        <el-dropdown-menu>
          <el-dropdown-item command="profile">{{ $t('common.profile') }}</el-dropdown-item>
          <el-dropdown-item command="logout">{{ $t('common.logout') }}</el-dropdown-item>
        </el-dropdown-menu>
      </template>
    </el-dropdown>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { ArrowDown, House, Document, Monitor, Upload, Search, List, Connection } from '@element-plus/icons-vue'
import { useDatabaseStatus } from '@/hooks/useDatabaseStatus'

const router = useRouter()
const route = useRoute()
const { locale, t } = useI18n()
const username = ref(localStorage.getItem('username') || 'Admin')

const { data } = useDatabaseStatus()
const isDatabaseOnline = computed(() => {
  return data.value?.data?.message === 'Database is reachable'
})

const statusTooltip = computed(() => {
  return isDatabaseOnline.value
    ? t('database.online')
    : t('database.offline')
})

const currentLanguage = computed(() => {
  return locale.value === 'zh-CN' ? '中文' : 'English'
})

const handleLanguageChange = (lang: string) => {
  locale.value = lang
  localStorage.setItem('language', lang)
}

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

.nav-right {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-right: 20px;
}

.database-status {
  display: flex;
  align-items: center;
}

.database-status .el-avatar {
  cursor: pointer;
}

.language-dropdown {
  display: flex;
  align-items: center;
  cursor: pointer;
  color: #606266;
  margin-right: 20px;
}

.language-dropdown .el-icon {
  margin-left: 4px;
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