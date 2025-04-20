<template>
  <el-menu
    :default-active="route.path"
    class="sidebar-menu"
    :collapse="isCollapse"
    :router="true"
  >
    <el-menu-item index="/">
      <el-icon><House /></el-icon>
      <template #title>{{ $t('nav.home') }}</template>
    </el-menu-item>
    <el-menu-item index="/search">
      <el-icon><Search /></el-icon>
      <template #title>{{ $t('nav.search') }}</template>
    </el-menu-item>
    <el-menu-item index="/samples">
      <el-icon><Document /></el-icon>
      <template #title>{{ $t('nav.samples') }}</template>
    </el-menu-item>
    <el-menu-item index="/analysis">
      <el-icon><Upload /></el-icon>
      <template #title>{{ $t('nav.analysis') }}</template>
    </el-menu-item>
    <el-sub-menu index="yara">
      <template #title>
        <el-icon><Monitor /></el-icon>
        <span>{{ $t('nav.yara') }}</span>
      </template>
      <el-menu-item index="/yara/create">{{ $t('nav.createYara') }}</el-menu-item>
      <el-menu-item index="/yara/list">{{ $t('nav.listYara') }}</el-menu-item>
    </el-sub-menu>
    <el-menu-item index="/tasks">
      <el-icon><List /></el-icon>
      <template #title>{{ $t('nav.tasks') }}</template>
    </el-menu-item>
    <el-menu-item index="/migration">
      <el-icon><Connection /></el-icon>
      <template #title>{{ $t('nav.migration') }}</template>
    </el-menu-item>
  </el-menu>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRoute } from 'vue-router'
import { House, Document, Monitor, Upload, Search, List, Connection } from '@element-plus/icons-vue'

const route = useRoute()
const isCollapse = ref(false)
</script>

<style scoped>
.sidebar-menu {
  height: 100%;
  border-right: none;
}

.sidebar-menu:not(.el-menu--collapse) {
  width: 200px;
}
</style> 