<template>
  <el-menu
    class="side-menu"
    :default-active="activeMenu"
    :router="true"
  >
    <el-menu-item index="/">
      <el-icon><home-filled /></el-icon>
      <span>首页</span>
    </el-menu-item>
    
    <el-sub-menu index="/samples">
      <template #title>
        <el-icon><document /></el-icon>
        <span>样本管理</span>
      </template>
      <el-menu-item index="/samples">样本列表</el-menu-item>
      <el-menu-item index="/samples/create">新建样本</el-menu-item>
    </el-sub-menu>

    <el-sub-menu index="/scales">
      <template #title>
        <el-icon><data-line /></el-icon>
        <span>规模管理</span>
      </template>
      <el-menu-item index="/scales">规模列表</el-menu-item>
      <el-menu-item index="/scales/create">新建规模</el-menu-item>
    </el-sub-menu>

    <el-menu-item index="/settings">
      <el-icon><setting /></el-icon>
      <span>系统设置</span>
    </el-menu-item>
  </el-menu>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import {
  HomeFilled,
  Document,
  DataLine,
  Setting
} from '@element-plus/icons-vue'

const route = useRoute()
const activeMenu = computed(() => route.path)
</script>

<style scoped>
.side-menu {
  height: 100%;
  border-right: none;
}

.side-menu :deep(.el-menu-item),
.side-menu :deep(.el-sub-menu__title) {
  height: 50px;
  line-height: 50px;
}

.side-menu :deep(.el-menu-item .el-icon),
.side-menu :deep(.el-sub-menu__title .el-icon) {
  margin-right: 8px;
  font-size: 18px;
}

.side-menu :deep(.el-menu-item.is-active) {
  background-color: #ecf5ff;
  color: #409eff;
}
</style> 