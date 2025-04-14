<template>
  <el-container class="layout-container">
    <el-header>
      <NavBar />
    </el-header>
    
    <el-main>
      <router-view></router-view>
    </el-main>
    
    <el-footer>
      <p>© 2025 Argus. All rights reserved.</p>
    </el-footer>
  </el-container>
</template>

<script setup lang="ts">
import NavBar from '@/components/layout/NavBar.vue'
</script>

<style scoped>
.layout-container {
  min-height: 100vh;
}

.el-main {
  padding: 2rem;
  background-color: #f5f7fa;
}

.el-footer {
  text-align: center;
  color: #909399;
  padding: 1rem;
  background-color: #fff;
}
</style> 