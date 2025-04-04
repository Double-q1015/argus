<template>
  <el-container class="layout-container">
    <el-header height="60px">
      <nav-bar />
    </el-header>
    <el-container>
      <el-aside width="200px">
        <side-bar />
      </el-aside>
      <el-main>
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import NavBar from './NavBar.vue'
import SideBar from './SideBar.vue'
</script>

<style scoped>
.layout-container {
  height: 100vh;
}

.el-header {
  background-color: #fff;
  border-bottom: 1px solid #dcdfe6;
  padding: 0;
}

.el-aside {
  background-color: #f5f7fa;
  border-right: 1px solid #dcdfe6;
}

.el-main {
  background-color: #fff;
  padding: 20px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style> 