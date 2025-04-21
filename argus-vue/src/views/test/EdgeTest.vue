<template>
  <div class="edge-test-page">
    <el-card class="test-card">
      <template #header>
        <div class="card-header">
          <span>边连接组件测试</span>
          <el-button-group>
            <el-button @click="addNode">添加节点</el-button>
            <el-button @click="toggleHighlight">切换高亮</el-button>
            <el-button @click="resetView">重置视图</el-button>
          </el-button-group>
        </div>
      </template>
      <index-connect-edge-test />
    </el-card>
  </div>
</template>

<script setup lang="ts">
import IndexConnectEdgeTest from '@/components/FileFlow/EdgeTypes/__tests__/IndexConnectEdge.test.vue'

const addNode = () => {
  // 可以通过 ref 来调用测试组件的方法
  console.log('添加节点')
}

const toggleHighlight = () => {
  console.log('切换高亮')
}

const resetView = () => {
  console.log('重置视图')
}
</script>

<style scoped>
.edge-test-page {
  padding: 20px;
  min-height: 100vh;
  background-color: var(--el-bg-color-page);
}

.test-card {
  margin: 0 auto;
  max-width: 1200px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

:deep(.el-card__body) {
  padding: 0;
}
</style> 