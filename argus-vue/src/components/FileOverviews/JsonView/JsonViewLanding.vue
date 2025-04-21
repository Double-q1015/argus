<template>
  <div class="json-view-landing">
    <el-card class="overview-card" :body-style="{ padding: '0px' }">
      <div class="overview-header">
        <h3>JSON 视图</h3>
        <el-button
          :icon="expanded ? 'el-icon-arrow-up' : 'el-icon-arrow-down'"
          @click="() => onExpandChange(!expanded)"
          text
        />
      </div>
      <div v-if="expanded" class="overview-content">
        <json-view-card :data="selectedNodeData" />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { type OverviewLandingProps } from '../types'
import JsonViewCard from './JsonViewCard.vue'

defineProps<OverviewLandingProps>()
</script>

<style scoped>
.json-view-landing {
  width: 100%;
  margin-bottom: 16px;
}

.overview-card {
  border-radius: 8px;
}

.overview-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  border-bottom: 1px solid var(--el-border-color-light);
}

.overview-header h3 {
  margin: 0;
  font-size: 16px;
  color: var(--el-text-color-primary);
}

.overview-content {
  padding: 16px;
}
</style> 