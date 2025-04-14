<template>
  <div class="dashboard-container">
    <h2>仪表盘</h2>
    <el-row :gutter="20">
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>样本类型分布</span>
            </div>
          </template>
          <div class="chart-placeholder">
            样本类型统计图表
          </div>
        </el-card>
      </el-col>
      
      <el-col :span="12">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>每日样本趋势</span>
            </div>
          </template>
          <div class="chart-placeholder">
            每日样本数量趋势图
          </div>
        </el-card>
      </el-col>
    </el-row>
    
    <el-row :gutter="20" class="mt-4">
      <el-col :span="24">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>最近活动</span>
            </div>
          </template>
          <el-timeline>
            <el-timeline-item
              v-for="(activity, index) in activities"
              :key="index"
              :timestamp="activity.time"
              :type="activity.type"
            >
              {{ activity.content }}
            </el-timeline-item>
          </el-timeline>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">

const activities = [
  {
    content: '上传了新样本 "example.exe"',
    time: '2024-03-29 15:00:00',
    type: 'primary'
  },
  {
    content: '完成了样本 "test.dll" 的分析',
    time: '2024-03-29 14:30:00',
    type: 'success'
  },
  {
    content: '更新了系统设置',
    time: '2024-03-29 14:00:00',
    type: 'info'
  },
  {
    content: '删除了过期样本',
    time: '2024-03-29 13:30:00',
    type: 'warning'
  }
]
</script>

<style scoped>
.dashboard-container {
  padding: 20px;
  background-color: var(--el-bg-color);
  min-height: 100vh;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chart-placeholder {
  height: 300px;
  display: flex;
  justify-content: center;
  align-items: center;
  background-color: var(--el-fill-color);
  border-radius: 4px;
  color: var(--el-text-color-secondary);
}

.mt-4 {
  margin-top: 20px;
}

:root.dark h2 {
  color: var(--el-text-color-primary);
}
</style> 