<template>
    <div class="chart-container">
      <el-card>
        <template #header>
          <div class="card-header">
            <span>{{ t('home.stats.mimeTypeStats') }}</span>
          </div>
        </template>
        
        <div ref="chartRef" style="height: 400px"></div>
      </el-card>
    </div>
  </template>
  
<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch } from 'vue'
import * as echarts from 'echarts'
import { useStatsCharts } from '@/hooks/useStatsChart'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const stats = useStatsCharts().data
console.log(stats)

const initChart = () => {
  if (!chartRef.value) return
  chart = echarts.init(chartRef.value)
  updateChart()
}

const updateChart = () => {
  if (!chart || !stats.value) return

  const mimeTypeStats = Array.isArray(stats.value.data) ? stats.value.data : []
  
  const option = {
    tooltip: {
      trigger: 'axis',
      axisPointer: {
        type: 'shadow'
      }
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true
    },
    xAxis: {
      type: 'category',
      data: mimeTypeStats.map(item => item.mime_type),
      axisLabel: {
        interval: 0,
        rotate: 30
      }
    },
    yAxis: {
      type: 'value'
    },
    series: [{
      data: mimeTypeStats.map(item => item.count),
      type: 'bar',
      showBackground: true,
      backgroundStyle: {
        color: 'rgba(180, 180, 180, 0.2)'
      }
    }]
  }

  chart.setOption(option)
}

// 监听数据变化
watch(() => stats.value, () => {
  if (chart) {
    updateChart()
  }
}, { deep: true })

onMounted(() => {
  initChart()
  window.addEventListener('resize', () => chart?.resize())
})

onUnmounted(() => {
  window.removeEventListener('resize', () => chart?.resize())
  chart?.dispose()
})
</script>

<style scoped>
.chart-container {
margin-bottom: 20px;
}
</style>