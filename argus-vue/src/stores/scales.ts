import { defineStore } from 'pinia'
import {
  getScales,
  getScaleDetail,
  createScale,
  updateScale,
  deleteScale,
  startScale,
  stopScale,
  getScaleResults,
  type Scale,
  type CreateScaleParams,
  type UpdateScaleParams
} from '@/api/scales'
import { ElMessage } from 'element-plus'

export const useScalesStore = defineStore('scales', {
  state: () => ({
    scales: [] as Scale[],
    currentScale: null as Scale | null,
    loading: false,
    detailLoading: false
  }),

  actions: {
    // 获取规模分析列表
    async fetchScales() {
      this.loading = true
      try {
        const response = await getScales()
        if (response.status === 'success') {
          this.scales = response.data.scales
        }
      } catch (error) {
        console.error('获取规模分析列表失败:', error)
        ElMessage.error('获取规模分析列表失败')
      } finally {
        this.loading = false
      }
    },

    // 获取规模分析详情
    async fetchScaleDetail(id: string) {
      this.detailLoading = true
      try {
        const response = await getScaleDetail(id)
        if (response.status === 'success') {
          this.currentScale = response.data.scale
        }
      } catch (error) {
        console.error('获取规模分析详情失败:', error)
        ElMessage.error('获取规模分析详情失败')
      } finally {
        this.detailLoading = false
      }
    },

    // 创建规模分析
    async createScale(params: CreateScaleParams) {
      try {
        const response = await createScale(params)
        if (response.status === 'success') {
          ElMessage.success('创建规模分析成功')
          this.scales.push(response.data.scale)
          return response.data.scale
        }
      } catch (error) {
        console.error('创建规模分析失败:', error)
        ElMessage.error('创建规模分析失败')
        return null
      }
    },

    // 更新规模分析
    async updateScale(id: string, params: UpdateScaleParams) {
      try {
        const response = await updateScale(id, params)
        if (response.status === 'success') {
          ElMessage.success('更新规模分析成功')
          const index = this.scales.findIndex(scale => scale.id === id)
          if (index !== -1) {
            this.scales[index] = response.data.scale
          }
          if (this.currentScale?.id === id) {
            this.currentScale = response.data.scale
          }
          return response.data.scale
        }
      } catch (error) {
        console.error('更新规模分析失败:', error)
        ElMessage.error('更新规模分析失败')
        return null
      }
    },

    // 删除规模分析
    async deleteScale(id: string) {
      try {
        const response = await deleteScale(id)
        if (response.status === 'success') {
          ElMessage.success('删除规模分析成功')
          this.scales = this.scales.filter(scale => scale.id !== id)
          if (this.currentScale?.id === id) {
            this.currentScale = null
          }
          return true
        }
      } catch (error) {
        console.error('删除规模分析失败:', error)
        ElMessage.error('删除规模分析失败')
        return false
      }
    },

    // 启动规模分析
    async startScale(id: string) {
      try {
        const response = await startScale(id)
        if (response.status === 'success') {
          ElMessage.success('启动规模分析成功')
          await this.fetchScaleDetail(id)
          return true
        }
      } catch (error) {
        console.error('启动规模分析失败:', error)
        ElMessage.error('启动规模分析失败')
        return false
      }
    },

    // 停止规模分析
    async stopScale(id: string) {
      try {
        const response = await stopScale(id)
        if (response.status === 'success') {
          ElMessage.success('停止规模分析成功')
          await this.fetchScaleDetail(id)
          return true
        }
      } catch (error) {
        console.error('停止规模分析失败:', error)
        ElMessage.error('停止规模分析失败')
        return false
      }
    },

    // 获取规模分析结果
    async fetchScaleResults(id: string) {
      try {
        const response = await getScaleResults(id)
        if (response.status === 'success') {
          if (this.currentScale && this.currentScale.id === id) {
            this.currentScale.results = response.data.results
          }
          return response.data.results
        }
      } catch (error) {
        console.error('获取规模分析结果失败:', error)
        ElMessage.error('获取规模分析结果失败')
        return null
      }
    },

    // 清除当前规模分析
    clearCurrentScale() {
      this.currentScale = null
    }
  }
}) 