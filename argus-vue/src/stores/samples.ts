import { defineStore } from 'pinia'
import {
  getSamples,
  getSample,
  uploadSample,
  deleteSample,
} from '@/api/samples'
import type { Sample, SampleQueryParams } from '@/types/sample'
import { ElMessage } from 'element-plus'

export const useSamplesStore = defineStore('samples', {
  state: () => ({
    samples: [] as Sample[],
    currentSample: null as Sample | null,
    loading: false,
    detailLoading: false,
    commonTags: [] as string[],
    total: 0,
    currentPage: 1,
    pageSize: 10
  }),

  actions: {
    // 获取样本列表
    async fetchSamples(params?: Partial<SampleQueryParams>) {
      this.loading = true
      try {
        const response = await getSamples({
          limit: this.pageSize,
          ...params
        })
        this.samples = response.data.data || []
        this.total = response.data.total || this.samples.length
      } catch (error) {
        console.error('获取样本列表失败:', error)
        ElMessage.error('获取样本列表失败')
      } finally {
        this.loading = false
      }
    },

    // 获取样本详情
    async fetchSampleDetail(sha256: string) {
      this.detailLoading = true
      try {
        const response = await getSample(sha256)
        this.currentSample = response.data
      } catch (error) {
        console.error('获取样本详情失败:', error)
        ElMessage.error('获取样本详情失败')
      } finally {
        this.detailLoading = false
      }
    },

    // 上传样本
    async uploadSample(file: File, tags?: string[], description?: string) {
      try {
        const response = await uploadSample({ file, tags, description })
        ElMessage.success('样本上传成功')
        return response.data
      } catch (error) {
        console.error('样本上传失败:', error)
        ElMessage.error('样本上传失败')
        return null
      }
    },

    // 删除样本
    async deleteSample(sha256: string) {
      try {
        await deleteSample(sha256)
        ElMessage.success('样本删除成功')
        this.samples = this.samples.filter(sample => sample.sha256_digest !== sha256)
        return true
      } catch (error) {
        console.error('样本删除失败:', error)
        ElMessage.error('样本删除失败')
        return false
      }
    },


    // 获取常用标签 - 由于API中没有获取常用标签的方法，这里暂时使用硬编码的标签
    async fetchCommonTags() {
      try {
        // 模拟API调用
        this.commonTags = [
          '恶意软件',
          '病毒',
          '木马',
          '勒索软件',
          '可疑文件',
          '正常文件',
          '待分析'
        ]
      } catch (error) {
        console.error('获取常用标签失败:', error)
      }
    },

    // 清除当前样本
    clearCurrentSample() {
      this.currentSample = null
    }
  }
}) 