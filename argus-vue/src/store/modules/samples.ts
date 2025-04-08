import { defineStore } from 'pinia'
import { getSamples, deleteSample, getSample, uploadSample } from '@/api/samples'
import type { Sample } from '@/types/sample'

export const useSamplesStore = defineStore('samples', {
  state: () => ({
    samples: [] as Sample[],
    currentSample: null as Sample | null,
    loading: false,
    error: null as string | null
  }),
  
  getters: {
    getSampleById: (state) => (id: string) => {
      return state.samples.find(sample => sample.sha256_digest === id)
    }
  },
  
  actions: {
    async fetchSamples(params = { limit: 10, order: -1, sort: 'timestamp' }) {
      this.loading = true
      this.error = null
      try {
        const response = await getSamples(params)
        this.samples = response.data.data || []
      } catch (error) {
        this.error = error instanceof Error ? error.message : '获取样本列表失败'
      } finally {
        this.loading = false
      }
    },

    async fetchSampleById(id: string) {
      this.loading = true
      this.error = null
      try {
        const response = await getSample(id)
        this.currentSample = response.data
      } catch (error) {
        this.error = error instanceof Error ? error.message : '获取样本详情失败'
      } finally {
        this.loading = false
      }
    },

    async createSample(file: File, tags?: string[], description?: string) {
      this.loading = true
      this.error = null
      try {
        const response = await uploadSample({ file, tags, description })
        this.samples.unshift(response.data)
        return response.data
      } catch (error) {
        this.error = error instanceof Error ? error.message : '创建样本失败'
        throw error
      } finally {
        this.loading = false
      }
    },

    async deleteSample(id: string) {
      this.loading = true
      this.error = null
      try {
        await deleteSample(id)
        this.samples = this.samples.filter(s => s.sha256_digest !== id)
        if (this.currentSample?.sha256_digest === id) {
          this.currentSample = null
        }
      } catch (error) {
        this.error = error instanceof Error ? error.message : '删除样本失败'
        throw error
      } finally {
        this.loading = false
      }
    }
  }
}) 