import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  base: '/',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  },
  optimizeDeps: {
    include: ['@tanstack/vue-query']
  },
  server: {
    host: '0.0.0.0',
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true
      }
    }
  },
  preview: {
    host: '0.0.0.0',
    port: 4173,
    strictPort: true,
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: true,
    chunkSizeWarningLimit: 1000,
    // rollupOptions: {
    //   output: {
    //     manualChunks: {
    //       'element-plus': ['element-plus'],
    //       'vue-vendor': ['vue', 'vue-router', 'pinia'],
    //       'axios': ['axios']
    //     }
    //   }
    // },
    commonjsOptions: {
      include: [/node_modules/]
    }
  }
})
