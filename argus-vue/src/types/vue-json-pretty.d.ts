declare module 'vue-json-pretty' {
  import { Component } from 'vue'
  
  interface VueJsonPrettyProps {
    data: any
    deep?: number
    showLength?: boolean
    showLine?: boolean
    theme?: string
    onClick?: (node: any) => void
  }

  const VueJsonPretty: Component
  export default VueJsonPretty
} 