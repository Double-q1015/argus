export interface StrelkaResponse {
  id: string
  index?: string
  enrichment?: {
    virustotal?: number
  }
  scan?: {
    qr?: {
      data?: string
    }
    pe?: {
      header?: {
        machine?: {
          type?: string
        }
      }
      compile_time?: string
      address_of_entry_point?: string
      sections?: any[]
      security?: boolean
      file_info?: {
        legal_copyright?: string
        product_name?: string
        file_description?: string
        original_filename?: string
        file_version?: string
      }
      symbols?: {
        imported?: string[]
        exported?: string[]
      }
    }
    tlsh?: {
      match?: string
    }
    yara?: {
      matches?: string[]
    }
    encrypted_zip?: {
      total?: {
        extracted?: number
      }
      flags?: string[]
    }
    seven_zip?: {
      total?: {
        extracted?: number
      }
      flags?: string[]
    }
    rar?: {
      total?: {
        extracted?: number
      }
      flags?: string[]
    }
    zip?: {
      total?: {
        extracted?: number
      }
      flags?: string[]
    }
    [key: string]: {
      base64_thumbnail?: string
      total?: {
        extracted?: number
      }
      flags?: string[]
      data?: string
      match?: string
      matches?: string[]
      elapsed?: number
      valid?: boolean
      size?: number
      entropy?: number
      information?: string[]
      meta?: {
        identifier: string
        rule: string
        value: string
      }
      rules_loaded?: number
      tags?: string[]
    } | {
      header?: {
        machine?: {
          type?: string
        }
      }
      compile_time?: string
      address_of_entry_point?: string
      sections?: any[]
      security?: boolean
      file_info?: {
        legal_copyright?: string
        product_name?: string
        file_description?: string
        original_filename?: string
        file_version?: string
      }
      symbols?: {
        imported?: string[]
        exported?: string[]
      }
    } | undefined
  }
  file?: {
    tree?: {
      node?: string
      parent?: string
    }
    source?: string
    name?: string
    size?: number
    depth?: number
    flavors?: {
      mime?: string[]
      yara?: string[]
    }
  }
  insights?: any[]
  iocs?: Array<{ ioc: string }>
}

export interface StrelkaNodeData {
  id: string
  nodeMain: string
  nodeLabel: string
  yaraList?: string[]
  iocList?: string[]
  type: string
}

export interface StrelkaEdge {
  id: string
  source: string
  target: string
  type?: string
  label?: string
}

export interface FlowData {
  nodes: StrelkaNodeData[]
  edges: StrelkaEdge[]
}

export interface FlowElement {
  id: string
  type: string
  data: {
    color?: string
    [key: string]: any
  }
  style?: Record<string, any>
  hidden?: boolean
}

export interface FlowNode extends FlowElement {
  type: 'event' | 'index'
  data: StrelkaNodeData
  position: { x: number; y: number }
}

export interface FlowEdge extends FlowElement {
  type: 'edge' | 'indexedge'
  source: string
  target: string
}