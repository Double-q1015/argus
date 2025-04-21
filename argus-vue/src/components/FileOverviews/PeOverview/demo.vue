<template>
    <div style="padding: 24px">
      <div class="demo-nav" style="margin-bottom: 16px">
        <el-button type="primary" @click="$router.push('/')">返回首页</el-button>
      </div>
      <PeOverviewLanding
        v-model:expanded="expanded"
        :selected-node-data="mockData"
        @expand-change="handleExpandChange"
      />
    </div>
</template>
  
<script lang="ts" setup>
import { ref } from 'vue'
// import PeOverviewCard from './PeOverviewCard.vue' // 确保路径正确
import PeOverviewLanding from './PeOverviewLanding.vue'

const expanded = ref(true)
const handleExpandChange = (value: boolean) => {
  expanded.value = value
}

const mockData = {
file: {
    name: 'analyzer.exe',
    size: 12345,
    depth: 0,
    flavors: {
    mime: ['application/x-dosexec']
    },
    tree: {
    node: 'root',
    root: 'root'
    },
    scan: {
    count: 1,
    files: ['analyzer.exe'],
    hash: {
        md5: 'abcdef1234567890'
    }
    },
    scanners: ['pe', 'yara']
},
insights: [],
request: {
    attributes: {
    filename: 'analyzer.exe',
    metadata: {
        client_environment: 'test',
        client_hostname: 'test-host',
        client_name: 'test-client',
        client_user_name: 'tester',
        client_version: '1.0.0',
        user_name: 'test_user'
    }
    },
    client: 'test-client',
    id: 'test-123',
    time: 1234567890
},
scan: {
    pe: {
    header: {
        machine: {
        type: 'Intel 386 (0x14C)',
        description: 'Intel 386 or later processors and compatible processors'
        }
    },
    compile_time: '2024-03-01 12:34:56',
    address_of_entry_point: 0x0001F000,
    sections: [
        {
        name: '.text',
        address: {
            virtual: 0x00001000,
            physical: 0x00000200
        },
        size: 4096,
        entropy: 6.123,
        md5: 'a1b2c3d4e5f60718293a1b2c3d4e5f60'
        },
        {
        name: '.rdata',
        address: {
            virtual: 0x00002000,
            physical: 0x00001000
        },
        size: 2048,
        entropy: 7.567,
        md5: '9c8a7b6e5d4c3b2a19081716a5b4c3d2'
        },
        {
        name: '.data',
        address: {
            virtual: 0x00003000,
            physical: 0x00002000
        },
        size: 1024,
        entropy: 3.789,
        md5: 'f1e2d3c4b5a697887766554433221100'
        }
    ],
    security: true,
    file_info: {
        legal_copyright: '© 2024 CyberSecurity Inc.',
        product_name: 'SecureAnalyzer',
        file_description: 'Static PE file analyzer',
        original_filename: 'analyzer.exe',
        file_version: '1.4.0.0',
        file_type: 'application/x-dosexec'
    },
    symbols: {
        imported: [
        'KERNEL32.dll!CreateFileW',
        'KERNEL32.dll!ReadFile',
        'USER32.dll!MessageBoxW'
        ],
        exported: [
        'ExportedFunction1',
        'ExportedFunction2'
        ]
    }
    },
    vb: {}
}
}
</script>
  