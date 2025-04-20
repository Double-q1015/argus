export default {
  common: {
    welcome: 'Welcome',
    login: 'Login',
    logout: 'Logout',
    profile: 'Profile',
    settings: 'Settings'
  },
  nav: {
    home: 'Home',
    search: 'Search',
    samples: 'Samples',
    analysis: 'Analysis',
    yara: 'Yara',
    createYara: 'Create Yara Rule',
    listYara: 'View Yara Rules',
    tasks: 'Tasks',
    migration: 'Migration'
  },
  database: {
    online: 'Database is reachable',
    offline: 'Database is not reachable, please contact the administrator'
  },
  yara: {
    create: {
      title: 'Create Yara Rule',
      name: 'Rule Name',
      namePlaceholder: 'Please enter rule name',
      nameRules: {
        required: 'Please enter rule name',
        length: 'Length should be between 3 and 50 characters'
      },
      description: 'Rule Description',
      descriptionPlaceholder: 'Please enter rule description',
      descriptionRules: {
        required: 'Please enter rule description'
      },
      content: 'Rule Content',
      contentPlaceholder: 'Please enter Yara rule content',
      contentRules: {
        required: 'Please enter rule content'
      },
      submit: 'Create Rule',
      reset: 'Reset',
      success: 'Rule created successfully',
      error: 'Failed to create rule'
    },
    list: {
      title: 'Yara Rules List',
      createButton: 'Create Rule',
      table: {
        name: 'Rule Name',
        description: 'Description',
        createTime: 'Create Time',
        status: 'Status',
        actions: 'Actions',
        view: 'View',
        edit: 'Edit',
        delete: 'Delete'
      },
      status: {
        active: 'Active',
        inactive: 'Inactive'
      },
      dialog: {
        viewTitle: 'View Rule'
      },
      confirm: {
        deleteTitle: 'Warning',
        deleteMessage: 'Are you sure you want to delete this rule?',
        confirmButton: 'Confirm',
        cancelButton: 'Cancel'
      },
      message: {
        deleteSuccess: 'Delete successful',
        deleteError: 'Failed to delete rule',
        loadError: 'Failed to load rules list'
      }
    }
  },
  analysis: {
    title: 'File Analysis',
    dropZone: {
      title: 'Drag and drop files here for analysis',
      description1: 'Supports Windows PE executables and all file types',
      description2: 'Maximum 10 files, 10MB per file'
    },
    fileList: {
      startAnalysis: 'Start Analysis',
      clearList: 'Clear List'
    },
    message: {
      maxFiles: 'Maximum {count} files allowed',
      maxFileSize: 'The following files exceed size limit (10MB): {files}',
      noFiles: 'Please add files first',
      analysisSuccess: 'All files analyzed successfully',
      analysisPartial: 'Analysis complete, {success} successful, {error} failed',
      analysisError: 'Analysis failed, please try again'
    }
  },
  home: {
    stats: {
      totalSamples: 'Total Samples',
      todaySamples: 'Today\'s New',
      totalStorage: 'Total Storage',
      activeUsers: 'Active Users',
      mimeTypeStats: 'Mime Type Stats'
    },
    recentSamples: {
      title: 'Recently Added Samples',
      viewAll: 'View All',
      table: {
        sha256: 'SHA256 Digest',
        time: 'Time',
        name: 'Name',
        tags: 'Tags'
      }
    },
    message: {
      loadError: 'Failed to load data'
    }
  },
  login: {
    title: 'Welcome',
    subtitle: 'Please login to your account',
    username: 'Username',
    password: 'Password',
    captcha: 'Verification Code',
    submit: 'Login',
    register: 'Register',
    rules: {
      username: {
        required: 'Please enter username',
        length: 'Username length should be between 3-20 characters'
      },
      password: {
        required: 'Please enter password',
        min: 'Password must be at least 8 characters'
      },
      captcha: {
        required: 'Please enter verification code'
      }
    },
    error: {
      default: 'Login failed, please check username and password'
    },
    success: 'Login successful'
  },
  migration: {
    create: {
      title: 'Create Migration Task',
      back: 'Back',
      success: 'Migration task created successfully',
      error: 'Failed to create migration task'
    },
    detail: {
      title: 'Migration Task Details',
      back: 'Back',
      labels: {
        name: 'Task Name',
        status: 'Status',
        sourceStorage: 'Source Storage',
        targetStorage: 'Target Storage',
        createdAt: 'Created At',
        updatedAt: 'Updated At',
        startedAt: 'Started At',
        completedAt: 'Completed At',
        description: 'Description',
        errorMessage: 'Error Message'
      },
      progress: {
        title: 'Migration Progress',
        processedFiles: 'Processed Files',
        processedSize: 'Processed Size'
      },
      fileList: {
        title: 'File List',
        filePath: 'File Path',
        status: 'Status',
        sourceSize: 'Source File Size',
        targetSize: 'Target File Size',
        errorMessage: 'Error Message'
      },
      message: {
        loadTaskError: 'Failed to load migration task',
        loadTaskEmpty: 'Migration task data is empty or invalid',
        loadFileStatusError: 'Failed to load file statuses'
      }
    }
  }
} 