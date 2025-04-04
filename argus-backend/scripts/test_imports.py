#!/usr/bin/env python3

import sys
import os

# 添加项目根目录到Python路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from app.models.analysis import Task
    print("Successfully imported Task from app.models.analysis")
except ImportError as e:
    print(f"Import error: {e}")
    
try:
    from app.models.analysis import TaskStatus
    print("Successfully imported TaskStatus from app.models.analysis")
except ImportError as e:
    print(f"Import error: {e}")
    
try:
    from app.models.analysis import AnalysisConfig
    print("Successfully imported AnalysisConfig from app.models.analysis")
except ImportError as e:
    print(f"Import error: {e}") 