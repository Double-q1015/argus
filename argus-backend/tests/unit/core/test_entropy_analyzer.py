import os
import pytest
import sys
from pathlib import Path
from collections import defaultdict

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))