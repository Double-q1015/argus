from typing import List
from app.schemas.search import SearchCondition, SearchType, SearchOperator

class SearchParser:
    @staticmethod
    def parse_query(query: str) -> List[SearchCondition]:
        """
        解析搜索查询字符串，返回搜索条件列表
        
        格式示例：
        - sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        - filename:sample.exe
        """
        conditions = []
        query_lines = [line.strip() for line in query.split('\n') if line.strip()]
        
        for line in query_lines:
            if ':' not in line:
                continue
                
            search_type, value = line.split(':', 1)
            search_type = search_type.lower().strip()
            value = value.strip()
            
            try:
                # 验证搜索类型是否有效
                search_type_enum = SearchType(search_type)
                
                # 处理字符串中的引号
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                
                condition = SearchCondition(
                    type=search_type_enum,
                    value=value,
                    operator=SearchOperator.EQUALS if search_type_enum == SearchType.SHA256 
                            else SearchOperator.CONTAINS
                )
                conditions.append(condition)
                
            except ValueError:
                continue
                
        return conditions[:10]  # 限制最多10个条件 