from enum import Enum
from typing import Optional, List, Union
from pydantic import BaseModel, Field

class SearchOperator(str, Enum):
    EQUALS = "="
    GREATER = ">"
    LESS = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    CONTAINS = "contains"

class SearchType(str, Enum):
    # 基础搜索
    MD5 = "md5"
    SHA256 = "sha256"
    FILENAME = "filename"
    
    # Hash 搜索
    SHA1 = "sha1"
    IMPHASH = "imphash"
    
    # PE 元数据搜索
    DHASH = "dhash"
    FUZZY_DHASH = "fuzzy_dhash"
    COMPILE_TIME = "compile_time"
    ENTRYPOINT = "entrypoint"
    PLATFORM = "platform"
    SECTION = "section"
    IMPORT = "import"
    DLL = "dll"
    VERSION = "version"
    COMPANY = "company"
    PRODUCT = "product"
    ORIGINAL_NAME = "original_name"
    PDB = "pdb"
    ENTROPY = "entropy"
    SIGNED = "signed"
    
    # 资源搜索
    RESOURCE_TYPE = "resource_type"
    RESOURCE_LANG = "resource_lang"

class SearchCondition(BaseModel):
    type: SearchType
    value: str
    operator: SearchOperator = SearchOperator.EQUALS

class SearchQuery(BaseModel):
    conditions: List[SearchCondition] = Field(max_items=10)

class SearchResult(BaseModel):
    file_name: str
    description: Optional[str]
    file_path: str
    file_size: int
    file_type: str
    sha256_digest: str
    analysis_status: str

class SearchResponse(BaseModel):
    total: int
    results: List[SearchResult] 