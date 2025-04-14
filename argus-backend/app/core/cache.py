from typing import Dict, Any, Optional
from datetime import datetime, timedelta

class Cache:
    """
    简单的内存缓存实现
    """
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._expiry: Dict[str, datetime] = {}

    def get(self, key: str) -> Optional[Any]:
        """
        获取缓存值
        
        Args:
            key: 缓存键
            
        Returns:
            Optional[Any]: 缓存值，如果不存在或已过期则返回None
        """
        if key not in self._cache:
            return None
            
        if key in self._expiry and datetime.now() > self._expiry[key]:
            del self._cache[key]
            del self._expiry[key]
            return None
            
        return self._cache[key]

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """
        设置缓存值
        
        Args:
            key: 缓存键
            value: 缓存值
            ttl: 过期时间（秒），None表示永不过期
        """
        self._cache[key] = value
        if ttl is not None:
            self._expiry[key] = datetime.now() + timedelta(seconds=ttl)
        else:
            self._expiry[key] = datetime.max

    def delete(self, key: str):
        """
        删除缓存值
        
        Args:
            key: 缓存键
        """
        if key in self._cache:
            del self._cache[key]
        if key in self._expiry:
            del self._expiry[key]

    def clear(self):
        """清空所有缓存"""
        self._cache.clear()
        self._expiry.clear() 