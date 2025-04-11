from typing import List, Union, Optional, Dict, Any
from pydantic import BaseSettings, validator
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler


load_dotenv()

class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Argus"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Argus API"
    # 系统用户
    SYSTEM_USER: str = "system_admin"
    # 系统用户密码
    SYSTEM_USER_PASSWORD: str = "system_admin_password"
    
    # CORS配置
    BACKEND_CORS_ORIGINS: List[str] = []

    @validator("BACKEND_CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # JWT配置
    SECRET_KEY: str = "your-secret-key-here"  # 在生产环境中应该使用环境变量
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30


    # MongoDB配置
    MONGODB_URL: str = "mongodb://192.168.2.9:27017"
    MONGODB_DB: str = "argus"

    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS: List[str] = ["jpg", "jpeg", "png", "gif"]

    # MinIO配置
    MINIO_ENDPOINT: str = "192.168.2.9:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET_NAME: str = "malware"
    MINIO_SECURE: bool = False
    
    # 压缩配置
    COMPRESSION_PASSWORD: str = "infected"
    
    # 日志配置
    LOG_DIR: str = "logs"
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5

    # AWS S3配置
    S3_ENDPOINT: Optional[str] = None
    S3_ACCESS_KEY: Optional[str] = None
    S3_SECRET_KEY: Optional[str] = None
    S3_REGION: str = "us-east-1"
    S3_BUCKET_NAME: Optional[str] = None
    S3_SECURE: bool = True
    
    # 本地文件存储配置
    LOCAL_STORAGE_PATH: str = "/data/argus-samples"
    
    # 存储配置
    STORAGE_TYPE: str = "minio"  # 可选值: "minio", "s3", "local"

    # 配置样本文件在存储系统中的保存路径，建议使用sha256_digest的前四个字节作为四级目录
    # 也可以配置sha256_digest作为路径，例如：
    # SAMPLE_STORAGE_PATTERN: str = "sha256_digest"
    SAMPLE_STORAGE_PREFIX: str = "samples"
    SAMPLE_STORAGE_PATTERN: str = "sha256_digest[0]/sha256_digest[1]/sha256_digest[2]/sha256_digest[3]/sha256_digest"
    
    @property
    def storage_config(self) -> Dict[str, Any]:
        """获取存储配置"""
        if self.STORAGE_TYPE == "minio":
            return {
                "endpoint": self.MINIO_ENDPOINT,
                "access_key": self.MINIO_ACCESS_KEY,
                "secret_key": self.MINIO_SECRET_KEY,
                "secure": self.MINIO_SECURE,
                "bucket_name": self.MINIO_BUCKET_NAME
            }
        elif self.STORAGE_TYPE == "s3":
            if not all([self.S3_ACCESS_KEY, self.S3_SECRET_KEY, self.S3_BUCKET_NAME]):
                raise ValueError("S3 configuration is incomplete")
            return {
                "endpoint": self.S3_ENDPOINT,
                "access_key": self.S3_ACCESS_KEY,
                "secret_key": self.S3_SECRET_KEY,
                "region": self.S3_REGION,
                "bucket_name": self.S3_BUCKET_NAME,
                "secure": self.S3_SECURE
            }
        elif self.STORAGE_TYPE == "local":
            return {
                "base_path": self.LOCAL_STORAGE_PATH
            }
        else:
            raise ValueError(f"Unsupported storage type: {self.STORAGE_TYPE}")

    def setup_logging(self):
        """配置日志系统"""
        # 创建日志目录
        if not os.path.exists(self.LOG_DIR):
            os.makedirs(self.LOG_DIR)
        
        # 配置根日志记录器
        root_logger = logging.getLogger()
        root_logger.setLevel(self.LOG_LEVEL)
        
        # 创建文件处理器
        file_handler = RotatingFileHandler(
            os.path.join(self.LOG_DIR, "app.log"),
            maxBytes=self.LOG_MAX_BYTES,
            backupCount=self.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )
        file_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(self.LOG_FORMAT))
        
        # 添加处理器
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
settings.setup_logging()  # 初始化时设置日志 

# 语言定义
LANG_DICT = {
    0x007f: "LANG_INVARIANT",
    0x0036: "LANG_AFRIKAANS",
    0x001c: "LANG_ALBANIAN",
    0x0084: "LANG_ALSATIAN",
    0x005e: "LANG_AMHARIC",
    0x0001: "LANG_ARABIC",
    0x002b: "LANG_ARMENIAN",
    0x004d: "LANG_ASSAMESE",
    0x002c: "LANG_AZERBAIJANI",  # 使用 LANG_AZERBAIJANI 替代 LANG_AZERI
    0x0045: "LANG_BANGLA",
    0x006d: "LANG_BASHKIR",
    0x002d: "LANG_BASQUE",
    0x0023: "LANG_BELARUSIAN",
    0x0045: "LANG_BENGALI",  # 与 LANG_BANGLA 相同
    0x007e: "LANG_BRETON",
    0x001a: "LANG_BOSNIAN",
    0x781a: "LANG_BOSNIAN_NEUTRAL",
    0x0002: "LANG_BULGARIAN",
    0x0003: "LANG_CATALAN",
    0x0092: "LANG_CENTRAL_KURDISH",
    0x005c: "LANG_CHEROKEE",
    0x0004: "LANG_CHINESE",
    0x7c04: "LANG_CHINESE_TRADITIONAL",
    0x0083: "LANG_CORSICAN",
    0x001a: "LANG_CROATIAN",
    0x0005: "LANG_CZECH",
    0x0006: "LANG_DANISH",
    0x008c: "LANG_DARI",
    0x0065: "LANG_DIVEHI",
    0x0013: "LANG_DUTCH",
    0x0009: "LANG_ENGLISH",
    0x0025: "LANG_ESTONIAN",
    0x0038: "LANG_FAEROESE",
    0x0029: "LANG_PERSIAN",  # 使用 LANG_PERSIAN 替代 LANG_FARSI
    0x0064: "LANG_FILIPINO",
    0x000b: "LANG_FINNISH",
    0x000c: "LANG_FRENCH",
    0x0062: "LANG_FRISIAN",
    0x0067: "LANG_FULAH",
    0x0056: "LANG_GALICIAN",
    0x0037: "LANG_GEORGIAN",
    0x0007: "LANG_GERMAN",
    0x0008: "LANG_GREEK",
    0x006f: "LANG_GREENLANDIC",
    0x0047: "LANG_GUJARATI",
    0x0068: "LANG_HAUSA",
    0x0075: "LANG_HAWAIIAN",
    0x000d: "LANG_HEBREW",
    0x0039: "LANG_HINDI",
    0x000e: "LANG_HUNGARIAN",
    0x000f: "LANG_ICELANDIC",
    0x0070: "LANG_IGBO",
    0x0021: "LANG_INDONESIAN",
    0x005d: "LANG_INUKTITUT",
    0x003c: "LANG_IRISH",
    0x0010: "LANG_ITALIAN",
    0x0011: "LANG_JAPANESE",
    0x004b: "LANG_KANNADA",
    0x0060: "LANG_KASHMIRI",
    0x003f: "LANG_KAZAK",
    0x0053: "LANG_KHMER",
    0x0086: "LANG_KICHE",
    0x0087: "LANG_KINYARWANDA",
    0x0057: "LANG_KONKANI",
    0x0012: "LANG_KOREAN",
    0x0040: "LANG_KYRGYZ",
    0x0054: "LANG_LAO",
    0x0026: "LANG_LATVIAN",
    0x0027: "LANG_LITHUANIAN",
    0x002e: "LANG_LOWER_SORBIAN",
    0x006e: "LANG_LUXEMBOURGISH",
    0x002f: "LANG_MACEDONIAN",
    0x003e: "LANG_MALAY",
    0x004c: "LANG_MALAYALAM",
    0x003a: "LANG_MALTESE",
    0x0058: "LANG_MANIPURI",
    0x0081: "LANG_MAORI",
    0x007a: "LANG_MAPUDUNGUN",
    0x004e: "LANG_MARATHI",
    0x007c: "LANG_MOHAWK",
    0x0050: "LANG_MONGOLIAN",
    0x0061: "LANG_NEPALI",
    0x0014: "LANG_NORWEGIAN",
    0x0082: "LANG_OCCITAN",
    0x0048: "LANG_ODIA",  # 使用 LANG_ODIA 替代 LANG_ORIYA
    0x0063: "LANG_PASHTO",
    0x0015: "LANG_POLISH",
    0x0016: "LANG_PORTUGUESE",
    0x0046: "LANG_PUNJABI",
    0x006b: "LANG_QUECHUA",
    0x0018: "LANG_ROMANIAN",
    0x0017: "LANG_ROMANSH",
    0x0019: "LANG_RUSSIAN",
    0x0085: "LANG_SAKHA",  # 使用 LANG_SAKHA 替代 LANG_YAKUT
    0x003b: "LANG_SAMI",
    0x004f: "LANG_SANSKRIT",
    0x0091: "LANG_SCOTTISH_GAELIC",
    0x001a: "LANG_SERBIAN",
    0x7c1a: "LANG_SERBIAN_NEUTRAL",
    0x0059: "LANG_SINDHI",
    0x005b: "LANG_SINHALESE",
    0x001b: "LANG_SLOVAK",
    0x0024: "LANG_SLOVENIAN",
    0x006c: "LANG_SOTHO",
    0x000a: "LANG_SPANISH",
    0x0041: "LANG_SWAHILI",
    0x001d: "LANG_SWEDISH",
    0x005a: "LANG_SYRIAC",
    0x0028: "LANG_TAJIK",
    0x005f: "LANG_TAMAZIGHT",
    0x0049: "LANG_TAMIL",
    0x0044: "LANG_TATAR",
    0x004a: "LANG_TELUGU",
    0x001e: "LANG_THAI",
    0x0051: "LANG_TIBETAN",
    0x0073: "LANG_TIGRINYA",  # 使用 LANG_TIGRINYA 替代 LANG_TIGRIGNA
    0x0032: "LANG_TSWANA",
    0x001f: "LANG_TURKISH",
    0x0042: "LANG_TURKMEN",
    0x0080: "LANG_UIGHUR",
    0x0022: "LANG_UKRAINIAN",
    0x0020: "LANG_URDU",
    0x0043: "LANG_UZBEK",
    0x002a: "LANG_VIETNAMESE",
    0x0052: "LANG_WELSH",
    0x0088: "LANG_WOLOF",
    0x0034: "LANG_XHOSA",
    0x0078: "LANG_YI",
    0x006a: "LANG_YORUBA",
    0x0035: "LANG_ZULU",
    0x0000: "LANG_NEUTRAL",
   
}

SUBLANG_DICT = {
    # 通用子语言
    "NEUTRAL": {
        0x00: "SUBLANG_NEUTRAL",           # language neutral
        0x01: "SUBLANG_DEFAULT",           # user default
        0x02: "SUBLANG_SYS_DEFAULT",       # system default
        0x03: "SUBLANG_CUSTOM_DEFAULT",    # default custom language/locale
        0x04: "SUBLANG_CUSTOM_UNSPECIFIED",# custom language/locale
        0x05: "SUBLANG_UI_CUSTOM_DEFAULT"  # Default custom MUI language/locale
    },
    
    # 阿拉伯语子语言
    "ARABIC": {
        0x01: "SUBLANG_ARABIC_SAUDI_ARABIA",
        0x02: "SUBLANG_ARABIC_IRAQ",
        0x03: "SUBLANG_ARABIC_EGYPT",
        0x04: "SUBLANG_ARABIC_LIBYA",
        0x05: "SUBLANG_ARABIC_ALGERIA",
        0x06: "SUBLANG_ARABIC_MOROCCO",
        0x07: "SUBLANG_ARABIC_TUNISIA",
        0x08: "SUBLANG_ARABIC_OMAN",
        0x09: "SUBLANG_ARABIC_YEMEN",
        0x0a: "SUBLANG_ARABIC_SYRIA",
        0x0b: "SUBLANG_ARABIC_JORDAN",
        0x0c: "SUBLANG_ARABIC_LEBANON",
        0x0d: "SUBLANG_ARABIC_KUWAIT",
        0x0e: "SUBLANG_ARABIC_UAE",
        0x0f: "SUBLANG_ARABIC_BAHRAIN",
        0x10: "SUBLANG_ARABIC_QATAR"
    },

    # 中文子语言
    "CHINESE": {
        0x01: "SUBLANG_CHINESE_TRADITIONAL",  # Chinese (Taiwan)
        0x02: "SUBLANG_CHINESE_SIMPLIFIED",   # Chinese (PR China)
        0x03: "SUBLANG_CHINESE_HONGKONG",     # Chinese (Hong Kong S.A.R., P.R.C.)
        0x04: "SUBLANG_CHINESE_SINGAPORE",    # Chinese (Singapore)
        0x05: "SUBLANG_CHINESE_MACAU"         # Chinese (Macau S.A.R.)
    },

    # 英语子语言
    "ENGLISH": {
        0x01: "SUBLANG_ENGLISH_US",           # English (USA)
        0x02: "SUBLANG_ENGLISH_UK",           # English (UK)
        0x03: "SUBLANG_ENGLISH_AUS",          # English (Australian)
        0x04: "SUBLANG_ENGLISH_CAN",          # English (Canadian)
        0x05: "SUBLANG_ENGLISH_NZ",           # English (New Zealand)
        0x06: "SUBLANG_ENGLISH_EIRE",         # English (Irish)
        0x07: "SUBLANG_ENGLISH_SOUTH_AFRICA", # English (South Africa)
        0x08: "SUBLANG_ENGLISH_JAMAICA",      # English (Jamaica)
        0x09: "SUBLANG_ENGLISH_CARIBBEAN",    # English (Caribbean)
        0x0a: "SUBLANG_ENGLISH_BELIZE",       # English (Belize)
        0x0b: "SUBLANG_ENGLISH_TRINIDAD",     # English (Trinidad)
        0x0c: "SUBLANG_ENGLISH_ZIMBABWE",     # English (Zimbabwe)
        0x0d: "SUBLANG_ENGLISH_PHILIPPINES",  # English (Philippines)
        0x10: "SUBLANG_ENGLISH_INDIA",        # English (India)
        0x11: "SUBLANG_ENGLISH_MALAYSIA",     # English (Malaysia)
        0x12: "SUBLANG_ENGLISH_SINGAPORE"     # English (Singapore)
    },

    # 法语子语言
    "FRENCH": {
        0x01: "SUBLANG_FRENCH",               # French
        0x02: "SUBLANG_FRENCH_BELGIAN",       # French (Belgian)
        0x03: "SUBLANG_FRENCH_CANADIAN",      # French (Canadian)
        0x04: "SUBLANG_FRENCH_SWISS",         # French (Swiss)
        0x05: "SUBLANG_FRENCH_LUXEMBOURG",    # French (Luxembourg)
        0x06: "SUBLANG_FRENCH_MONACO"         # French (Monaco)
    },

    # 德语子语言
    "GERMAN": {
        0x01: "SUBLANG_GERMAN",               # German
        0x02: "SUBLANG_GERMAN_SWISS",         # German (Swiss)
        0x03: "SUBLANG_GERMAN_AUSTRIAN",      # German (Austrian)
        0x04: "SUBLANG_GERMAN_LUXEMBOURG",    # German (Luxembourg)
        0x05: "SUBLANG_GERMAN_LIECHTENSTEIN"  # German (Liechtenstein)
    },

    # 意大利语子语言
    "ITALIAN": {
        0x01: "SUBLANG_ITALIAN",              # Italian
        0x02: "SUBLANG_ITALIAN_SWISS"         # Italian (Swiss)
    },

    # 日语子语言
    "JAPANESE": {
        0x01: "SUBLANG_JAPANESE_JAPAN"        # Japanese (Japan)
    },

    # 韩语子语言
    "KOREAN": {
        0x01: "SUBLANG_KOREAN"                # Korean (Extended Wansung)
    },

    # 葡萄牙语子语言
    "PORTUGUESE": {
        0x01: "SUBLANG_PORTUGUESE_BRAZILIAN", # Portuguese (Brazil)
        0x02: "SUBLANG_PORTUGUESE"            # Portuguese
    },

    # 俄语子语言
    "RUSSIAN": {
        0x01: "SUBLANG_RUSSIAN_RUSSIA"        # Russian (Russia)
    },

    # 西班牙语子语言
    "SPANISH": {
        0x01: "SUBLANG_SPANISH",              # Spanish (Castilian)
        0x02: "SUBLANG_SPANISH_MEXICAN",      # Spanish (Mexico)
        0x03: "SUBLANG_SPANISH_MODERN",       # Spanish (Modern)
        0x04: "SUBLANG_SPANISH_GUATEMALA",    # Spanish (Guatemala)
        0x05: "SUBLANG_SPANISH_COSTA_RICA",   # Spanish (Costa Rica)
        0x06: "SUBLANG_SPANISH_PANAMA",       # Spanish (Panama)
        0x07: "SUBLANG_SPANISH_DOMINICAN_REPUBLIC", # Spanish (Dominican Republic)
        0x08: "SUBLANG_SPANISH_VENEZUELA",    # Spanish (Venezuela)
        0x09: "SUBLANG_SPANISH_COLOMBIA",     # Spanish (Colombia)
        0x0a: "SUBLANG_SPANISH_PERU",         # Spanish (Peru)
        0x0b: "SUBLANG_SPANISH_ARGENTINA",    # Spanish (Argentina)
        0x0c: "SUBLANG_SPANISH_ECUADOR",      # Spanish (Ecuador)
        0x0d: "SUBLANG_SPANISH_CHILE",        # Spanish (Chile)
        0x0e: "SUBLANG_SPANISH_URUGUAY",      # Spanish (Uruguay)
        0x0f: "SUBLANG_SPANISH_PARAGUAY",     # Spanish (Paraguay)
        0x10: "SUBLANG_SPANISH_BOLIVIA",      # Spanish (Bolivia)
        0x11: "SUBLANG_SPANISH_EL_SALVADOR",  # Spanish (El Salvador)
        0x12: "SUBLANG_SPANISH_HONDURAS",     # Spanish (Honduras)
        0x13: "SUBLANG_SPANISH_NICARAGUA",    # Spanish (Nicaragua)
        0x14: "SUBLANG_SPANISH_PUERTO_RICO",  # Spanish (Puerto Rico)
        0x15: "SUBLANG_SPANISH_US"            # Spanish (United States)
    },

    # 塞尔维亚语子语言
    "SERBIAN": {
        0x01: "SUBLANG_SERBIAN_CROATIA",      # Croatian (Croatia)
        0x02: "SUBLANG_SERBIAN_LATIN",        # Serbian (Latin)
        0x03: "SUBLANG_SERBIAN_CYRILLIC",     # Serbian (Cyrillic)
        0x06: "SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_LATIN",    # Serbian (Bosnia and Herzegovina - Latin)
        0x07: "SUBLANG_SERBIAN_BOSNIA_HERZEGOVINA_CYRILLIC", # Serbian (Bosnia and Herzegovina - Cyrillic)
        0x09: "SUBLANG_SERBIAN_SERBIA_LATIN", # Serbian (Serbia - Latin)
        0x0a: "SUBLANG_SERBIAN_SERBIA_CYRILLIC", # Serbian (Serbia - Cyrillic)
        0x0b: "SUBLANG_SERBIAN_MONTENEGRO_LATIN",    # Serbian (Montenegro - Latn)
        0x0c: "SUBLANG_SERBIAN_MONTENEGRO_CYRILLIC"  # Serbian (Montenegro - Cyrillic)
    },

    # 其他语言的子语言
    "OTHER": {
        # 阿非利卡语
        "AFRIKAANS": {
            0x01: "SUBLANG_AFRIKAANS_SOUTH_AFRICA"  # Afrikaans (South Africa)
        },
        # 阿尔巴尼亚语
        "ALBANIAN": {
            0x01: "SUBLANG_ALBANIAN_ALBANIA"  # Albanian (Albania)
        },
        # 阿姆哈拉语
        "AMHARIC": {
            0x01: "SUBLANG_AMHARIC_ETHIOPIA"  # Amharic (Ethiopia)
        },
        # 亚美尼亚语
        "ARMENIAN": {
            0x01: "SUBLANG_ARMENIAN_ARMENIA"  # Armenian (Armenia)
        },
        # 阿塞拜疆语
        "AZERBAIJANI": {
            0x01: "SUBLANG_AZERBAIJANI_AZERBAIJAN_LATIN",    # Azerbaijani (Azerbaijan, Latin)
            0x02: "SUBLANG_AZERBAIJANI_AZERBAIJAN_CYRILLIC"  # Azerbaijani (Azerbaijan, Cyrillic)
        },
        # 孟加拉语
        "BANGLA": {
            0x01: "SUBLANG_BANGLA_INDIA",      # Bangla (India)
            0x02: "SUBLANG_BANGLA_BANGLADESH"  # Bangla (Bangladesh)
        },
        # 巴斯克语
        "BASQUE": {
            0x01: "SUBLANG_BASQUE_BASQUE"  # Basque (Basque)
        },
        # 白俄罗斯语
        "BELARUSIAN": {
            0x01: "SUBLANG_BELARUSIAN_BELARUS"  # Belarusian (Belarus)
        },
        # 波斯尼亚语
        "BOSNIAN": {
            0x05: "SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_LATIN",     # Bosnian (Bosnia and Herzegovina - Latin)
            0x08: "SUBLANG_BOSNIAN_BOSNIA_HERZEGOVINA_CYRILLIC"   # Bosnian (Bosnia and Herzegovina - Cyrillic)
        },
        # 保加利亚语
        "BULGARIAN": {
            0x01: "SUBLANG_BULGARIAN_BULGARIA"  # Bulgarian (Bulgaria)
        },
        # 加泰罗尼亚语
        "CATALAN": {
            0x01: "SUBLANG_CATALAN_CATALAN"  # Catalan (Catalan)
        },
        # 捷克语
        "CZECH": {
            0x01: "SUBLANG_CZECH_CZECH_REPUBLIC"  # Czech (Czech Republic)
        },
        # 丹麦语
        "DANISH": {
            0x01: "SUBLANG_DANISH_DENMARK"  # Danish (Denmark)
        },
        # 荷兰语
        "DUTCH": {
            0x01: "SUBLANG_DUTCH",           # Dutch
            0x02: "SUBLANG_DUTCH_BELGIAN"    # Dutch (Belgian)
        },
        # 爱沙尼亚语
        "ESTONIAN": {
            0x01: "SUBLANG_ESTONIAN_ESTONIA"  # Estonian (Estonia)
        },
        # 芬兰语
        "FINNISH": {
            0x01: "SUBLANG_FINNISH_FINLAND"  # Finnish (Finland)
        },
        # 希腊语
        "GREEK": {
            0x01: "SUBLANG_GREEK_GREECE"  # Greek (Greece)
        },
        # 希伯来语
        "HEBREW": {
            0x01: "SUBLANG_HEBREW_ISRAEL"  # Hebrew (Israel)
        },
        # 印地语
        "HINDI": {
            0x01: "SUBLANG_HINDI_INDIA"  # Hindi (India)
        },
        # 匈牙利语
        "HUNGARIAN": {
            0x01: "SUBLANG_HUNGARIAN_HUNGARY"  # Hungarian (Hungary)
        },
        # 冰岛语
        "ICELANDIC": {
            0x01: "SUBLANG_ICELANDIC_ICELAND"  # Icelandic (Iceland)
        },
        # 印尼语
        "INDONESIAN": {
            0x01: "SUBLANG_INDONESIAN_INDONESIA"  # Indonesian (Indonesia)
        },
        # 爱尔兰语
        "IRISH": {
            0x02: "SUBLANG_IRISH_IRELAND"  # Irish (Ireland)
        },
        # 卡纳达语
        "KANNADA": {
            0x01: "SUBLANG_KANNADA_INDIA"  # Kannada (India)
        },
        # 哈萨克语
        "KAZAK": {
            0x01: "SUBLANG_KAZAK_KAZAKHSTAN"  # Kazakh (Kazakhstan)
        },
        # 高棉语
        "KHMER": {
            0x01: "SUBLANG_KHMER_CAMBODIA"  # Khmer (Cambodia)
        },
        # 吉尔吉斯语
        "KYRGYZ": {
            0x01: "SUBLANG_KYRGYZ_KYRGYZSTAN"  # Kyrgyz (Kyrgyzstan)
        },
        # 老挝语
        "LAO": {
            0x01: "SUBLANG_LAO_LAO"  # Lao (Lao PDR)
        },
        # 拉脱维亚语
        "LATVIAN": {
            0x01: "SUBLANG_LATVIAN_LATVIA"  # Latvian (Latvia)
        },
        # 立陶宛语
        "LITHUANIAN": {
            0x01: "SUBLANG_LITHUANIAN"  # Lithuanian
        },
        # 马来语
        "MALAY": {
            0x01: "SUBLANG_MALAY_MALAYSIA",        # Malay (Malaysia)
            0x02: "SUBLANG_MALAY_BRUNEI_DARUSSALAM" # Malay (Brunei Darussalam)
        },
        # 马拉雅拉姆语
        "MALAYALAM": {
            0x01: "SUBLANG_MALAYALAM_INDIA"  # Malayalam (India)
        },
        # 马耳他语
        "MALTESE": {
            0x01: "SUBLANG_MALTESE_MALTA"  # Maltese (Malta)
        },
        # 毛利语
        "MAORI": {
            0x01: "SUBLANG_MAORI_NEW_ZEALAND"  # Maori (New Zealand)
        },
        # 蒙古语
        "MONGOLIAN": {
            0x01: "SUBLANG_MONGOLIAN_CYRILLIC_MONGOLIA",  # Mongolian (Cyrillic, Mongolia)
            0x02: "SUBLANG_MONGOLIAN_PRC"                 # Mongolian (PRC)
        },
        # 尼泊尔语
        "NEPALI": {
            0x01: "SUBLANG_NEPALI_NEPAL",   # Nepali (Nepal)
            0x02: "SUBLANG_NEPALI_INDIA"    # Nepali (India)
        },
        # 挪威语
        "NORWEGIAN": {
            0x01: "SUBLANG_NORWEGIAN_BOKMAL",  # Norwegian (Bokmal)
            0x02: "SUBLANG_NORWEGIAN_NYNORSK"  # Norwegian (Nynorsk)
        },
        # 波兰语
        "POLISH": {
            0x01: "SUBLANG_POLISH_POLAND"  # Polish (Poland)
        },
        # 罗马尼亚语
        "ROMANIAN": {
            0x01: "SUBLANG_ROMANIAN_ROMANIA"  # Romanian (Romania)
        },
        # 斯洛伐克语
        "SLOVAK": {
            0x01: "SUBLANG_SLOVAK_SLOVAKIA"  # Slovak (Slovakia)
        },
        # 斯洛文尼亚语
        "SLOVENIAN": {
            0x01: "SUBLANG_SLOVENIAN_SLOVENIA"  # Slovenian (Slovenia)
        },
        # 瑞典语
        "SWEDISH": {
            0x01: "SUBLANG_SWEDISH",           # Swedish
            0x02: "SUBLANG_SWEDISH_FINLAND"    # Swedish (Finland)
        },
        # 泰语
        "THAI": {
            0x01: "SUBLANG_THAI_THAILAND"  # Thai (Thailand)
        },
        # 土耳其语
        "TURKISH": {
            0x01: "SUBLANG_TURKISH_TURKEY"  # Turkish (Turkey)
        },
        # 乌克兰语
        "UKRAINIAN": {
            0x01: "SUBLANG_UKRAINIAN_UKRAINE"  # Ukrainian (Ukraine)
        },
        # 乌尔都语
        "URDU": {
            0x01: "SUBLANG_URDU_PAKISTAN",  # Urdu (Pakistan)
            0x02: "SUBLANG_URDU_INDIA"      # Urdu (India)
        },
        # 乌兹别克语
        "UZBEK": {
            0x01: "SUBLANG_UZBEK_LATIN",     # Uzbek (Latin)
            0x02: "SUBLANG_UZBEK_CYRILLIC"   # Uzbek (Cyrillic)
        },
        # 越南语
        "VIETNAMESE": {
            0x01: "SUBLANG_VIETNAMESE_VIETNAM"  # Vietnamese (Vietnam)
        },
        # 威尔士语
        "WELSH": {
            0x01: "SUBLANG_WELSH_UNITED_KINGDOM"  # Welsh (United Kingdom)
        }
    }
}

RESOURCE_TYPE_DICT = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}