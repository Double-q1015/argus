from io import BytesIO
from captcha.image import ImageCaptcha
import random
import string
from fastapi.responses import StreamingResponse
import logging
import os

# 确保日志目录存在
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
log_dir = os.path.join(BASE_DIR, "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# 创建文件处理器
file_handler = logging.FileHandler(os.path.join(log_dir, 'captcha.log'))
file_handler.setLevel(logging.DEBUG)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到日志记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# 存储验证码的字典，key为session_id，value为验证码
captcha_store = {}

def generate_captcha_text(length: int = 4) -> str:
    """生成随机验证码文本"""
    characters = string.ascii_letters + string.digits
    text = ''.join(random.choice(characters) for _ in range(length))
    logger.debug(f"Generated captcha text: {text}")
    return text

def generate_captcha_image(text: str) -> BytesIO:
    """生成验证码图片"""
    image = ImageCaptcha(width=160, height=60)
    return image.generate(text)

def create_captcha(session_id: str) -> str:
    """创建新的验证码"""
    captcha_text = generate_captcha_text()
    captcha_store[session_id] = captcha_text
    logger.debug(f"Created captcha for session {session_id}: {captcha_text}")
    logger.debug(f"Current captcha store: {captcha_store}")
    return captcha_text

def verify_captcha(session_id: str, captcha_text: str) -> bool:
    """验证验证码"""
    logger.debug(f"Verifying captcha for session {session_id}")
    logger.debug(f"Input captcha: {captcha_text}")
    logger.debug(f"Current captcha store: {captcha_store}")
    
    stored_captcha = captcha_store.get(session_id)
    logger.debug(f"Stored captcha: {stored_captcha}")
    
    if not stored_captcha:
        logger.warning(f"No stored captcha found for session {session_id}")
        return False
    
    # 验证后删除验证码
    del captcha_store[session_id]
    result = stored_captcha.lower() == captcha_text.lower()
    logger.debug(f"Captcha verification result: {result}")
    return result

def get_captcha_image(session_id: str) -> StreamingResponse:
    """获取验证码图片"""
    captcha_text = create_captcha(session_id)
    image = generate_captcha_image(captcha_text)
    return StreamingResponse(image, media_type="image/png") 