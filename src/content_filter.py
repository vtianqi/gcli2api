"""
内容审查模块
请求进来先过滤敏感内容，保护上游账号不被封
"""

import re
from typing import Optional, Tuple
from log import log

# 敏感词列表（可扩展）
BLOCK_PATTERNS = [
    # 违法内容
    r"制作\s*(炸弹|爆炸物|毒品|武器)",
    r"如何\s*(杀人|自杀|伤害|攻击)",
    r"(儿童|未成年).{0,10}(色情|性|裸体)",
    r"(毒品|大麻|冰毒|海洛因).{0,10}(购买|获取|制作|合成)",
    # 账号安全相关（防止被 Claude 检测）
    r"(jailbreak|越狱|绕过|破解).{0,20}(限制|过滤|审查)",
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"你现在是.{0,20}(没有限制|不受约束|自由的AI)",
    r"pretend\s+you\s+(are|have\s+no)",
]

# 编译正则，提高性能
_COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in BLOCK_PATTERNS]

# 警告词（记录日志但不拦截）
WARN_PATTERNS = [
    r"(黑客|hacker|hack).{0,20}(教程|方法|技术)",
    r"(破解|crack).{0,10}(密码|账号|系统)",
]
_COMPILED_WARN_PATTERNS = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in WARN_PATTERNS]


def check_content(messages: list) -> Tuple[bool, Optional[str]]:
    """
    检查消息内容是否违规

    Args:
        messages: OpenAI 格式的消息列表 [{"role": "user", "content": "..."}]

    Returns:
        (is_safe, reason) — is_safe=True 表示安全，False 表示拦截
    """
    if not messages:
        return True, None

    # 拼接所有用户消息内容
    text_to_check = ""
    for msg in messages:
        if isinstance(msg, dict):
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role in ("user", "system") and isinstance(content, str):
                text_to_check += content + "\n"
            elif role in ("user", "system") and isinstance(content, list):
                # 多模态内容
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_to_check += block.get("text", "") + "\n"

    if not text_to_check.strip():
        return True, None

    # 检查拦截词
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(text_to_check)
        if match:
            reason = f"内容违规: 命中规则 [{match.group(0)[:30]}]"
            log.warning(f"[ContentFilter] 拦截请求: {reason}")
            return False, reason

    # 检查警告词（只记录，不拦截）
    for pattern in _COMPILED_WARN_PATTERNS:
        match = pattern.search(text_to_check)
        if match:
            log.warning(f"[ContentFilter] 警告请求包含敏感词: {match.group(0)[:30]}")

    return True, None


def check_content_safe_response() -> dict:
    """返回标准拦截响应"""
    return {
        "error": {
            "message": "Your request was flagged by our content policy. Please modify your message and try again.",
            "type": "content_policy_violation",
            "code": "content_filter"
        }
    }
