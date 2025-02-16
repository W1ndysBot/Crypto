import base64
import logging
import re
import os
import sys
import hashlib
import random
import string

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from app.api import send_group_msg, send_private_msg
from app.switch import load_switch, save_switch

menu_message = """编码解码功能如下：
1. b64d 解码base64
2. b64e 编码base64
3. hash 哈希值计算
4. bin2all 二进制转其他
5. oct2all 八进制转其他
6. dec2all 十进制转其他
7. hex2all 十六进制转其他
8. genpass 生成强密码"""


async def handle_crypto_help_message_group(websocket, group_id, user_id):
    await send_group_msg(
        websocket,
        group_id,
        f"[CQ:at,qq={user_id}]" + menu_message,
    )


async def handle_crypto_help_message_private(websocket, user_id):
    await send_private_msg(
        websocket,
        user_id,
        menu_message,
    )


def generate_password(length, complexity):
    if complexity == 1:
        chars = string.ascii_lowercase + string.digits
    elif complexity == 2:
        chars = string.ascii_letters + string.digits
    elif complexity == 3:
        chars = string.ascii_letters + string.digits + string.punctuation
    else:
        raise ValueError("无效的复杂度等级")

    return "".join(random.choice(chars) for _ in range(length))


async def handle_crypto_group_message(websocket, msg):
    try:
        user_id = msg["user_id"]
        group_id = msg["group_id"]
        raw_message = msg["raw_message"]
        # role = msg["sender"]["role"]
        # message_id = int(msg["message_id"])

        if raw_message == "Crypto":
            await handle_crypto_help_message_group(websocket, group_id, user_id)
            return

        # base64
        # 解码
        if raw_message.startswith("b64d "):
            encoded_message = raw_message[len("b64d ") :]
            if re.match(r"^[A-Za-z0-9+/]+={0,2}$", encoded_message):
                decoded_message = base64.b64decode(encoded_message).decode()
                decoded_message = f"[CQ:at,qq={user_id}]解码结果如下\n{decoded_message}"
                await send_group_msg(websocket, group_id, decoded_message)
            else:
                await send_group_msg(websocket, group_id, "无效的base64编码")
        # 编码
        elif raw_message.startswith("b64e "):
            decoded_message = raw_message[len("b64e ") :]
            encoded_message = base64.b64encode(decoded_message.encode()).decode()
            encoded_message = f"[CQ:at,qq={user_id}]编码结果如下\n{encoded_message}"
            await send_group_msg(websocket, group_id, encoded_message)

        # 哈希校验
        elif raw_message.startswith("hash "):
            message = raw_message[len("hash ") :]
            md5_encoded = hashlib.md5(message.encode()).hexdigest()
            sha1_encoded = hashlib.sha1(message.encode()).hexdigest()
            sha256_encoded = hashlib.sha256(message.encode()).hexdigest()
            sha512_encoded = hashlib.sha512(message.encode()).hexdigest()
            encoded_message = f"[CQ:at,qq={user_id}]哈希结果如下\nMD5: {md5_encoded}\nSHA1: {sha1_encoded}\nSHA256: {sha256_encoded}\nSHA512: {sha512_encoded}"
            await send_group_msg(websocket, group_id, encoded_message)
        # 进制转换
        elif raw_message.startswith("bin2all "):
            binary_number = raw_message[len("bin2all ") :]
            decimal_number = int(binary_number, 2)
            await send_group_msg(
                websocket, group_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("oct2all "):
            octal_number = raw_message[len("oct2all ") :]
            decimal_number = int(octal_number, 8)
            await send_group_msg(
                websocket, group_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("dec2all "):
            decimal_number = int(raw_message[len("dec2all ") :])
            await send_group_msg(
                websocket, group_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("hex2all "):
            hex_number = raw_message[len("hex2all ") :]
            decimal_number = int(hex_number, 16)
            await send_group_msg(
                websocket, group_id, format_conversion_message(user_id, decimal_number)
            )
        # 生成强密码
        elif raw_message.startswith("genpass "):
            try:
                parts = raw_message.split()
                length = int(parts[1])
                complexity = int(parts[2])
                password = generate_password(length, complexity)
                await send_group_msg(
                    websocket,
                    group_id,
                    f"[CQ:at,qq={user_id}]生成的密码如下\n{password}",
                )
            except (IndexError, ValueError):
                await send_group_msg(
                    websocket,
                    group_id,
                    "无效的命令格式。正确格式：genpass <长度> <复杂度>\n长度：1-100\n复杂度：1-3",
                )

    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return


async def handle_crypto_private_message(websocket, msg):
    try:
        user_id = msg["user_id"]
        raw_message = msg["raw_message"]

        if raw_message == "Crypto":
            await handle_crypto_help_message_private(websocket, user_id)
            return

        # base64
        # 解码
        if raw_message.startswith("b64d "):
            encoded_message = raw_message[len("b64d ") :]
            if re.match(r"^[A-Za-z0-9+/]+={0,2}$", encoded_message):
                decoded_message = base64.b64decode(encoded_message).decode()
                decoded_message = f"[CQ:at,qq={user_id}]解码结果如下\n{decoded_message}"
                await send_private_msg(websocket, user_id, decoded_message)
            else:
                await send_private_msg(websocket, user_id, "无效的base64编码")
        # 编码
        elif raw_message.startswith("b64e "):
            decoded_message = raw_message[len("b64e ") :]
            encoded_message = base64.b64encode(decoded_message.encode()).decode()
            encoded_message = f"[CQ:at,qq={user_id}]编码结果如下\n{encoded_message}"
            await send_private_msg(websocket, user_id, encoded_message)
        # MD5 编码
        elif raw_message.startswith("md5e "):
            message = raw_message[len("md5e ") :]
            md5_encoded = hashlib.md5(message.encode()).hexdigest()
            md5_encoded_message = f"[CQ:at,qq={user_id}]MD5编码结果如下\n{md5_encoded}"
            await send_private_msg(websocket, user_id, md5_encoded_message)
        # 进制转换
        elif raw_message.startswith("bin2all "):
            binary_number = raw_message[len("bin2all ") :]
            decimal_number = int(binary_number, 2)
            await send_private_msg(
                websocket, user_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("oct2all "):
            octal_number = raw_message[len("oct2all ") :]
            decimal_number = int(octal_number, 8)
            await send_private_msg(
                websocket, user_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("dec2all "):
            decimal_number = int(raw_message[len("dec2all ") :])
            await send_private_msg(
                websocket, user_id, format_conversion_message(user_id, decimal_number)
            )
        elif raw_message.startswith("hex2all "):
            hex_number = raw_message[len("hex2all ") :]
            decimal_number = int(hex_number, 16)
            await send_private_msg(
                websocket, user_id, format_conversion_message(user_id, decimal_number)
            )
        # 生成强密码
        elif raw_message.startswith("genpass "):
            try:
                parts = raw_message.split()
                length = int(parts[1])
                complexity = int(parts[2])
                password = generate_password(length, complexity)
                await send_private_msg(
                    websocket, user_id, f"生成的密码如下\n{password}"
                )
            except (IndexError, ValueError):
                await send_private_msg(
                    websocket,
                    user_id,
                    "无效的命令格式。正确格式：genpass <长度> <复杂度>",
                )

    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return


def format_conversion_message(user_id, decimal_number):
    binary = bin(decimal_number)[2:]
    octal = oct(decimal_number)[2:]
    hexadecimal = hex(decimal_number)[2:]
    return f"[CQ:at,qq={user_id}]转换结果如下\n二进制：{binary}\n八进制：{octal}\n十进制：{decimal_number}\n十六进制：{hexadecimal}"


# 统一事件处理入口
async def handle_events(websocket, msg):
    """统一事件处理入口"""
    post_type = msg.get("post_type", "response")  # 添加默认值
    try:
        # 处理回调事件
        if msg.get("status") == "ok":
            ...

        post_type = msg.get("post_type")

        # 处理元事件
        if post_type == "meta_event":
            ...

        # 处理消息事件
        elif post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                await handle_crypto_group_message(websocket, msg)
            elif message_type == "private":
                await handle_crypto_private_message(websocket, msg)

        # 处理通知事件
        elif post_type == "notice":
            if msg.get("notice_type") == "group":
                ...

    except Exception as e:
        error_type = {
            "message": "消息",
            "notice": "通知",
            "request": "请求",
            "meta_event": "元事件",
        }.get(post_type, "未知")

        logging.error(f"处理Crypto{error_type}事件失败: {e}")

        # 发送错误提示
        if post_type == "message":
            message_type = msg.get("message_type")
            if message_type == "group":
                await send_group_msg(
                    websocket,
                    msg.get("group_id"),
                    f"处理Crypto{error_type}事件失败，错误信息：{str(e)}",
                )
            elif message_type == "private":
                await send_private_msg(
                    websocket,
                    msg.get("user_id"),
                    f"处理Crypto{error_type}事件失败，错误信息：{str(e)}",
                )
