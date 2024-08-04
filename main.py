import base64
import logging
import re
import os
import sys

sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from app.api import send_group_msg, send_private_msg


async def handle_crypto_help_message(websocket, group_id, user_id):
    await send_group_msg(
        websocket,
        group_id,
        """
[CQ:at,qq={user_id}]
编码解码功能如下：
1. b64decode 解码base64编码
2. b64encode 编码base64编码
        """,
    )


async def handle_crypto_group_message(websocket, msg):
    try:
        user_id = msg["user_id"]
        group_id = msg["group_id"]
        raw_message = msg["raw_message"]
        role = msg["sender"]["role"]
        message_id = int(msg["message_id"])

        if raw_message == "编码解码":
            await handle_crypto_help_message(websocket, group_id, user_id)
            return

        # base64 编解码
        if raw_message.startswith("b64decode "):
            encoded_message = raw_message[len("b64decode ") :]
            if re.match(r"^[A-Za-z0-9+/]+={0,2}$", encoded_message):
                decoded_message = base64.b64decode(encoded_message).decode()
                decoded_message = f"[CQ:at,qq={user_id}]解码结果如下\n{decoded_message}"
                await send_group_msg(websocket, group_id, decoded_message)
            else:
                await send_group_msg(websocket, group_id, "无效的base64编码")
        elif raw_message.startswith("b64encode "):
            decoded_message = raw_message[len("b64encode ") :]
            encoded_message = base64.b64encode(decoded_message.encode()).decode()
            encoded_message = f"[CQ:at,qq={user_id}]编码结果如下\n{encoded_message}"
            await send_group_msg(websocket, group_id, encoded_message)
    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return


async def handle_crypto_private_message(websocket, msg):
    try:
        user_id = msg["user_id"]
        raw_message = msg["raw_message"]

        # base64 编解码
        if raw_message.startswith("b64decode "):
            encoded_message = raw_message[len("b64decode ") :]
            if re.match(r"^[A-Za-z0-9+/]+={0,2}$", encoded_message):
                decoded_message = base64.b64decode(encoded_message).decode()
                await send_private_msg(websocket, user_id, decoded_message)
            else:
                await send_private_msg(websocket, user_id, "无效的base64编码")

    except Exception as e:
        logging.error(f"处理编解码消息失败: {e}")
        return
