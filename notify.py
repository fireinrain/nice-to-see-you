import os
from datetime import datetime

import pytz
import requests

BOT_TOKEN = None
CHAT_ID = None
bot_token = os.getenv('TG_BOT_TOKEN')
chat_id = os.getenv('TG_CHAT_ID')
if bot_token:
    BOT_TOKEN = bot_token
else:
    print(f"you must provide a bot token!")
if chat_id:
    CHAT_ID = chat_id
else:
    print(f"you must provide a chat_id!")


def send_telegram_message(message: str, mybot_token=BOT_TOKEN, channel_id=CHAT_ID):
    """
    Send a message to a Telegram channel.

    :param bot_token: Your Telegram Bot API token
    :param channel_id: The ID of the channel (including the '@' symbol for public channels)
    :param message: The message to send
    :return: True if successful, False otherwise
    """
    base_url = f"https://api.telegram.org/bot{mybot_token}/sendMessage"

    payload = {
        "chat_id": channel_id,
        "text": message,
        "parse_mode": "MarkdownV2"  # Optional: allows HTML formatting in your message
    }

    try:
        response = requests.post(base_url, json=payload)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error sending message: {e}")
        return False


def pretty_telegram_notify(message_header: str, message_from: str, message_info: str) -> str:
    # 设置时区为东八区
    tz = pytz.timezone("Asia/Shanghai")
    formatted_time = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")

    # 替换字符串中的字符
    froms = message_from.split(" ")
    tg_tag1 = froms[0].replace("-", "_")
    tag_tag2 = froms[1].replace("-", "_")

    # 构建消息字符串
    message = f"{message_header}\n\n- 消息来源: {message_from}\n- 当前时间：{formatted_time}\n- 提示消息：\n    {message_info}\n#{tg_tag1} #{tag_tag2}"
    return message


SPECIAL_CHARS = [
    '\\',
    '_',
    '*',
    '[',
    ']',
    '(',
    ')',
    '~',
    '`',
    '>',
    '<',
    '&',
    '#',
    '+',
    '-',
    '=',
    '|',
    '{',
    '}',
    '.',
    '!'
]


def clean_str_for_tg(data_str: str) -> str:
    for char in SPECIAL_CHARS:
        data_str = data_str.replace(char, f'\\{char}')
    return data_str


# Usage example
if __name__ == "__main__":
    BOT_TOKEN = "xxxxx"
    CHANNEL_ID = "xxxx"  # or use the channel's numerical ID
    MESSAGE = "Hello, Telegram channel!"

    telegram_notify = pretty_telegram_notify("🍻🍻Open-Port-Sniffer运行",
                                             "xx xx",
                                             f" changed to ")
    telegram_notify = clean_str_for_tg(telegram_notify)
    success = send_telegram_message(MESSAGE)

    if success:
        print("Message sent successfully!")
    else:
        print("Failed to send message.")
