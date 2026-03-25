import os
import redis

redis_host = os.getenv("REDIS_HOST", "127.0.0.1")
redis_port = int(os.getenv("REDIS_PORT", 6379))
redis_pass = os.getenv("REDIS_PASS", "mypass")

pool = redis.ConnectionPool(
    host=redis_host,
    port=redis_port,
    db=0,
    password=redis_pass,
    # ⏱️ 超时
    socket_timeout=5,
    socket_connect_timeout=5,
    # 🔁 重试
    retry_on_timeout=True,
    # ❤️ 心跳
    health_check_interval=30,
    # 🚨 限制连接数（关键）
    max_connections=50,
    # 🔧 TCP keepalive（非常重要）
    socket_keepalive=True,
    socket_keepalive_options={},
)
# 适配的redis版本
# redis 版本 redis:6.2.14-alpine
# 初始化 Redis 连接
r = redis.Redis(connection_pool=pool,
                ssl=False)
