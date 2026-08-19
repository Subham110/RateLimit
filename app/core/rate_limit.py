import time

from fastapi import HTTPException, status

from app.db.redis import redis_client


def check_rate_limit(
    key: str,
    limit: int,
    window_seconds: int) -> None:
    
    now = int(time.time())
    
    window = now // window_seconds

    redis_key = f"rate_limit:{key}:{window}"

    count = redis_client.incr(redis_key)

    if count == 1:
        redis_client.expire(
            redis_key,
            window_seconds,
        )

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={
                "Retry-After": str(window_seconds),
            },
        )