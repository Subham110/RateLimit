from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
)
from app.db.database import get_db
from app.db.redis import redis_client
from app.models.user import User
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
)

from fastapi import Request
from app.core.rate_limit import check_rate_limit

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)



@router.post("/register",status_code=status.HTTP_201_CREATED)
def register(data: RegisterRequest,request: Request,db: Session = Depends(get_db)):
    # Get client IP
    client_ip = request.client.host

    # Rate limit registration
    check_rate_limit(
        key=f"register:ip:{client_ip}",
        limit=settings.REGISTER_IP_LIMIT,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    # Check whether email already exists
    existing_user = db.scalar(
        select(User).where(User.email == data.email)
    )

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Hash password
    hashed_password = hash_password(data.password)

    # Create user
    user = User(
        name=data.name,
        email=data.email,
        password_hash=hashed_password,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {
        "message": "Registration successful",
        "user_id": user.id,
        "Name": user.name,
        "Email": user.email
    }



@router.post("/login",response_model=TokenResponse)
def login(data: LoginRequest,request: Request,db: Session = Depends(get_db)):
    
    client_ip = request.client.host

    normalized_email = data.email.strip().lower()

    # IP RATE LIMIT
    check_rate_limit(
        key=f"login:ip:{client_ip}",
        limit=settings.LOGIN_IP_LIMIT,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    # EMAIL RATE LIMIT
    check_rate_limit(
        key=f"login:email:{normalized_email}",
        limit=settings.LOGIN_EMAIL_LIMIT,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    # GLOBAL RATE LIMIT
    check_rate_limit(
        key="login:global",
        limit=settings.LOGIN_GLOBAL_LIMIT,
        window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    )

    # Find user
    user = db.scalar(
        select(User).where(
            User.email == normalized_email
        )
    )

    # Don't reveal whether email exists
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    # Verify password
    if not verify_password(data.password,user.password_hash):
        
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid email or password")
        
    # Create access JWT
    access_token = create_access_token(user.id)
    
    # Create refresh token
    refresh_token, refresh_jti = create_refresh_token(
        user.id
    )
    # Store session in Redis
    session_key = f"session:{refresh_jti}"

    redis_client.setex(
        session_key,
        60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS,
        str(user.id),
    )
    
    # Return response
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
        
    }