"""
GET /auth/google
GET /auth/google/callback

GET /auth/microsoft
GET /auth/microsoft/callback

GET /auth/github
GET /auth/github/callback

"""

from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
)
from app.db.database import get_db
from app.db.redis import redis_client
from app.services.oauth_service import get_or_create_oauth_user

from authlib.integrations.starlette_client import OAuth


router = APIRouter(
    prefix="/auth",
    tags=["OAuth"],
)


oauth = OAuth()


oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url=(
        "https://accounts.google.com/"
        ".well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile",
    },
    
    name="microsoft",
    client_id=settings.MICROSOFT_CLIENT_ID,
    client_secret=settings.MICROSOFT_CLIENT_SECRET,
    server_metadata_url=(
        "https://login.microsoftonline.com/"
        "common/v2.0/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile",
    },
    
    name="github",
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={
        "scope": "read:user user:email",
    },
)

@router.get("/google")
async def google_login(request: Request):
    return await oauth.google.authorize_redirect(
        request,
        settings.GOOGLE_REDIRECT_URI,
    )

@router.get("/google/callback")
async def google_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    token = await oauth.google.authorize_access_token(
        request
    )

    user_info = token.get("userinfo")

    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Unable to retrieve Google user",
        )

    email = user_info.get("email")

    if not email or not user_info.get("email_verified"):
        raise HTTPException(
            status_code=400,
            detail="Verified email is required",
        )

    user = get_or_create_oauth_user(
        db,
        provider="google",
        subject=user_info["sub"],
        email=email.lower(),
        name=user_info.get("name") or email,
    )

    access_token = create_access_token(user.id)

    refresh_token, refresh_jti = create_refresh_token(
        user.id
    )

    redis_client.setex(
        f"session:{refresh_jti}",
        60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS,
        str(user.id),
    )

    return {
        "message": "Google login successful",
        "access_token": access_token,
        "token_type": "bearer",
    }
    
    
@router.get("/microsoft")
async def microsoft_login(request: Request):
    return await oauth.microsoft.authorize_redirect(
        request,
        settings.MICROSOFT_REDIRECT_URI,
    )
    
@router.get("/microsoft/callback")
async def microsoft_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    token = await oauth.microsoft.authorize_access_token(
        request
    )

    user_info = token.get("userinfo")

    if not user_info:
        raise HTTPException(
            status_code=401,
            detail="Unable to retrieve Microsoft user",
        )

    email = (
        user_info.get("email")
        or user_info.get("preferred_username")
    )

    if not email:
        raise HTTPException(
            status_code=400,
            detail="Email not available",
        )

    user = get_or_create_oauth_user(
        db,
        provider="microsoft",
        subject=user_info["sub"],
        email=email.lower(),
        name=user_info.get("name") or email,
    )

    access_token = create_access_token(user.id)

    refresh_token, refresh_jti = create_refresh_token(
        user.id
    )

    redis_client.setex(
        f"session:{refresh_jti}",
        60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS,
        str(user.id),
    )

    return {
        "message": "Microsoft login successful",
        "access_token": access_token,
        "token_type": "bearer",
    }
    
@router.get("/github")
async def github_login(request: Request):
    return await oauth.github.authorize_redirect(
        request,
        settings.GITHUB_REDIRECT_URI,
    )
    
@router.get("/github/callback")
async def github_callback(
    request: Request,
    db: Session = Depends(get_db),
):
    token = await oauth.github.authorize_access_token(
        request
    )

    response = await oauth.github.get(
        "user",
        token=token,
    )

    github_user = response.json()

    email = github_user.get("email")

    # GitHub can have private email addresses.
    if not email:
        email_response = await oauth.github.get(
            "user/emails",
            token=token,
        )

        emails = email_response.json()

        primary_email = next(
            (
                item
                for item in emails
                if item.get("primary")
                and item.get("verified")
            ),
            None,
        )

        if primary_email:
            email = primary_email["email"]

    if not email:
        raise HTTPException(
            status_code=400,
            detail="Verified GitHub email is required",
        )

    user = get_or_create_oauth_user(
        db,
        provider="github",
        subject=str(github_user["id"]),
        email=email.lower(),
        name=github_user.get("name")
        or github_user.get("login")
        or email,
    )

    access_token = create_access_token(user.id)

    refresh_token, refresh_jti = create_refresh_token(
        user.id
    )

    redis_client.setex(
        f"session:{refresh_jti}",
        60 * 60 * 24 * settings.REFRESH_TOKEN_EXPIRE_DAYS,
        str(user.id),
    )

    return {
        "message": "GitHub login successful",
        "access_token": access_token,
        "token_type": "bearer",
    }

