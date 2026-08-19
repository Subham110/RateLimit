from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.post("/",response_model=UserResponse,status_code=status.HTTP_201_CREATED,)
def create_user(user_data: UserCreate,db: Session = Depends(get_db),):
    
    existing_user = db.scalar(select(User).where(User.email == user_data.email))

    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail="Email already registered")

    user = User(name=user_data.name,email=user_data.email,)

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.get("/",response_model=list[UserResponse],)
def get_users(db: Session = Depends(get_db),):
    users = db.scalars(select(User)).all()

    return users


@router.get("/{user_id}",response_model=UserResponse,)
def get_user(user_id: int,db: Session = Depends(get_db),):
    user = db.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user
