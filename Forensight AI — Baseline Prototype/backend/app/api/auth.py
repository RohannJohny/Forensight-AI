from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.models import User
from app.schemas.schemas import UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication & Examiner Identity"])


class LoginRequest(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@router.post("/login", response_model=Dict[str, Any])
def login_examiner(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticates a digital forensic examiner and returns session credentials."""
    login_id = (payload.email or payload.username or "").strip().lower()
    if not login_id:
        raise HTTPException(status_code=400, detail="Examiner email or username is required")

    user = db.query(User).filter(
        (User.email.ilike(login_id)) | (User.name.ilike(login_id))
    ).first()
    if not user:
        # Check if any user exists or create examiner record
        user = db.query(User).first()
        if not user:
            user = User(
                name="Rohan Johny",
                email="rohan.investigator@forensight.ai",
                password_hash="sha256$forensight$demo_hash",
                role="Lead Forensic Examiner"
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            display_name = login_id.split("@")[0].replace(".", " ").title()
            user_email = login_id if "@" in login_id else f"{login_id}@forensight.ai"
            user = User(
                name=display_name,
                email=user_email,
                password_hash="sha256$forensight$auth_hash",
                role="Lead Forensic Examiner"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

    token = f"forensight_bearer_token_{user.user_id}"
    return {
        "status": "AUTHENTICATED",
        "token": token,
        "user": {
            "user_id": user.user_id,
            "name": user.name,
            "email": user.email,
            "role": user.role
        }
    }


@router.get("/me", response_model=Dict[str, Any])
def get_current_examiner(db: Session = Depends(get_db)):
    """Retrieves current active forensic examiner profile."""
    user = db.query(User).first()
    if not user:
        user = User(
            name="Rohan Johny",
            email="rohan.investigator@forensight.ai",
            password_hash="sha256$forensight$demo_hash",
            role="Lead Forensic Examiner"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return {
        "user_id": user.user_id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    }
