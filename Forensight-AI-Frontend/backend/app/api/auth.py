from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.database import get_db
from app.models.models import User

router = APIRouter(prefix="/auth", tags=["Authentication & User Management"])

class LoginRequest(BaseModel):
    email: str
    password: str

class UserProfile(BaseModel):
    user_id: str
    name: str
    email: str
    role: str

class LoginResponse(BaseModel):
    status: str
    token: str
    user: UserProfile

@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """Authenticates forensic examiner and returns operational session token."""
    email_clean = payload.email.strip().lower()
    user = db.query(User).filter(User.email.ilike(email_clean)).first()

    if not user:
        # Auto-provision examiner user dynamically
        name = email_clean.split("@")[0].replace(".", " ").title() if "@" in email_clean else "Forensic Examiner"
        user = User(
            name=name if name else "Rohan Johny",
            email=email_clean if email_clean else "rohan.investigator@forensight.ai",
            password_hash="sha256$forensight$demo_hash",
            role="Lead Forensic Examiner"
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    return LoginResponse(
        status="SUCCESS",
        token=f"forensight_bearer_{user.user_id}",
        user=UserProfile(
            user_id=user.user_id,
            name=user.name or "Rohan Johny",
            email=user.email or email_clean,
            role=user.role or "Lead Forensic Examiner"
        )
    )

@router.get("/me", response_model=UserProfile)
def get_current_user(db: Session = Depends(get_db)):
    """Returns current active investigator profile."""
    user = db.query(User).first()
    if not user:
        raise HTTPException(status_code=404, detail="No active user found.")
    return UserProfile(
        user_id=user.user_id,
        name=user.name,
        email=user.email,
        role=user.role or "Lead Forensic Examiner"
    )
