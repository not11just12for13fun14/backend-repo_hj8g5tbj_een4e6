"""
Database Schemas

Community Savings domain schemas using Pydantic models.
Each class name becomes a MongoDB collection with lowercase name.

Examples:
- User -> "user"
- Deposit -> "deposit"
- Loan -> "loan"
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal, List
from datetime import datetime


class Config(BaseModel):
    """System configuration (single document)
    Collection: config
    """
    interest_base_rate: float = Field(0.10, description="Base interest per 100 RWF (10% = 0.10)")
    interest_above_100_multiplier: float = Field(2.0, description="Multiplier for amounts > 100 RWF")


class User(BaseModel):
    """Users of the system (members and admins)
    Collection: user
    """
    full_name: str
    email: EmailStr
    password_hash: str
    role: Literal["member", "admin"] = "member"
    language: Literal["en", "ar", "sw", "rw"] = "en"
    profile_image: Optional[str] = None  # URL or path
    is_active: bool = True
    balance: float = 0.0
    savings: float = 0.0


class Deposit(BaseModel):
    """Deposits made by users
    Collection: deposit
    """
    user_id: str
    amount: float
    status: Literal["pending", "accepted", "rejected"] = "pending"
    proof_path: Optional[str] = None


class Loan(BaseModel):
    """Loans applied and managed
    Collection: loan
    """
    user_id: str
    amount: float
    interest: float
    total_payable: float
    status: Literal["pending", "active", "rejected", "repaid"] = "pending"


class Message(BaseModel):
    """Chat messages
    Collection: message
    """
    sender_id: str
    sender_name: str
    sender_avatar: Optional[str] = None
    recipient_id: Optional[str] = None  # None means group broadcast
    text: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AuditLog(BaseModel):
    """Audit trail
    Collection: auditlog
    """
    actor_id: Optional[str] = None
    action: str
    details: Optional[str] = None
    level: Literal["info", "warning", "security"] = "info"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
