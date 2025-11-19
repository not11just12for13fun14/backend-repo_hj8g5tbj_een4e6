import os
from typing import List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from bson.objectid import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Deposit as DepositSchema, Loan as LoanSchema, Message as MessageSchema, AuditLog as AuditSchema, Config as ConfigSchema

app = FastAPI(title="Community Savings API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utility helpers

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


def to_dict(doc):
    if not doc:
        return doc
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d


# Bootstrap indexes
@app.on_event("startup")
def ensure_indexes():
    if db is None:
        return
    db["user"].create_index("email", unique=True)
    db["user"].create_index("role")
    db["deposit"].create_index("user_id")
    db["loan"].create_index("user_id")
    db["message"].create_index("timestamp")
    db["auditlog"].create_index("timestamp")


# Auth models
class SignUpRequest(BaseModel):
    full_name: str
    email: EmailStr
    password: str
    role: str  # member or admin
    language: str = "en"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# Very simple password hash placeholder (in a real system, use bcrypt)
import hashlib

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


# Multilingual strings minimal set
TRANSLATIONS = {
    "en": {"welcome": "Welcome"},
    "ar": {"welcome": "مرحبا"},
    "sw": {"welcome": "Karibu"},
    "rw": {"welcome": "Murakaza neza"},
}

@app.get("/i18n/{lang}")
def get_translations(lang: str):
    return TRANSLATIONS.get(lang, TRANSLATIONS["en"])


# Auth Endpoints
@app.post("/auth/signup")
def signup(payload: SignUpRequest):
    # Enforce admin cap of 3
    role = payload.role.lower()
    if role not in ("member", "admin"):
        raise HTTPException(400, "Invalid role")

    if role == "admin":
        admin_count = db["user"].count_documents({"role": "admin"})
        if admin_count >= 3:
            raise HTTPException(403, "Admin limit reached (3)")

    user_doc = {
        "full_name": payload.full_name,
        "email": payload.email.lower(),
        "password_hash": hash_password(payload.password),
        "role": role,
        "language": payload.language if payload.language in ["en", "ar", "sw", "rw"] else "en",
        "profile_image": None,
        "is_active": True,
        "balance": 0.0,
        "savings": 0.0,
    }
    try:
        inserted_id = db["user"].insert_one(user_doc).inserted_id
        create_document("auditlog", AuditSchema(actor_id=str(inserted_id), action="signup", details=f"role={role}"))
    except Exception as e:
        raise HTTPException(400, f"Signup failed: {str(e)}")

    return {"id": str(inserted_id), "role": role}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email.lower()})
    if not user or user.get("password_hash") != hash_password(payload.password):
        raise HTTPException(401, "Invalid credentials")
    create_document("auditlog", AuditSchema(actor_id=str(user["_id"]), action="login"))
    return {"id": str(user["_id"]), "full_name": user["full_name"], "role": user["role"], "language": user.get("language", "en")}


# Financial Overview
@app.get("/dashboard/overview")
def financial_overview():
    users = list(db["user"].find({}))
    deposits = list(db["deposit"].find({"status": "accepted"}))
    active_loans = list(db["loan"].find({"status": "active"}))

    total_balance = sum(u.get("balance", 0.0) for u in users)
    total_savings = sum(u.get("savings", 0.0) for u in users)
    annual_cash_out = sum(d.get("amount", 0.0) for d in deposits)  # simplistic

    return {
        "total_balance": total_balance,
        "total_savings": total_savings,
        "active_loans": len(active_loans),
        "annual_cash_out": annual_cash_out,
    }


# Deposit Management
@app.get("/deposits")
def list_deposits():
    items = [to_dict(d) for d in db["deposit"].find({}).sort("_id", -1)]
    return items


@app.post("/deposits")
def create_deposit(user_id: str = Form(...), amount: float = Form(...), proof: Optional[UploadFile] = File(None)):
    proof_path = None
    if proof:
        os.makedirs("uploads", exist_ok=True)
        proof_path = os.path.join("uploads", f"{ObjectId()}{os.path.splitext(proof.filename)[1]}")
        with open(proof_path, "wb") as f:
            f.write(proof.file.read())

    dep = DepositSchema(user_id=user_id, amount=amount, status="pending", proof_path=proof_path)
    dep_id = create_document("deposit", dep)
    create_document("auditlog", AuditSchema(actor_id=user_id, action="deposit_created", details=str(dep_id)))
    return {"id": dep_id}


@app.post("/deposits/{deposit_id}/accept")
def accept_deposit(deposit_id: str):
    d = db["deposit"].find_one({"_id": oid(deposit_id)})
    if not d:
        raise HTTPException(404, "Deposit not found")
    if d.get("status") == "accepted":
        return {"status": "already accepted"}
    db["deposit"].update_one({"_id": oid(deposit_id)}, {"$set": {"status": "accepted"}})
    # Update user's savings and balance
    db["user"].update_one({"_id": oid(d["user_id"])}, {"$inc": {"savings": d["amount"], "balance": d["amount"]}})
    create_document("auditlog", AuditSchema(actor_id=str(d["user_id"]), action="deposit_accepted", details=deposit_id))
    return {"status": "accepted"}


@app.post("/deposits/{deposit_id}/reject")
def reject_deposit(deposit_id: str):
    d = db["deposit"].find_one({"_id": oid(deposit_id)})
    if not d:
        raise HTTPException(404, "Deposit not found")
    db["deposit"].update_one({"_id": oid(deposit_id)}, {"$set": {"status": "rejected"}})
    create_document("auditlog", AuditSchema(action="deposit_rejected", details=deposit_id))
    return {"status": "rejected"}


@app.get("/uploads/{filename}")
async def get_upload(filename: str):
    path = os.path.join("uploads", filename)
    if not os.path.exists(path):
        raise HTTPException(404, "File not found")
    return FileResponse(path)


# Loans Management
MAX_ACTIVE_LOANS = 30


def compute_interest(amount: float) -> float:
    base = 0.10
    multiplier = 2.0 if amount > 100 else 1.0
    interest = amount * base * multiplier
    return round(interest, 2)


class LoanApply(BaseModel):
    user_id: str
    amount: float


@app.get("/loans/active")
def list_active_loans():
    loans = [to_dict(l) for l in db["loan"].find({"status": "active"})]
    return loans


@app.get("/loans/user/{user_id}")
def loans_for_user(user_id: str):
    loans = [to_dict(l) for l in db["loan"].find({"user_id": user_id}).sort("_id", -1)]
    return loans


@app.post("/loans/apply")
def apply_loan(payload: LoanApply):
    # Enforce active loan limit
    active_count = db["loan"].count_documents({"status": "active"})
    if active_count >= MAX_ACTIVE_LOANS:
        raise HTTPException(403, "Max active loans reached")

    interest = compute_interest(payload.amount)
    total_payable = payload.amount + interest
    loan = LoanSchema(user_id=payload.user_id, amount=payload.amount, interest=interest, total_payable=total_payable, status="pending")
    loan_id = create_document("loan", loan)
    create_document("auditlog", AuditSchema(actor_id=payload.user_id, action="loan_applied", details=str(loan_id)))
    return {"id": loan_id, "status": "pending", "interest": interest, "total_payable": total_payable}


@app.post("/loans/{loan_id}/accept")
def accept_loan(loan_id: str):
    l = db["loan"].find_one({"_id": oid(loan_id)})
    if not l:
        raise HTTPException(404, "Loan not found")
    if l.get("status") == "active":
        return {"status": "already active"}
    # Activate the loan
    db["loan"].update_one({"_id": oid(loan_id)}, {"$set": {"status": "active"}})
    # Credit user's balance with the loan amount
    db["user"].update_one({"_id": oid(l["user_id"])}, {"$inc": {"balance": l["amount"]}})
    create_document("auditlog", AuditSchema(actor_id=str(l["user_id"]), action="loan_accepted", details=loan_id))
    return {"status": "active"}


@app.post("/loans/{loan_id}/reject")
def reject_loan(loan_id: str):
    l = db["loan"].find_one({"_id": oid(loan_id)})
    if not l:
        raise HTTPException(404, "Loan not found")
    db["loan"].update_one({"_id": oid(loan_id)}, {"$set": {"status": "rejected"}})
    create_document("auditlog", AuditSchema(action="loan_rejected", details=loan_id))
    return {"status": "rejected"}


# Chat
class MessageCreate(BaseModel):
    sender_id: str
    sender_name: str
    sender_avatar: Optional[str] = None
    recipient_id: Optional[str] = None
    text: str


@app.get("/chat/messages")
def list_messages(limit: int = 100):
    msgs = [to_dict(m) for m in db["message"].find({}).sort("timestamp", -1).limit(min(limit, 200))]
    return msgs[::-1]


@app.post("/chat/messages")
def send_message(payload: MessageCreate):
    msg = MessageSchema(**payload.model_dump())
    msg_id = create_document("message", msg)
    return {"id": msg_id}


# Audit Dashboard
@app.get("/audit")
def audit_logs(limit: int = 200):
    logs = [to_dict(a) for a in db["auditlog"].find({}).sort("timestamp", -1).limit(min(limit, 500))]
    return logs


# Annual Report (basic aggregated numbers)
@app.get("/reports/annual/{year}")
def annual_report(year: int):
    # Simplistic aggregations
    total_deposits = sum(d.get("amount", 0.0) for d in db["deposit"].find({"status": "accepted"}))
    loans = list(db["loan"].find({}))
    loan_stats = {
        "total": len(loans),
        "active": sum(1 for l in loans if l.get("status") == "active"),
        "rejected": sum(1 for l in loans if l.get("status") == "rejected"),
        "repaid": sum(1 for l in loans if l.get("status") == "repaid"),
        "pending": sum(1 for l in loans if l.get("status") == "pending"),
        "total_principal": sum(l.get("amount", 0.0) for l in loans),
        "total_interest": sum(l.get("interest", 0.0) for l in loans),
    }
    earnings = loan_stats["total_interest"]
    expenses = 0.0  # placeholder for more detailed model
    savings_performance = total_deposits

    return {
        "year": year,
        "total_deposits": total_deposits,
        "loan_performance": loan_stats,
        "earnings": earnings,
        "expenses": expenses,
        "savings_performance": savings_performance,
    }


# Admin Panel utilities
@app.get("/admin/stats")
def admin_stats():
    users_count = db["user"].count_documents({})
    admins = db["user"].count_documents({"role": "admin"})
    members = users_count - admins
    deposits = db["deposit"].count_documents({})
    loans = db["loan"].count_documents({})
    return {
        "users": users_count,
        "admins": admins,
        "members": members,
        "deposits": deposits,
        "loans": loans,
    }


class InterestUpdate(BaseModel):
    interest_base_rate: float
    interest_above_100_multiplier: float


@app.post("/admin/config/interest")
def update_interest(cfg: InterestUpdate):
    db["config"].update_one({}, {"$set": cfg.model_dump()}, upsert=True)
    create_document("auditlog", AuditSchema(action="config_interest_updated", details=str(cfg.model_dump())))
    return {"status": "ok"}


@app.get("/admin/users")
def list_users():
    return [to_dict(u) for u in db["user"].find({}).sort("_id", -1)]


@app.delete("/admin/users/{user_id}")
def remove_user(user_id: str):
    res = db["user"].delete_one({"_id": oid(user_id)})
    if res.deleted_count == 0:
        raise HTTPException(404, "User not found")
    create_document("auditlog", AuditSchema(action="user_removed", details=user_id))
    return {"status": "deleted"}


@app.get("/")
def read_root():
    return {"message": "Community Savings API Running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
