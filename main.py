
# ========================
# IMPORTS
# ========================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

import os
import random
import stripe

from passlib.context import CryptContext
from jose import jwt

from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import json
from fastapi import Request
# ========================
# CONFIG
# ========================
pwd_context = CryptContext(schemes=["bcrypt"])
SECRET = os.getenv("SECRET_KEY", "dev-secret")

# lien webhook
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "whsec_88258daee3745fa170a37bae7b5be12b3f1a0eb67db594e9cfa8b3311a99aed6")

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return payload["user_id"]
    except:
        return None
    
# ================
# HELPERS
# ================
import time

def is_subscription_valid(user):
    if not user.current_period_end:
        return False

    return user.current_period_end > int(time.time())

from fastapi import HTTPException

def require_premium(user):
    if not user or not is_subscription_valid(user):
        raise HTTPException(status_code=403, detail="Premium required")
# ========================
# DATABASE
# ========================
DATABASE_URL = "sqlite:///./food.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ========================
# MODEL
# ========================
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    password = Column(String)

    is_premium = Column(Boolean, default=False)
    filters = Column(String, default="{}")

    # 🔥 AJOUTS STRIPE
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    subscription_status = Column(String, nullable=True)
    current_period_end = Column(Integer, nullable=True)

    # 🔥 OPTIONNEL (propre pour ton app)
    plan_type = Column(String, default="free")

# ========================
# APP
# ========================
app = FastAPI()

Base.metadata.create_all(bind=engine)

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

# ========================
# MIDDLEWARE / STATIC
# ========================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

base_dir = os.path.dirname(os.path.abspath(__file__))

app.mount(
    "/static",
    StaticFiles(directory=os.path.join(base_dir, "static")),
    name="static"
)


# ========================
# ROUTES AUTH
# ========================
@app.post("/register")
def register(data: dict):
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == data["email"]).first()

        if existing:
            return {"error": "User already exists"}

        # 🔥 FIX PASSWORD
        password = data["password"].encode("utf-8")[:72].decode("utf-8", "ignore")
        hashed = pwd_context.hash(password)

        user = User(
            email=data["email"],
            password=hashed
        )

        db.add(user)
        db.commit()

        return {"message": "Account created"}
    finally:
        db.close()


@app.post("/login")
def login(data: dict):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == data["email"]).first()

        password = data["password"].encode("utf-8")[:72].decode("utf-8", "ignore")

        if not user or not pwd_context.verify(password, user.password):
            return {"error": "invalid credentials"}

        token = jwt.encode(
            {"user_id": user.id},
            SECRET,
            algorithm="HS256"
        )

        return {"token": token}
    finally:
        db.close()

@app.post("/save-filters")
def save_filters(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])

        user = db.query(User).filter(User.id == user_id).first()

        # 🔥 PROTECTION PREMIUM
        require_premium(user)

        user.filters = json.dumps(data["filters"])

        db.commit()

        return {"message": "saved"}

    finally:
        db.close()

@app.post("/get-filters")
def get_filters(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])

        user = db.query(User).filter(User.id == user_id).first()

        # 🔥 PROTECTION PREMIUM
        require_premium(user)

        filters = json.loads(user.filters)
        return {"filters": filters}

    finally:
        db.close()

@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            STRIPE_WEBHOOK_SECRET
        )
    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)

    # ✅ gérer les événements
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]

        user_id = session["metadata"].get("user_id")
        subscription_id = session.get("subscription")
        customer_id = session.get("customer")

        if user_id:
            db = SessionLocal()
            try:
                user = db.query(User).filter(User.id == user_id).first()

                if user:
                    user.is_premium = True
                    user.stripe_subscription_id = subscription_id
                    user.stripe_customer_id = customer_id
                    user.subscription_status = "active"
                    user.plan_type = "premium"

                    db.commit()

                    print(f"💎 User {user_id} premium activé")
            finally:
                db.close()
    
    elif event["type"] == "customer.subscription.updated":
        sub = event["data"]["object"]

        subscription_id = sub["id"]
        status = sub["status"]
        current_period_end = sub["current_period_end"]

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()

            if user:
                user.subscription_status = status
                user.current_period_end = current_period_end

                if status != "active":
                    user.is_premium = False
                    user.plan_type = "free"

                db.commit()

                print(f"🔄 Subscription updated: {status}")
        finally:
            db.close()

    if event["type"] == "customer.subscription.deleted":
        sub = event["data"]["object"]

        subscription_id = sub["id"]

        db = SessionLocal()
        try:
            user = db.query(User).filter(User.stripe_subscription_id == subscription_id).first()

            if user:
                user.is_premium = False
                user.subscription_status = "canceled"
                db.commit()
        finally:
            db.close()

    return {"status": "success"}

# ========================
# ROUTES EXISTANTES
# ========================
@app.get("/")
def read_index():
    return FileResponse(
        os.path.join(base_dir, "static", "index.html"),
        headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
    )

@app.get("/logo.png")
def logo_redirect():
    return FileResponse(os.path.join(base_dir, "static", "logo.png"))

@app.get("/manifest.json")
def manifest_redirect():
    return FileResponse(os.path.join(base_dir, "static", "manifest.json"))

@app.get("/index.html")
def index_redirect():
    return FileResponse(os.path.join(base_dir, "static", "index.html"))



# 🔍 DEBUG (à ajouter ici)

print("STATIC PATH:", os.path.join(base_dir, "static"))

print("BASE DIR:", base_dir)
print("STATIC EXISTS:", os.path.exists(os.path.join(base_dir, "static")))
print("FILES:", os.listdir(os.path.join(base_dir, "static")))

# 🍔 base de plats
plats = [
    {"nom": "Burger", "sucre": False, "sale": True, "rapide": True, "sante": False, "viande": True, "chaud": True, "image": "https://images.unsplash.com/photo-1568901346375-23c9450c58cd"},
    {"nom": "Salade", "sucre": False, "sale": True, "rapide": True, "sante": True, "viande": False, "chaud": False, "image": "https://images.unsplash.com/photo-1546069901-ba9599a7e63c"},
    {"nom": "Pizza", "sucre": False, "sale": True, "rapide": True, "sante": False, "viande": True, "chaud": True, "image": "https://images.unsplash.com/photo-1548365328-9f547fb0953d"},
    {"nom": "Smoothie", "sucre": True, "sale": False, "rapide": True, "sante": True, "viande": False, "chaud": False, "image": "https://images.unsplash.com/photo-1505252585461-04db1eb84625"}
]

# 🧠 préférences TEMPORAIRES (1 utilisateur à la fois)
preferences = {
    "sucre": 0,
    "sale": 0,
    "rapide": 0,
    "sante": 0,
    "viande": 0,
    "chaud": 0
}

# 🍽️ obtenir un plat
@app.get("/plat")
def get_plat():
    scored = []

    for plat in plats:
        score = 0
        for key in preferences:
            if plat[key]:
                score += preferences[key]

        scored.append((score, plat))

    scored.sort(key=lambda x: x[0], reverse=True)

    top = scored[:2] if len(scored) >= 2 else scored

    return random.choice(top)[1]

# 👍👎 feedback utilisateur
@app.post("/feedback")
def feedback(data: dict):
    like = data.get("like")
    plat = data.get("plat")

    if plat is None:
        return {"error": "plat manquant"}

    for key in preferences:
        if plat.get(key):
            if like:
                preferences[key] += 1
            else:
                preferences[key] -= 1

    return {
        "message": "ok",
        "preferences": preferences
    }
@app.post("/create-checkout-session")
def create_checkout_session(data: dict):
    try:
        user_id = get_current_user(data["token"])

        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{
                "price": "price_1TJ1HCD1kzixmLZnDlbHOA2a",
                "quantity": 1,
            }],
            success_url="http://127.0.0.1:8000/?success=true",
            cancel_url="http://127.0.0.1:8000?canceled=true",
            metadata={
                "user_id": user_id  # ✅ sécurisé
            }
        )

        return {"url": session.url}

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=400)


    
@app.post("/is-premium")
def is_premium(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return {"premium": False}

        # 🔥 logique premium réelle
        premium_status = user.is_premium and is_subscription_valid(user)

        return {"premium": premium_status}

    finally:
        db.close()

@app.post("/cancel-subscription")
def cancel_subscription(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        if not user or not user.stripe_subscription_id:
            return {"error": "No subscription"}

        # 🔥 annuler dans Stripe
        stripe.Subscription.delete(user.stripe_subscription_id)

        # 🔥 update DB
        user.is_premium = False
        user.subscription_status = "canceled"
        user.plan_type = "free"

        db.commit()

        return {"message": "Subscription canceled"}

    except Exception as e:
        return {"error": str(e)}

    finally:
        db.close()

@app.post("/verify-subscription")
def verify_subscription(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        # 🔥 ici tu recevras :
        # receipt Apple OU purchaseToken Google

        receipt = data.get("receipt")

        # ⚠️ pour l'instant fake validation
        if receipt:
            user.is_premium = True
            user.plan_type = "premium"

            db.commit()

            return {"status": "premium"}

        return {"status": "invalid"}

    finally:
        db.close()   