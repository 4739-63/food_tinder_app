
# ========================
# IMPORTS
# ========================
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, FileResponse

import os
import requests
import random
import stripe

import hashlib
import hmac
import secrets
from jose import jwt

from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

import json
from fastapi import Request
# ========================
# CONFIG
# ========================

SECRET = os.getenv("SECRET_KEY", "dev-secret")

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100000
    ).hex()
    return f"{salt}${hashed}"

def verify_password(password: str, stored_password: str) -> bool:
    try:
        salt, saved_hash = stored_password.split("$", 1)
        check_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000
        ).hex()
        return hmac.compare_digest(saved_hash, check_hash)
    except Exception:
        return False

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

def detect_language(text: str) -> str:
    text = (text or "").lower()

    french_words = [
        "recette", "poulet", "boeuf", "bœuf", "déjeuner", "dîner", "souper",
        "fromage", "santé", "salade", "gâteau", "chocolat", "maison",
        "facile", "rapide", "délicieux", "épicé"
    ]

    english_words = [
        "recipe", "chicken", "beef", "breakfast", "lunch", "dinner",
        "cheese", "healthy", "salad", "cake", "chocolate", "homemade",
        "easy", "quick", "delicious", "spicy"
    ]

    fr_score = sum(1 for w in french_words if w in text)
    en_score = sum(1 for w in english_words if w in text)

    if fr_score > en_score:
        return "fr"
    if en_score > fr_score:
        return "en"
    return "unknown"


def calculate_feed_score(post, likes: int, comments: int):
    now = int(time.time())
    age_hours = max(1, (now - (post.created_at or now)) / 3600)

    # 🔥 fraîcheur
    freshness_score = max(0, 30 - age_hours * 0.6)

    # 🔥 popularité
    popularity_score = likes * 0.8 + comments * 1.6

    # 🔥 type de contenu
    media_score = 4 if post.media_type == "video" else 1

    # 🔥 exploration (découverte)
    exploration_score = random.random() * 8

    # 🔥 langue
    lang = detect_language(post.caption)

    lang_bonus = 0
    if lang == "fr":
        lang_bonus = 3
    elif lang == "en":
        lang_bonus = 1

    # 🔥 score final
    return (
        freshness_score +
        popularity_score +
        media_score +
        exploration_score +
        lang_bonus
    )

def has_seen_post_recently(db, user_id, post_id):
    if not user_id:
        return False

    recent = int(time.time()) - 60 * 60 * 6  # 6h

    return db.query(PostView).filter(
        PostView.user_id == user_id,
        PostView.post_id == post_id,
        PostView.viewed_at > recent
    ).first() is not None

def calculate_trending_score(likes, comments, created_at):
    age_hours = max(1, (time.time() - created_at) / 3600)

    return (likes * 2 + comments * 3) / age_hours

def dynamic_rerank(scored_posts, max_items):
    final = []
    seen_users = set()
    recent_categories = []

    for item in scored_posts:
        post = item["post"]
        features = detect_food_features(post)

        category = None
        for key, value in features.items():
            if value and key not in ["video", "image", "lang_fr", "lang_en"]:
                category = key
                break

        if post.user_id in seen_users:
            item["score"] -= 12

        if category and recent_categories.count(category) >= 2:
            item["score"] -= 10

        final.append({
            **item,
            "category": category
        })

    final.sort(key=lambda x: x["score"], reverse=True)

    clean = []
    used_ids = set()

    for item in final:
        post = item["post"]

        if post.id in used_ids:
            continue

        used_ids.add(post.id)
        clean.append(item)

        if item.get("category"):
            recent_categories.append(item["category"])

        seen_users.add(post.user_id)

        if len(clean) >= max_items:
            break

    return clean

def ml_light_score(post, likes, comments, taste):
    features = detect_food_features(post)

    score = 0

    weights = {
        "like_rate": 1.2,
        "comment_rate": 2.2,
        "video": 4,
        "image": 1,
        "fresh": 3,
        "personal": 2.5,
    }

    score += likes * weights["like_rate"]
    score += comments * weights["comment_rate"]

    if post.media_type == "video":
        score += weights["video"]
    else:
        score += weights["image"]

    if taste:
        for key, active in features.items():
            if active and hasattr(taste, key):
                score += (getattr(taste, key) or 0) * weights["personal"]

    return score

INTERNAL_MEALS = [
    {
        "idMeal": "internal_v1",
        "nom": "Vegan Burger",
        "image": "https://images.unsplash.com/photo-1550547660-d9450f859349",
        "recette": "Cook plant-based patty, assemble with bun, lettuce and sauce.",
        "ingredients": ["Vegan bun", "Plant-based patty", "Lettuce", "Tomato"],

        "vegan": True,
        "gluten": True,
        "arachide": False,

        "style_comfort": True,
        "base_bread_wrap": True,
        "rapide": True,

        "categoryName": "Burger",
        "areaName": "Global"
    },
    {
        "idMeal": "internal_v2",
        "nom": "Quinoa Salad",
        "image": "https://images.unsplash.com/photo-1505253210343-d5f897a4c1e3?auto=format&fit=crop&w=1200&q=80",
        "recette": "Mix cooked quinoa with fresh vegetables, olive oil and lemon.",
        "ingredients": ["Quinoa", "Tomato", "Cucumber", "Olive oil"],

        "vegan": True,
        "gluten": False,
        "arachide": False,

        "style_comfort": False,
        "base_bread_wrap": False,
        "rapide": True,

        "categoryName": "Healthy",
        "areaName": "Global"
    },
    {
        "idMeal": "internal_v3",
        "nom": "Vegan Pad Thai",
        "image": "https://images.unsplash.com/photo-1604908176997-431f0c6c2c3b?auto=format&fit=crop&w=1200&q=80",
        "recette": "Cook rice noodles, add tofu, vegetables and sauce, then mix well.",
        "ingredients": ["Rice noodles", "Tofu", "Carrot", "Bean sprouts", "Soy sauce"],

        "vegan": True,
        "gluten": False,
        "arachide": True,

        "style_comfort": True,
        "base_bread_wrap": False,
        "rapide": True,

        "categoryName": "Asian",
        "areaName": "Thailand"
    },
    {
       "idMeal": "internal_v4",
        "nom": "Vegan Tacos",
        "image": "https://images.unsplash.com/photo-1600891964599-f61ba0e24092",
        "recette": "Fill tortillas with black beans, avocado, veggies and vegan sauce.",
        "ingredients": ["Tortilla", "Black beans", "Avocado", "Tomato", "Lettuce"],

        "vegan": True,
        "gluten": True,
        "arachide": False,

        "style_comfort": True,
        "base_bread_wrap": True,
        "rapide": True,

        "categoryName": "Mexican",
        "areaName": "Mexico"
    },
    {
        "idMeal": "internal_v5",
        "nom": "Vegan Buddha Bowl",
        "image": "https://images.unsplash.com/photo-1512621776951-a57141f2eefd",
        "recette": "Combine rice, roasted vegetables, chickpeas and tahini sauce.",
        "ingredients": ["Rice", "Chickpeas", "Broccoli", "Carrot", "Tahini"],

        "vegan": True,
        "gluten": False,
        "arachide": False,

        "style_comfort": False,
        "base_bread_wrap": False,
        "rapide": True,

        "categoryName": "Healthy",
        "areaName": "Global"
    },
    {
        "idMeal": "internal_v6",
        "nom": "Vegan Chocolate Dessert",
        "image": "https://images.unsplash.com/photo-1541783245831-57d6fb0926d3",
        "recette": "Mix cocoa, plant milk and sugar, chill and serve.",
        "ingredients": ["Cocoa", "Plant milk", "Sugar"],

        "vegan": True,
        "gluten": False,
        "arachide": False,

        "sucre": True,
        "dessert": True,

        "style_comfort": True,
        "base_bread_wrap": False,
        "rapide": True,

        "categoryName": "Dessert",
        "areaName": "Global"
    },
    {
        "idMeal": "internal_v7",
        "nom": "Vegan Pasta Primavera",
        "image": "https://images.unsplash.com/photo-1525755662778-989d0524087e",
        "recette": "Cook pasta and mix with sautéed vegetables and olive oil.",
        "ingredients": ["Pasta", "Zucchini", "Tomato", "Olive oil"],
        "vegan": True, "gluten": True, "arachide": False,
        "style_comfort": True, "base_bread_wrap": False, "rapide": True,
        "categoryName": "Italian", "areaName": "Italy"
    },
    {
        "idMeal": "internal_v8",
        "nom": "Vegan Smoothie Bowl",
        "image": "https://images.unsplash.com/photo-1490645935967-10de6ba17061",
        "recette": "Blend fruits and top with granola and seeds.",
        "ingredients": ["Banana", "Berries", "Granola"],
        "vegan": True, "gluten": False, "arachide": False,
        "sucre": True, "dessert": True,
        "style_comfort": False, "rapide": True,
        "categoryName": "Dessert", "areaName": "Global"
    },
    {
        "idMeal": "internal_v9",
        "nom": "Vegan Curry",
        "image": "https://images.unsplash.com/photo-1585937421612-70a008356fbe?auto=format&fit=crop&w=1200&q=80",
        "recette": "Cook vegetables with coconut milk and curry spices.",
        "ingredients": ["Coconut milk", "Carrot", "Potato"],
        "vegan": True, "gluten": False, "arachide": False,
        "style_comfort": True, "rapide": True,
        "categoryName": "Indian", "areaName": "India"
    },
    {
        "idMeal": "internal_v10",
        "nom": "Vegan Avocado Toast",
        "image": "https://images.unsplash.com/photo-1546069901-ba9599a7e63c",
        "recette": "Spread avocado on toasted bread with seasoning.",
        "ingredients": ["Bread", "Avocado", "Salt"],
        "vegan": True, "gluten": True, "arachide": False,
        "rapide": True, "base_bread_wrap": True,
        "categoryName": "Breakfast", "areaName": "Global"
    },
    {
        "idMeal": "internal_v11",
        "nom": "Vegan Falafel Wrap",
        "image": "https://images.unsplash.com/photo-1546069901-ba9599a7e63c?auto=format&fit=crop&w=1200&q=80",
        "recette": "Wrap falafel with veggies and sauce.",
        "ingredients": ["Falafel", "Wrap", "Salad"],
        "vegan": True, "gluten": True, "arachide": False,
        "style_comfort": True, "base_bread_wrap": True,
        "categoryName": "Middle Eastern", "areaName": "Lebanon"
    },
    {
        "idMeal": "internal_v12",
        "nom": "Vegan Sushi",
        "image": "https://images.unsplash.com/photo-1579871494447-9811cf80d66c?auto=format&fit=crop&w=1200&q=80",
        "recette": "Roll rice with vegetables in seaweed.",
        "ingredients": ["Rice", "Nori", "Cucumber"],
        "vegan": True, "gluten": False, "arachide": False,
        "categoryName": "Asian", "areaName": "Japan"
    },
    {
        "idMeal": "internal_v13",
        "nom": "Vegan Pancakes",
        "image": "https://images.unsplash.com/photo-1504754524776-8f4f37790ca0",
        "recette": "Cook pancakes with plant milk and flour.",
        "ingredients": ["Flour", "Plant milk", "Sugar"],
        "vegan": True, "gluten": True, "arachide": False,
        "sucre": True, "dessert": True,
        "style_comfort": True,
        "categoryName": "Dessert", "areaName": "Global"
    },
    {
        "idMeal": "internal_v14",
        "nom": "Vegan Chili",
        "image": "https://images.unsplash.com/photo-1574894709920-11b28e7367e3?auto=format&fit=crop&w=1200&q=80",
        "recette": "Cook beans with tomato sauce and spices.",
        "ingredients": ["Beans", "Tomato", "Spices"],
        "vegan": True, "gluten": False, "arachide": False,
        "style_comfort": True,
        "categoryName": "Mexican", "areaName": "Mexico"
    },
    {
        "idMeal": "internal_v15",
        "nom": "Vegan Caesar Salad",
        "image": "https://images.unsplash.com/photo-1550304943-4f24f54ddde9",
        "recette": "Mix lettuce with vegan dressing and croutons.",
        "ingredients": ["Lettuce", "Croutons", "Dressing"],
        "vegan": True, "gluten": True, "arachide": False,
        "categoryName": "Healthy", "areaName": "Global"
    },
    {
        "idMeal": "internal_v16",
        "nom": "Vegan Burrito Bowl",
        "image": "https://images.unsplash.com/photo-1546069901-5ec6a79120b0?auto=format&fit=crop&w=1200&q=80",
        "recette": "Combine rice, beans, avocado and salsa.",
        "ingredients": ["Rice", "Beans", "Avocado"],
        "vegan": True, "gluten": False, "arachide": False,
        "style_comfort": True,
        "categoryName": "Mexican", "areaName": "Mexico"
    },
    {
        "idMeal": "internal_v17",
        "nom": "Vegan Ice Cream",
        "image": "https://images.unsplash.com/photo-1563805042-7684c019e1cb?auto=format&fit=crop&w=1200&q=80",
        "recette": "Blend frozen fruits into creamy texture.",
        "ingredients": ["Frozen banana", "Cocoa"],
        "vegan": True, "gluten": False, "arachide": False,
        "sucre": True, "dessert": True,
        "categoryName": "Dessert", "areaName": "Global"
    },
    {
        "idMeal": "internal_v18",
        "nom": "Vegan Ramen",
        "image": "https://images.unsplash.com/photo-1569718212165-3a8278d5f624?auto=format&fit=crop&w=1200&q=80",
        "recette": "Cook noodles in vegetable broth.",
        "ingredients": ["Noodles", "Broth", "Veggies"],
        "vegan": True, "gluten": True, "arachide": False,
        "style_comfort": True,
        "categoryName": "Asian", "areaName": "Japan"
    },
    {
        "idMeal": "internal_v19",
        "nom": "Vegan Energy Balls",
        "image": "https://images.unsplash.com/photo-1590080874088-eec64895b423?auto=format&fit=crop&w=1200&q=80",
        "recette": "Mix oats, dates and cocoa into balls.",
        "ingredients": ["Oats", "Dates", "Cocoa"],
        "vegan": True, "gluten": False, "arachide": False,
        "sucre": True, "dessert": True,
        "rapide": True,
        "categoryName": "Snack", "areaName": "Global"
    },
    {
        "idMeal": "internal_v20",
        "nom": "Vegan Pizza",
        "image": "https://images.unsplash.com/photo-1601924582975-7e2d6c9f2c6f?auto=format&fit=crop&w=1200&q=80",
        "recette": "Top pizza with veggies and vegan cheese.",
        "ingredients": ["Dough", "Tomato", "Vegan cheese"],
        "vegan": True, "gluten": True, "arachide": False,
        "style_comfort": True,
        "categoryName": "Italian", "areaName": "Italy"
    }


]

# ========================
# DATABASE
# ========================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./food.db")

engine_kwargs = {}

if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
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
    name = Column(String, nullable=True)
    bio = Column(String, default="Food lover ")
    avatar = Column(String, nullable=True)
    # 🔥 AJOUTS STRIPE
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    subscription_status = Column(String, nullable=True)
    current_period_end = Column(Integer, nullable=True)

    # 🔥 OPTIONNEL (propre pour ton app)
    plan_type = Column(String, default="free")

class Post(Base):
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    username = Column(String)

    # image/photo ou ancienne URL vidéo
    image = Column(String)

    # image ou video
    media_type = Column(String, default="image")

    caption = Column(String)
    is_hidden = Column(Boolean, default=False)
    created_at = Column(Integer)

    # 🔥 nouvelles colonnes vidéo scalable
    video_provider = Column(String, nullable=True)          # cloudflare_stream / mux
    video_id = Column(String, nullable=True)                # id vidéo du provider
    video_playback_url = Column(String, nullable=True)      # URL lecture vidéo
    thumbnail_url = Column(String, nullable=True)           # miniature vidéo

class Like(Base):
    __tablename__ = "likes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)

class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    username = Column(String)
    text = Column(String)       

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    reason = Column(String)
    created_at = Column(Integer)

class Follow(Base):
    __tablename__ = "follows"

    id = Column(Integer, primary_key=True)
    follower_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    following_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(Integer, default=lambda: int(time.time()))

#===========
# mémoire algo
#==========
class UserTaste(Base):
    __tablename__ = "user_tastes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    lang_fr = Column(Integer, default=0)
    lang_en = Column(Integer, default=0)

    italian = Column(Integer, default=0)
    mexican = Column(Integer, default=0)
    asian = Column(Integer, default=0)
    comfort = Column(Integer, default=0)
    fresh = Column(Integer, default=0)
    sweet = Column(Integer, default=0)
    salty = Column(Integer, default=0)
    homemade = Column(Integer, default=0)
    quick = Column(Integer, default=0)

    pasta = Column(Integer, default=0)
    burger = Column(Integer, default=0)
    healthy = Column(Integer, default=0)
    dessert = Column(Integer, default=0)
    breakfast = Column(Integer, default=0)
    vegan = Column(Integer, default=0)
    spicy = Column(Integer, default=0)

    chicken = Column(Integer, default=0)
    beef = Column(Integer, default=0)
    seafood = Column(Integer, default=0)

    video = Column(Integer, default=0)
    image = Column(Integer, default=0)

    updated_at = Column(Integer, default=lambda: int(time.time()))

class PostView(Base):
    __tablename__ = "post_views"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    post_id = Column(Integer, ForeignKey("posts.id"))
    viewed_at = Column(Integer)

# ========================
# APP
# ========================
app = FastAPI()

Base.metadata.create_all(bind=engine)

from sqlalchemy import text

with engine.connect() as conn:
    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_type VARCHAR DEFAULT 'image';
    """))
    conn.commit()

with engine.connect() as conn:
    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS video_provider VARCHAR;
    """))

    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS video_id VARCHAR;
    """))

    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS video_playback_url VARCHAR;
    """))

    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS thumbnail_url VARCHAR;
    """))

    conn.commit()

from sqlalchemy import text

with engine.connect() as conn:
    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_hidden BOOLEAN DEFAULT FALSE;
    """))

    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            post_id INTEGER NOT NULL REFERENCES posts(id),
            reason VARCHAR,
            created_at INTEGER
        );
    """))

    conn.commit()

with engine.connect() as conn:
    conn.execute(text("""
        ALTER TABLE posts ADD COLUMN IF NOT EXISTS media_type VARCHAR DEFAULT 'image';
    """))
    conn.commit()

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

        password = data["password"]
        hashed = hash_password(password)

        user = User(
            email=data["email"],
            password=hashed,
            name=data.get("name"),
            bio=data.get("bio", "Food lover 🍽️"),
            avatar=data.get("avatar")
        )

        db.add(user)
        db.commit()

        return {"message": "Account created"}

    except Exception as e:
        print("REGISTER ERROR:", str(e))
        return JSONResponse(content={"error": str(e)}, status_code=500)

    finally:
        db.close()


@app.post("/login")
def login(data: dict):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == data["email"]).first()

        password = data["password"]

        if not user or not verify_password(password, user.password):
            return {"error": "invalid credentials"}

        token = jwt.encode(
            {
                "user_id": user.id,
                "exp": int(time.time()) + 60 * 60 * 24
            },
            SECRET,
            algorithm="HS256"
        )

        return {"token": token}

    except Exception as e:
        print("LOGIN ERROR:", str(e))
        return JSONResponse(content={"error": str(e)}, status_code=500)

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
        # 🔐 Vérification du token
        user_id = get_current_user(data.get("token"))

        if not user_id:
            return JSONResponse(
                content={"error": "Session expired. Please login again."},
                status_code=401
            )

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(
                content={"error": "Unauthorized"},
                status_code=401
            )

        # 📦 Vérification receipt
        receipt = data.get("receipt")

        if not receipt:
            return JSONResponse(
                content={"error": "Missing receipt"},
                status_code=400
            )

        # ⚠️ VERSION TEMPORAIRE (sandbox/test)
        user.is_premium = True
        user.plan_type = "premium"
        user.subscription_status = "active"
        user.current_period_end = int(time.time()) + 60 * 60 * 24 * 30

        db.commit()

        return {"status": "premium"}

    except Exception as e:
        print("VERIFY ERROR:", str(e))
        return JSONResponse(
            content={"error": "Server error"},
            status_code=500
        )

    finally:
        db.close()

import time

@app.post("/create-post")
def create_post(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return {"error": "Unauthorized"}

        video_id = data.get("video_id")
        media_type = data.get("media_type", "image")

        video_playback_url = data.get("video_playback_url")
        thumbnail_url = data.get("thumbnail_url")

        if media_type == "video" and video_id:
            video_playback_url = video_playback_url or f"https://videodelivery.net/{video_id}/manifest/video.m3u8"
            thumbnail_url = thumbnail_url or f"https://videodelivery.net/{video_id}/thumbnails/thumbnail.jpg"

        post = Post(
            user_id=user.id,
            username=user.name or user.email.split("@")[0],

            image=data.get("image") or thumbnail_url,
            media_type=media_type,
            caption=data["caption"],
            created_at=int(time.time()),

            video_provider=data.get("video_provider"),
            video_id=video_id,
            video_playback_url=video_playback_url,
            thumbnail_url=thumbnail_url
        )

        db.add(post)
        db.commit()

        return {"message": "Post created"}

    finally:
        db.close()

#========
# helper de mémoire feed
#==========

def get_or_create_taste(db, user_id: int):
    taste = db.query(UserTaste).filter(UserTaste.user_id == user_id).first()

    if not taste:
        taste = UserTaste(user_id=user_id)
        db.add(taste)
        db.commit()
        db.refresh(taste)

    return taste


def detect_food_features(post):
    text = (post.caption or "").lower()

    def has_any(words):
        return any(w in text for w in words)

    lang = detect_language(text)

    return {
        "lang_fr": lang == "fr",
        "lang_en": lang == "en",

        "italian": has_any(["italian", "pizza", "pasta", "risotto", "parmesan"]),
        "mexican": has_any(["mexican", "taco", "burrito", "quesadilla", "salsa"]),
        "asian": has_any(["asian", "ramen", "sushi", "thai", "teriyaki", "soy"]),
        "comfort": has_any(["comfort", "cheese", "burger", "fries", "warm", "cozy"]),
        "fresh": has_any(["fresh", "salad", "salade", "lemon", "lime", "healthy"]),
        "sweet": has_any(["sweet", "dessert", "cake", "chocolate", "cookie", "sucré"]),
        "salty": has_any(["salty", "savory", "salé", "chips", "fries"]),
        "homemade": has_any(["homemade", "maison", "fait maison"]),
        "quick": has_any(["quick", "fast", "easy", "rapide", "facile"]),

        "pasta": has_any(["pasta", "spaghetti", "macaroni", "penne", "lasagna"]),
        "burger": has_any(["burger", "cheeseburger"]),
        "healthy": has_any(["healthy", "santé", "salad", "salade", "protein", "protéine"]),
        "dessert": has_any(["dessert", "cake", "gâteau", "cookie", "chocolate", "chocolat"]),
        "breakfast": has_any(["breakfast", "déjeuner", "eggs", "oeufs", "pancake"]),
        "vegan": has_any(["vegan", "végane", "vegetarian", "végétarien"]),
        "spicy": has_any(["spicy", "épicé", "chili", "jalapeno"]),

        "chicken": has_any(["chicken", "poulet"]),
        "beef": has_any(["beef", "boeuf", "bœuf", "steak"]),
        "seafood": has_any(["seafood", "fish", "poisson", "shrimp", "crevette"]),

        "video": post.media_type == "video",
        "image": post.media_type != "video"
    }


def learn_user_taste(db, user_id: int, post, weight: int):
    taste = get_or_create_taste(db, user_id)
    features = detect_food_features(post)

    for key, active in features.items():
        if active and hasattr(taste, key):
            current = getattr(taste, key) or 0
            setattr(taste, key, max(-50, min(100, current + weight)))

    taste.updated_at = int(time.time())
    db.commit()


def calculate_personal_score(post, taste):
    if not taste:
        return 0

    features = detect_food_features(post)
    score = 0

    for key, active in features.items():
        if active and hasattr(taste, key):
            score += (getattr(taste, key) or 0) * 2.5

    return score

def apply_taste_decay(db, taste):
    if not taste:
        return

    now = int(time.time())
    last_update = taste.updated_at or now
    hours_passed = max(0, (now - last_update) / 3600)

    if hours_passed < 1:
        return

    decay_factor = 0.97 ** hours_passed

    protected_fields = {"id", "user_id", "updated_at"}

    for column in taste.__table__.columns:
        key = column.name

        if key in protected_fields:
            continue

        value = getattr(taste, key)

        if isinstance(value, int):
            new_value = int(value * decay_factor)

            if abs(new_value) < 1:
                new_value = 0

            setattr(taste, key, new_value)

    taste.updated_at = now
    db.commit()

@app.get("/feed")
def get_feed(skip: int = 0, limit: int = 10, token: str = ""):
    db = SessionLocal()
    try:
        limit = min(limit, 20)

        current_user_id = None
        if token:
            current_user_id = get_current_user(token)

        #  mémoire utilisateur backend
        taste = None
        if current_user_id:
            taste = get_or_create_taste(db, current_user_id)
        apply_taste_decay(db, taste)

        posts = (
            db.query(Post)
            .filter(Post.is_hidden == False)
            .all()
        )

        scored_posts = []

        for p in posts:
            likes = db.query(Like).filter(Like.post_id == p.id).count()
            comments = db.query(Comment).filter(Comment.post_id == p.id).count()

            base_score = calculate_feed_score(p, likes, comments)
            personal_score = calculate_personal_score(p, taste)
            ml_score = ml_light_score(p, likes, comments, taste)

            creator_boost = 5 if likes < 5 and comments < 3 else 0

            spam_penalty = 0
            if len((p.caption or "").strip()) < 3:
                spam_penalty -= 15

            follow_boost = 0

            if current_user_id:
                is_followed_creator = db.query(Follow).filter(
                    Follow.follower_id == current_user_id,
                    Follow.following_id == p.user_id
                ).first() is not None

                if is_followed_creator:
                    follow_boost = 80

            score = (
                follow_boost +
                base_score +
                personal_score +
                creator_boost +
                spam_penalty +
                ml_score
            )

            scored_posts.append({
                "post": p,
                "likes": likes,
                "comments": comments,
                "score": score,
                "user_id": p.user_id
            })

        scored_posts.sort(key=lambda item: item["score"], reverse=True)

        #  diversité / anti-répétition
        final_posts = dynamic_rerank(scored_posts, skip + limit)

        paginated = final_posts[skip:skip + limit]


        result = []

        for item in paginated:
            p = item["post"]
            likes = item["likes"]
            comments = item["comments"]

            user = db.query(User).filter(User.id == p.user_id).first()

            liked = False
            if current_user_id:
                liked = db.query(Like).filter(
                    Like.user_id == current_user_id,
                    Like.post_id == p.id
                ).first() is not None

            is_following = False

            if current_user_id:
                is_following = db.query(Follow).filter(
                    Follow.follower_id == current_user_id,
                    Follow.following_id == p.user_id
                ).first() is not None
            result.append({
                "id": p.id,
                "user_id": p.user_id,
                "author": p.username,
                "avatar": user.avatar if user and user.avatar else "",
                "image": p.image,
                "media_type": p.media_type or "image",
                "caption": p.caption or "",
                "language": detect_language(p.caption),
                "likes": likes,
                "liked": liked,
                "comments": comments,
                "commentsCount": comments,
                "created_at": p.created_at,
                "score": round(item["score"], 2),
                "is_following": is_following,

    # vidéo scalable
                "video_provider": p.video_provider,
                "video_id": p.video_id,
                "video_playback_url": p.video_playback_url,
                "thumbnail_url": p.thumbnail_url
            })

        #  enregistrer les posts vus AVANT le return
        if current_user_id:
            for item in paginated:
                db.add(PostView(
                    user_id=current_user_id,
                    post_id=item["post"].id,
                    viewed_at=int(time.time())
                ))

            db.commit()

        return result

    finally:
        db.close()


@app.post("/like")
def like_post(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        post_id = data["post_id"]

        existing = db.query(Like).filter(
            Like.user_id == user_id,
            Like.post_id == post_id
        ).first()

        post = db.query(Post).filter(Post.id == post_id).first()

        if existing:
            db.delete(existing)
            if post:
                learn_user_taste(db, user_id, post, -2)
        else:
            db.add(Like(user_id=user_id, post_id=post_id))
            if post:
                learn_user_taste(db, user_id, post, 4)

        db.commit()

        return {"message": "ok"}

    finally:
        db.close()

@app.post("/comment")
def comment_post(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        comment = Comment(
            user_id=user_id,
            post_id=data["post_id"],
            username=user.name or user.email.split("@")[0],
            text=data["text"]
        )

        db.add(comment)
        post = db.query(Post).filter(Post.id == data["post_id"]).first()
        if post:
            learn_user_taste(db, user_id, post, 6)
        
        db.commit()

        return {"message": "comment added"}

    finally:
        db.close()

@app.post("/comments")
def get_comments(data: dict):
    db = SessionLocal()
    try:
        post_id = data["post_id"]

        comments = db.query(Comment).filter(
            Comment.post_id == post_id
        ).all()

        return [
            {
                "author": c.username or "User",
                "text": c.text
            }
            for c in comments
        ]

    finally:
        db.close()                                         

@app.post("/get-profile")
def get_profile(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        return {
            "email": user.email,
            "name": user.name or user.email.split("@")[0],
            "bio": user.bio or "Food lover 🍽️",
            "avatar": user.avatar or "https://via.placeholder.com/180x180.png?text=Profile"
        }

    finally:
        db.close()

@app.post("/save-profile")
def save_profile(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])
        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        user.name = data.get("name", user.name)
        user.bio = data.get("bio", user.bio)
        user.avatar = data.get("avatar", user.avatar)

        db.commit()

        return {"message": "Profile saved"}

    finally:
        db.close()                

@app.post("/report-post")
def report_post(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data["token"])

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        post_id = data["post_id"]
        reason = data.get("reason", "Inappropriate content")

        post = db.query(Post).filter(Post.id == post_id).first()

        if not post:
            return JSONResponse(content={"error": "Post not found"}, status_code=404)

        existing = db.query(Report).filter(
            Report.user_id == user_id,
            Report.post_id == post_id
        ).first()

        if existing:
            return {"message": "Already reported"}

        report = Report(
            user_id=user_id,
            post_id=post_id,
            reason=reason,
            created_at=int(time.time())
        )

        db.add(report)

        report_count = db.query(Report).filter(Report.post_id == post_id).count()

        if report_count >= 3:
            post.is_hidden = True

        db.commit()

        return {"message": "Post reported"}

    finally:
        db.close()        

@app.post("/seed-feed")
def seed_feed():
    db = SessionLocal()
    try:
        existing_posts = db.query(Post).count()

        if existing_posts > 0:
            return {"message": "Feed already has posts"}

        demo_posts = [
            {
                "username": "MealSwipe Picks",
                "image": "https://www.themealdb.com/images/media/meals/1525873040.jpg",
                "caption": "Homemade pasta inspiration 🍝 What would you add to this plate?",
                "media_type": "image"
            },
            {
                "username": "Chef Bot",
                "image": "https://www.themealdb.com/images/media/meals/llcbn01574260722.jpg",
                "caption": "Clean salmon bowl idea 🥗 Fresh, simple and full of color.",
                "media_type": "image"
            },
            {
                "username": "Daily Food Idea",
                "image": "https://www.themealdb.com/images/media/meals/ustsqw1468250014.jpg",
                "caption": "Burger night inspiration 🍔 Would you swipe yes?",
                "media_type": "image"
            },
            {
                "username": "MealSwipe Picks",
                "image": "https://www.themealdb.com/images/media/meals/xr0n4r1576788363.jpg",
                "caption": "Comfort food pick of the day 🔥 Simple, warm and satisfying.",
                "media_type": "image"
            },
            {
                "username": "Food Inspiration",
                "image": "https://www.themealdb.com/images/media/meals/syqypv1486981727.jpg",
                "caption": "Dinner idea for tonight 🍽️ Save it if it gives you cravings.",
                "media_type": "image"
            }
        ]

        seed_user = db.query(User).filter(User.email == "seed@mealswipe.app").first()

        if not seed_user:
            seed_user = User(
                email="seed@mealswipe.app",
                password="seed_account_not_for_login",
                name="MealSwipe Picks",
                bio="Curated food inspiration from MealSwipe.",
                avatar="https://via.placeholder.com/180x180.png?text=MS",
                is_premium=True
            )
            db.add(seed_user)
            db.commit()
            db.refresh(seed_user)

        for item in demo_posts:
            post = Post(
                user_id=seed_user.id,
                username=item["username"],
                image=item["image"],
                media_type=item["media_type"],
                caption=item["caption"],
                is_hidden=False,
                created_at=int(time.time())
            )
            db.add(post)

        db.commit()

        return {"message": "Seed posts created"}

    finally:
        db.close()  

@app.post("/internal-meals")
def get_internal_meals(filters: dict):
    filters = filters or {}
    results = []

    for meal in INTERNAL_MEALS:
        if filters.get("vegan") and not meal["vegan"]:
            continue
        if filters.get("gluten") and meal["gluten"]:
            continue
        if filters.get("arachide") and meal["arachide"]:
            continue

        results.append(meal)

    random.shuffle(results)
    return results[:10]    

@app.post("/delete-post")
def delete_post(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data.get("token"))

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        post_id = data.get("post_id")

        post = db.query(Post).filter(Post.id == post_id).first()

        if not post:
            return JSONResponse(content={"error": "Post not found"}, status_code=404)

        if post.user_id != user_id:
            return JSONResponse(content={"error": "Forbidden"}, status_code=403)

        db.query(Like).filter(Like.post_id == post_id).delete()
        db.query(Comment).filter(Comment.post_id == post_id).delete()
        db.query(Report).filter(Report.post_id == post_id).delete()
        db.query(PostView).filter(PostView.post_id == post_id).delete()

        db.delete(post)
        db.commit()

        return {"message": "Post deleted"}

    except Exception as e:
        db.rollback()
        print("DELETE POST ERROR:", str(e))
        return JSONResponse(content={"error": str(e)}, status_code=500)

    finally:
        db.close()

@app.get("/user-profile")
def get_user_profile(user_id: int, token: str = ""):
    db = SessionLocal()
    try:
        current_user_id = get_current_user(token) if token else None

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        posts = (
            db.query(Post)
            .filter(Post.user_id == user_id, Post.is_hidden == False)
            .order_by(Post.created_at.desc())
            .all()
        )

        followers_count = db.query(Follow).filter(Follow.following_id == user_id).count()

        is_following = False
        if current_user_id:
            is_following = db.query(Follow).filter(
                Follow.follower_id == current_user_id,
                Follow.following_id == user_id
            ).first() is not None

        return {
            "id": user.id,
            "username": user.name or user.email.split("@")[0],
            "avatar": user.avatar or "https://via.placeholder.com/180x180.png?text=Profile",
            "bio": user.bio or "Food lover 🍽️",
            "followers": followers_count,
            "is_following": is_following,
            "is_me": current_user_id == user_id,
            "posts": [
                {
                    "id": p.id,
                    "image": p.image,
                    "media_type": p.media_type or "image",
                    "caption": p.caption or "",

                    "video_provider": p.video_provider,
                    "video_id": p.video_id,
                    "video_playback_url": p.video_playback_url,
                    "thumbnail_url": p.thumbnail_url
                }
                for p in posts
            ]
        }

    finally:
        db.close()

@app.post("/follow")
def follow_user(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data.get("token"))
        target_id = data.get("user_id")

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        if user_id == target_id:
            return JSONResponse(content={"error": "You cannot follow yourself"}, status_code=400)

        target = db.query(User).filter(User.id == target_id).first()
        if not target:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        existing = db.query(Follow).filter(
            Follow.follower_id == user_id,
            Follow.following_id == target_id
        ).first()

        if existing:
            db.delete(existing)
            db.commit()

            followers_count = db.query(Follow).filter(Follow.following_id == target_id).count()

            return {
                "following": False,
                "followers": followers_count
            }

        new_follow = Follow(
            follower_id=user_id,
            following_id=target_id,
            created_at=int(time.time())
        )

        db.add(new_follow)
        db.commit()

        followers_count = db.query(Follow).filter(Follow.following_id == target_id).count()

        return {
            "following": True,
            "followers": followers_count
        }

    finally:
        db.close() 

@app.post("/create-video-upload")
def create_video_upload(data: dict):
    try:
        token = data.get("token")
        user_id = get_current_user(token)

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID")
        api_token = os.getenv("CLOUDFLARE_STREAM_TOKEN")

        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/stream/direct_upload"

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }

        body = {
            "maxDurationSeconds": 300  # 🔥 limite 3 minutes
        }

        response = requests.post(url, headers=headers, json=body)
        data = response.json()

        if not data.get("success"):
            print("CLOUDFLARE ERROR:", data)
            return JSONResponse(
                content={
                    "error": "Cloudflare error",
                    "details": data
                },
                status_code=500
            )

        result = data["result"]

        return {
            "upload_url": result["uploadURL"],
            "video_id": result["uid"]
        }

    except Exception as e:
        return JSONResponse(content={"error": str(e)}, status_code=500)                       
    
@app.get("/search-users")
def search_users(q: str = "", token: str = ""):
    db = SessionLocal()
    try:
        query = q.strip().lower()

        if len(query) < 2:
            return []

        current_user_id = get_current_user(token) if token else None

        users = (
            db.query(User)
            .filter(User.name.ilike(f"%{query}%"))
            .limit(10)
            .all()
        )

        result = []

        for user in users:
            followers_count = db.query(Follow).filter(
                Follow.following_id == user.id
            ).count()

            is_following = False
            if current_user_id:
                is_following = db.query(Follow).filter(
                    Follow.follower_id == current_user_id,
                    Follow.following_id == user.id
                ).first() is not None

            result.append({
                "id": user.id,
                "username": user.name or user.email.split("@")[0],
                "avatar": user.avatar or "https://via.placeholder.com/180x180.png?text=User",
                "followers": followers_count,
                "is_following": is_following
            })

        return result

    finally:
        db.close()

@app.post("/debug-reset-premium")
def debug_reset_premium(data: dict):
    db = SessionLocal()
    try:
        user_id = get_current_user(data.get("token"))

        if not user_id:
            return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

        user = db.query(User).filter(User.id == user_id).first()

        if not user:
            return JSONResponse(content={"error": "User not found"}, status_code=404)

        user.is_premium = False
        user.plan_type = "free"
        user.subscription_status = None
        user.current_period_end = None

        db.commit()

        return {"message": "Premium reset"}
    finally:
        db.close()        