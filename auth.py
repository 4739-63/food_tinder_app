from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext

# 🔐 CONFIG JWT
SECRET_KEY = "supersecretkey_change_me"
ALGORITHM = "HS256"

# 🔐 HASH PASSWORD
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str):
    return pwd_context.hash(password)

# 🔐 CREATE TOKEN
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)