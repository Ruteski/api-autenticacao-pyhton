# # Obter token
# curl -X POST "http://localhost:8000/token" -F "username=user" -F "password=L0XuwPOdS5U"

# # Acessar rotas protegidas
# curl -H "Authorization: Bearer <seu_token>" http://localhost:8000/user
# curl -H "Authorization: Bearer <seu_token>" http://localhost:8000/admin

# # Listar usuários (apenas admin)
# curl -H "Authorization: Bearer <seu_token>" http://localhost:8000/users

# # Criar novo usuário (requer token de admin)
# curl -X POST "http://localhost:8000/users" \
#   -H "Authorization: Bearer <token_admin>" \
#   -H "Content-Type: application/x-www-form-urlencoded" \
#   -d "username=ruteski&password=newpass123&role=user"

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from typing import Optional
import sqlite3
from contextlib import contextmanager

# Configurações do JWT
SECRET_KEY = "minha_chave_secreta_muito_segura"  # Em produção, usar uma chave segura de verdade
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Criar aplicação FastAPI
app = FastAPI()

# Configuração do OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuração do banco de dados
DATABASE_NAME = "banco.db"

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def get_password_hash(password: str) -> str:
    return pbkdf2_sha256.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pbkdf2_sha256.verify(plain_password, hashed_password)

def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)
        
        # Inserir usuários iniciais com senhas hasheadas
        try:
            conn.execute("""
                INSERT INTO users (username, password, role)
                VALUES 
                    (?, ?, ?),
                    (?, ?, ?)
            """, (
                'user', get_password_hash('L0XuwPOdS5U'), 'user',
                'admin', get_password_hash('JKSipm0YH'), 'admin'
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            # Usuários já existem
            pass

# Inicializar o banco de dados
init_db()

def get_user(username: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        user = cursor.execute(
            "SELECT username, password, role FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        
        if user:
            return {
                "username": user["username"],
                "password": user["password"],
                "role": user["role"]
            }
    return None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: dict = Depends(get_current_user)):
    return current_user

# Rotas da API
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user["role"]}, 
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/user")
async def read_user_route(current_user: dict = Depends(get_current_active_user)):
    if current_user["role"] not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return {"message": "Hello User!", "user": current_user["username"], "role": current_user["role"]}

@app.get("/admin")
async def read_admin_route(current_user: dict = Depends(get_current_active_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return {"message": "Hello Admin!", "user": current_user["username"], "role": current_user["role"]}

# Rota para listar todos os usuários (apenas para admin)
@app.get("/users")
async def list_users(current_user: dict = Depends(get_current_active_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        users = cursor.execute("SELECT username, role FROM users").fetchall()
        return {"users": [dict(user) for user in users]}

# Rota para criar novo usuário (apenas para admin)
@app.post("/users")
async def create_user(
    username: str,
    password: str,
    role: str,
    current_user: dict = Depends(get_current_active_user)
):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    
    if role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role"
        )
    
    try:
        with get_db_connection() as conn:
            hashed_password = get_password_hash(password)
            conn.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    return {"message": "User created successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)