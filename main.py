from fastapi import FastAPI, HTTPException, Depends, status, Response
from authx import AuthX, AuthXConfig
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./test.db"
engine = create_async_engine(SQLALCHEMY_DATABASE_URL)
async_session = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# User Model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


# Auth configuration
config = AuthXConfig()
config.JWT_SECRET_KEY = "SECRET_KEY"
config.JWT_ACCESS_CSRF_COOKIE_NAME = "access_token"
config.JWT_TOKEN_LOCATION = ["cookies"]
security = AuthX(config=config)

app = FastAPI()


# Database dependency
async def get_db():
    async with async_session() as session:
        yield session


# Pydantic models
class UserCreate(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


# Database initialization
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# Registration endpoint
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    existing_user = await db.execute(
        User.__table__.select().where(User.username == user.username)
    )
    if existing_user.scalar():
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password)
    new_user = User(username=user.username, hashed_password=hashed_password)
    db.add(new_user)
    await db.commit()
    return {"message": "User created successfully"}


# Login endpoint
@app.post("/login")
async def login(
        response: Response,
        user_data: UserLogin,
        db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        User.__table__.select().where(User.username == user_data.username)
    )
    user = result.scalar()

    if not user or not pwd_context.verify(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = security.create_access_token(uid=str(user.id))
    security.set_access_cookie(response, access_token)
    return {"message": "Login successful"}


# Protected endpoint
@app.get("/protected")
async def protected(
        user_id: str = Depends(security.access_token_required)
):
    return {"message": "Secret data", "user_id": user_id}


# Logout endpoint
@app.post("/logout")
async def logout(response: Response):
    security.unset_jwt_cookies(response)
    return {"message": "Successfully logged out"}