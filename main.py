import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from pydantic import BaseModel
from typing import Optional, List, Dict
import datetime
import json

from sqlalchemy.testing import db
from starlette.middleware.cors import CORSMiddleware

# Configuración de la base de datos
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://root:0000@localhost/dbConejoRuts"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo de base de datos para usuarios
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(255), index=True)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))

# Modelo de base de datos para rutas
class Route(Base):
    __tablename__ = "routes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), index=True)
    path = Column(String(1000))  # Especifica la longitud adecuada para VARCHAR en MySQL

# Crear tablas en la base de datos si no existen
Base.metadata.create_all(bind=engine)

# Contexto de encriptación de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key para JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Modelos Pydantic
class UserCreate(BaseModel):
    full_name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    full_name: str  # Agregamos el nombre completo al token

class TokenData(BaseModel):
    email: Optional[str] = None

class RouteBase(BaseModel):
    title: str
    path: List[Dict[str, float]]  # Asegúrate de que path sea una lista de objetos JSON válidos

class RouteCreate(RouteBase):
    pass

class RouteDB(BaseModel):
    id: int
    title: str
    path: List[Dict[str, float]]

    class Config:
        orm_mode = True

# Dependencia de base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Funciones auxiliares
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_route_by_name(db: Session, title: str):
    return db.query(Route).filter(Route.title == title).first()

def delete_route_by_name(db: Session, title: str):
    route = get_route_by_name(db, title)
    if not route:
        raise HTTPException(status_code=404, detail="Route not found")
    db.delete(route)
    db.commit()
    return route

# Crear la aplicación FastAPI
app = FastAPI()

# Configuración del esquema OAuth2 para autenticación
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Rutas de la API para usuarios
@app.post("/register", response_model=Token)
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(full_name=user.full_name, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": new_user.email, "full_name": new_user.full_name}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "full_name": new_user.full_name}

@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, user.email)
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    access_token_expires = datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.email, "full_name": db_user.full_name}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "full_name": db_user.full_name}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        full_name: str = payload.get("full_name")  # Obtener el nombre completo del payload JWT
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

@app.get("/routes", response_model=List[RouteDB])
def read_routes(db: Session = Depends(get_db)):
    routes = db.query(Route).all()
    return routes

@app.post("/routes", response_model=RouteDB)
def create_route(route: RouteCreate, db: Session = Depends(get_db)):
    path_json = json.dumps(route.path)  # Convertir path a JSON
    db_route = Route(title=route.title, path=path_json)
    db.add(db_route)
    db.commit()
    db.refresh(db_route)

    # Convertir path de nuevo a lista de objetos JSON
    db_route.path = json.loads(db_route.path)

    return db_route  # Devolver correctamente RouteDB con la lista de path


@app.delete("/routes/{route_title}")
def delete_route(route_title: str, db: Session = Depends(get_db)):
    try:
        db_route = db.query(Route).filter(Route.title == route_title).first()
        if db_route is None:
            raise HTTPException(status_code=404, detail="Route not found")

        db.delete(db_route)
        db.commit()
        return {"message": "Route deleted successfully"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/route-names", response_model=List[str])
def get_route_names(db: Session = Depends(get_db)):
    routes = db.query(Route.title).all()
    route_names = [route.title for route in routes]
    return route_names

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Aquí podrías especificar el origen de tu aplicación React Native
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
