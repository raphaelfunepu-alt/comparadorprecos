"""
MVP: Aplicativo FastAPI para coleta de preços (exemplo funcional) com autenticação JWT
Como usar (local):
1) criar e ativar venv: python -m venv .venv && source .venv/bin/activate
2) instalar dependências: pip install -r requirements.txt
3) rodar: uvicorn mvp_price_collector_fastapi:app --reload
"""
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timedelta
import os, requests, re, statistics, json
from bs4 import BeautifulSoup
from jose import JWTError, jwt
from passlib.context import CryptContext

# Database (SQLite via simple file + in-memory structures using tiny SQLAlchemy)
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

# --- Config ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./prices.db")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change_this_secret_in_prod")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
APP_DEFAULT_USER = os.getenv("APP_DEFAULT_USER", "admin")
APP_DEFAULT_PASS = os.getenv("APP_DEFAULT_PASS", "1234")  # keep safe in prod

# --- DB Setup ---
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Product(Base):
    __tablename__ = "products"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    sku = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    offers = relationship("Offer", back_populates="product")

class Offer(Base):
    __tablename__ = "offers"
    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("products.id"))
    source = Column(String)
    price = Column(Float)
    currency = Column(String(8), default="BRL")
    url = Column(Text)
    phone = Column(String, nullable=True)
    email = Column(String, nullable=True)
    availability = Column(Boolean, default=True)
    scraped_at = Column(DateTime, default=datetime.utcnow)
    product = relationship("Product", back_populates="offers")

Base.metadata.create_all(bind=engine)

# --- Pydantic schemas ---
class ScrapeRequest(BaseModel):
    url: str
    product_title: Optional[str] = None
    source_name: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class OfferOut(BaseModel):
    id: int
    source: Optional[str]
    price: float
    currency: str
    url: str
    phone: Optional[str]
    email: Optional[str]
    availability: bool
    scraped_at: datetime
    class Config:
        orm_mode = True

class ProductOut(BaseModel):
    id: int
    title: str
    sku: Optional[str]
    created_at: datetime
    class Config:
        orm_mode = True

# --- Utilities: simple scraping ---
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PriceBot/1.0)"}
PRICE_RE = re.compile(r"\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})")
PHONE_RE = re.compile(r"\+?\d[\d\-\s()]{6,}\d")
EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+")

def parse_price_text(text: str) -> Optional[float]:
    if not text:
        return None
    m = PRICE_RE.search(text.replace('\xa0', ' '))
    if not m:
        return None
    raw = m.group(0).replace('.', '').replace(',', '.')
    try:
        return float(raw)
    except:
        return None

def simple_scrape(url: str) -> dict:
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
    except Exception as e:
        return {"error": str(e)}
    soup = BeautifulSoup(r.text, "html.parser")
    price = None
    script = soup.find('script', type='application/ld+json')
    if script:
        try:
            payload = json.loads(script.string)
            if isinstance(payload, dict) and 'offers' in payload and 'price' in payload['offers']:
                price = float(payload['offers']['price'])
        except:
            pass
    if price is None:
        price = parse_price_text(' '.join(list(soup.stripped_strings)[:400]))
    phone = PHONE_RE.search(r.text)
    email = EMAIL_RE.search(r.text)
    return {
        'price': price,
        'currency': 'BRL',
        'phone': phone.group(0) if phone else None,
        'email': email.group(0) if email else None,
        'error': None
    }

def estimate_market_price(prices: List[float]) -> Optional[float]:
    clean = [p for p in prices if p]
    if not clean:
        return None
    if len(clean) < 3:
        return statistics.median(clean)
    q1, q3 = statistics.quantiles(clean, n=4)[0], statistics.quantiles(clean, n=4)[2]
    iqr = q3 - q1
    filtered = [p for p in clean if q1 - 1.5*iqr <= p <= q3 + 1.5*iqr]
    return statistics.median(filtered or clean)

# --- Auth (JWT) ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# For MVP we store one default user (username + hashed password) in memory
_default_user = {"username": APP_DEFAULT_USER, "hashed_password": get_password_hash(APP_DEFAULT_PASS)}

def authenticate_user(username: str, password: str):
    if username != _default_user["username"]:
        return False
    if not verify_password(password, _default_user["hashed_password"]):
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(lambda: None), authorization: Optional[str] = None):
    # Custom dependency to extract Authorization header manually (FastAPI normally uses Security)
    from fastapi import Request
    def _inner(request: Request):
        auth = request.headers.get("Authorization")
        if not auth or not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Not authenticated")
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            username: str = payload.get("sub")
            if username is None or username != APP_DEFAULT_USER:
                raise HTTPException(status_code=401, detail="Invalid token payload")
        except JWTError:
            raise HTTPException(status_code=401, detail="Token invalid or expired")
        return {"username": username}
    return _inner

# --- FastAPI app ---
app = FastAPI(
    title="💰 Price Collector API",
    description="API para coleta de preços e cálculo de valor de mercado.\\n\\nDesenvolvido por GPT Online",
    version="1.0.0",
    contact={
        "name": "GPT Online",
        "url": "https://gptonline.ai/",
        "email": "contato@gptonline.ai"
    }
)

@app.get("/", response_class=HTMLResponse)
def root():
    html = """
    <html>
    <head><title>Price Collector API</title></head>
    <body style='font-family:Arial;text-align:center;padding:40px;'>
    <h1>💰 Price Collector API</h1>
    <p>Bem-vindo! Aceda à <a href='/custom-docs'>documentação Swagger</a> para testar os endpoints.</p>
    <p>Desenvolvido por <a href='https://gptonline.ai/'>GPT Online</a> 🇵🇹</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/custom-docs", include_in_schema=False)
def custom_docs():
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title="💰 Price Collector — Documentação",
        swagger_favicon_url="https://gptonline.ai/favicon.ico"
    )

@app.post("/auth/login", response_model=Token)
def login(form_data: dict):
    username = form_data.get("username")
    password = form_data.get("password")
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")
    user_ok = authenticate_user(username, password)
    if not user_ok:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/scrape", status_code=201)
def scrape_and_store(req: ScrapeRequest, current_user: dict = Depends(get_current_user())):
    db = SessionLocal()
    product = Product(title=req.product_title or req.url)
    db.add(product); db.commit(); db.refresh(product)
    result = simple_scrape(req.url)
    if result.get('error'):
        db.close(); raise HTTPException(status_code=400, detail=result['error'])
    offer = Offer(
        product_id=product.id,
        source=req.source_name or req.url,
        price=result.get('price', 0.0),
        currency=result.get('currency', 'BRL'),
        url=req.url,
        phone=result.get('phone'),
        email=result.get('email'),
        availability=result.get('price') is not None,
        scraped_at=datetime.utcnow()
    )
    db.add(offer); db.commit(); db.refresh(offer); db.close()
    return {"product_id": product.id, "offer_id": offer.id}

@app.get("/products", response_model=List[ProductOut])
def list_products(q: Optional[str] = None, current_user: dict = Depends(get_current_user())):
    db = SessionLocal()
    query = db.query(Product)
    if q: query = query.filter(Product.title.ilike(f"%{q}%"))
    items = query.order_by(Product.created_at.desc()).limit(50).all()
    db.close()
    return items

@app.get("/products/{product_id}/offers", response_model=List[OfferOut])
def get_offers(product_id: int, current_user: dict = Depends(get_current_user())):
    db = SessionLocal()
    offers = db.query(Offer).filter(Offer.product_id == product_id).order_by(Offer.scraped_at.desc()).all()
    db.close()
    if not offers: raise HTTPException(404, "Produto não encontrado")
    return offers

@app.get("/products/{product_id}/estimate")
def get_estimate(product_id: int, current_user: dict = Depends(get_current_user())):
    db = SessionLocal()
    offers = db.query(Offer).filter(Offer.product_id == product_id, Offer.availability == True).all()
    db.close()
    prices = [o.price for o in offers if o.price and o.price > 0]
    estimate = estimate_market_price(prices)
    return {"product_id": product_id, "market_estimate": estimate, "sample_size": len(prices)}

@app.get("/products/{product_id}/best_contact")
def get_best_contact(product_id: int, current_user: dict = Depends(get_current_user())):
    db = SessionLocal()
    offer = db.query(Offer).filter(Offer.product_id == product_id, Offer.availability == True).order_by(Offer.price.asc()).first()
    db.close()
    if not offer: raise HTTPException(404, "Nenhuma oferta válida encontrada")
    return {"offer_id": offer.id, "price": offer.price, "phone": offer.phone, "email": offer.email, "url": offer.url}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow()}
