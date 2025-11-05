# 🛍️ Price Collector API — MVP (FastAPI)

API simples para coleta de preços via scraping e estimativa de valor de mercado.

## ⚙️ Como rodar localmente

1. Clonar o repositório e entrar na pasta:
   ```bash
   git clone <teu-repo>
   cd price_collector_app
   ```

2. Criar e ativar ambiente virtual:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   .venv\Scripts\activate     # Windows
   ```

3. Instalar dependências:
   ```bash
   pip install -r requirements.txt
   ```

4. Rodar o servidor:
   ```bash
   uvicorn mvp_price_collector_fastapi:app --reload
   ```

A aplicação ficará disponível em: **http://localhost:8000**

---

## 🐳 Rodar com Docker

```bash
docker build -t price-collector .
docker run -d -p 8000:8000 price-collector
```

---

## 🔍 Endpoints principais

| Método | Endpoint | Descrição |
|--------|-----------|-----------|
| `POST` | `/auth/login` | Obter token JWT (body: {"username":"...","password":"..."}) |
| `POST` | `/scrape` | Coleta preço e dados de contato de um URL (requer Authorization) |
| `GET`  | `/products` | Lista produtos cadastrados (requer Authorization) |
| `GET`  | `/products/{id}/offers` | Ofertas registradas de um produto (requer Authorization) |
| `GET`  | `/products/{id}/estimate` | Estimativa de valor de mercado (requer Authorization) |
| `GET`  | `/products/{id}/best_contact` | Retorna contato do melhor preço (requer Authorization) |
| `GET`  | `/health` | Teste de disponibilidade (público) |

---

## 🔑 Como autenticar

1. Definir variáveis de ambiente (ou usar `.env.example`):
   ```env
   JWT_SECRET_KEY=uma_chave_muito_segura_123456789
   APP_DEFAULT_USER=admin
   APP_DEFAULT_PASS=1234
   ```

2. Obter token:
   ```bash
   curl -X POST "http://localhost:8000/auth/login" -H "Content-Type: application/json" -d '{"username":"admin","password":"1234"}'
   ```

3. Copiar token e usar em `Authorize` no Swagger ou no header:
   ```bash
   Authorization: Bearer <token>
   ```

---

Criado por [GPT Online](https://gptonline.ai/)
