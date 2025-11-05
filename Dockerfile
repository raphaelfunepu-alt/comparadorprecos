# Imagem base leve do Python
FROM python:3.11-slim

# Diretório de trabalho
WORKDIR /app

# Copiar dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY mvp_price_collector_fastapi.py .

# Expor porta padrão do FastAPI/Uvicorn
EXPOSE 8000

# Comando de inicialização
CMD ["uvicorn", "mvp_price_collector_fastapi:app", "--host", "0.0.0.0", "--port", "8000"]
