import os
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

SERVICE_NAME = "images"
SERVICE_PORT = 8001
SERVICE_HOST = "localhost"
SERVICE_URL = f"http://{SERVICE_HOST}:{SERVICE_PORT}"
REGISTRY_URL = os.getenv("REGISTRY_URL", "http://localhost:8100")

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with httpx.AsyncClient() as client:
        try:
            await client.post(f"{REGISTRY_URL}/register", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"{SERVICE_NAME} registrado")
        except:
            print("Falha no registro")
    yield
    async with httpx.AsyncClient() as client:
        try:
            await client.delete(f"{REGISTRY_URL}/deregister", json={"name": SERVICE_NAME, "url": SERVICE_URL})
            print(f"{SERVICE_NAME} desregistrado")
        except:
            print("Falha ao desregistrar")

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

fake_image_db = {
    "1": {"id": "1", "url": "http://example.com/image1.jpg", "description": "Image 1"},
    "2": {"id": "2", "url": "http://example.com/image2.jpg", "description": "Image 2"},
}

@app.get("/")
async def get_images():
    return list(fake_image_db.values())

@app.get("/health")
async def health_check():
    return {"status": "ok"}
