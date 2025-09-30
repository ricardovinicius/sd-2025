import grpc
import asyncio
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.responses import JSONResponse
import auth_service.auth_pb2 as auth_pb2
import auth_service.auth_pb2_grpc as auth_grpc
import images_service.images_pb2 as img_pb2
import images_service.images_pb2_grpc as img_grpc

app = FastAPI()

async def verify_token(token: str):
    async with grpc.aio.insecure_channel("localhost:50052") as channel:
        stub = auth_grpc.AuthServiceStub(channel)
        jwks = await stub.GetJWKS(auth_pb2.Empty())
        # validar token JWT aqui usando jwks.keys_json
        return True  # placeholder

@app.get("/images")
async def get_images(token: str = Depends(verify_token)):
    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = img_grpc.ImagesServiceStub(channel)
        response = await stub.GetImages(img_pb2.Empty())
        return [dict(id=i.id, url=i.url, description=i.description) for i in response.images]

@app.get("/health")
async def health_check():
    return {"status": "ok"}
