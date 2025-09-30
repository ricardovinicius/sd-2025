import threading
import uvicorn
import asyncio

# Importa os servidores gRPC
from auth_service import server_grpc as auth_grpc
from images_service import server_grpc as images_grpc

# Importa os servidores HTTP FastAPI
from auth_service import server_http as auth_http
from images_service import server_http as images_http
from api_gateway import gateway

# Funções para rodar cada serviço HTTP em uma thread
def run_http_app(app, host, port):
    uvicorn.run(app, host=host, port=port, log_level="info")

# Funções para rodar gRPC em thread separada
def run_grpc_server(server_func):
    server_func()  # server_func já chama server.start() e wait_for_termination()

if __name__ == "__main__":
    # Threads para HTTP FastAPI
    threads = []
    threads.append(threading.Thread(target=run_http_app, args=(auth_http.app, "0.0.0.0", 8003)))
    threads.append(threading.Thread(target=run_http_app, args=(images_http.app, "0.0.0.0", 8001)))
    threads.append(threading.Thread(target=run_http_app, args=(gateway.app, "0.0.0.0", 8000)))

    # Threads para gRPC
    threads.append(threading.Thread(target=run_grpc_server, args=(auth_grpc.serve,)))
    threads.append(threading.Thread(target=run_grpc_server, args=(images_grpc.serve,)))

    # Inicia todas as threads
    for t in threads:
        t.start()

    # Aguarda todas as threads (na prática, ficará rodando infinitamente)
    for t in threads:
        t.join()
