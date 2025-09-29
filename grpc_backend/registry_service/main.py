import asyncio
from collections import defaultdict
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, HttpUrl

# --- Modelos de Dados ---
class ServiceInstance(BaseModel):
    name: str
    url: str

# --- Banco de Dados em Memória ---
# Usamos um defaultdict para facilitar a adição de instâncias
services_db = defaultdict(list)
HEALTH_CHECK_INTERVAL = 15  # segundos

# --- Lógica de Health Check ---
async def health_check_task():
    """Tarefa em background que verifica a saúde dos serviços registrados."""
    while True:
        # Criamos uma cópia para poder modificar o dicionário original durante a iteração
        services_to_check = list(services_db.items())
        
        for service_name, instances in services_to_check:
            updated_instances = []
            for instance in instances:
                try:
                    async with httpx.AsyncClient(timeout=3) as client:
                        # Cada microserviço precisará de um endpoint /health
                        response = await client.get(f"{instance['url']}/health")
                        if response.status_code == 200:
                            updated_instances.append(instance)
                        else:
                            print(f"Health check falhou para {service_name} em {instance['url']}: Status {response.status_code}")
                except httpx.RequestError:
                    print(f"Health check falhou para {service_name} em {instance['url']}: Serviço inacessível.")
            
            if updated_instances:
                services_db[service_name] = updated_instances
            else:
                # Remove o serviço se nenhuma instância estiver saudável
                del services_db[service_name]
                print(f"Removendo serviço '{service_name}' pois nenhuma instância está saudável.")

        await asyncio.sleep(HEALTH_CHECK_INTERVAL)

# --- Ciclo de Vida da Aplicação (Lifespan) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Inicia a tarefa de health check em background quando a aplicação começa
    task = asyncio.create_task(health_check_task())
    print("Service Registry iniciado com health check.")
    yield
    # Cancela a tarefa quando a aplicação desliga
    task.cancel()
    await task
    print("Service Registry desligado.")

# --- Aplicação FastAPI ---
app = FastAPI(title="Service Registry", lifespan=lifespan)

@app.post("/register")
async def register_service(instance: ServiceInstance):
    """Registra uma nova instância de um serviço."""
    service_list = services_db[instance.name]
    
    # Evita registrar a mesma URL duas vezes
    if any(s['url'] == str(instance.url) for s in service_list):
        return {"message": "Instância já registrada."}
        
    service_list.append(instance.model_dump())
    print(f"Serviço '{instance.name}' registrado em {instance.url}")
    return {"message": f"Serviço '{instance.name}' registrado com sucesso."}

@app.get("/services/{service_name}")
async def find_service(service_name: str):
    """Encontra todas as instâncias de um serviço específico."""
    instances = services_db.get(service_name)
    if not instances:
        raise HTTPException(status_code=404, detail="Serviço não encontrado.")
    return instances

@app.delete("/deregister")
async def deregister_service(instance: ServiceInstance):
    """Remove uma instância de serviço (desligamento gracioso)."""
    service_list = services_db.get(instance.name, [])
    
    initial_len = len(service_list)
    services_db[instance.name] = [s for s in service_list if s['url'] != str(instance.url)]
    
    if len(services_db[instance.name]) < initial_len:
        print(f"Serviço '{instance.name}' desregistrado de {instance.url}")
        if not services_db[instance.name]:
            del services_db[instance.name] # Limpa a chave se não houver mais instâncias
        return {"message": "Instância desregistrada com sucesso."}
    else:
        raise HTTPException(status_code=404, detail="Instância não encontrada para desregistrar.")