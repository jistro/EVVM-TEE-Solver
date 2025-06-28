from dotenv import load_dotenv
import base64
import json

load_dotenv()

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from dstack_sdk import AsyncTappdClient
from dstack_sdk.ethereum import to_account_secure
from dstack_sdk.solana import to_keypair_secure
from banks_database import banks_database

app = FastAPI()

# Variables globales para almacenar las llaves RSA
private_key = None
public_key_pem = None
keys_initialized = False

def generate_rsa_keys():
    """Genera un par de llaves RSA y las almacena globalmente"""
    global private_key, public_key_pem, keys_initialized

    if keys_initialized:
        raise Exception("Las llaves RSA ya han sido inicializadas y no se pueden regenerar")

    try:
        # Generar llave privada RSA de 2048 bits
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Obtener la llave pública desde la llave privada
        public_key = private_key.public_key()

        # Serializar la llave pública en formato PEM
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Convertir a string
        public_key_pem = public_key_bytes.decode('utf-8')

        keys_initialized = True
        print(f"🔧 Debug: Llave pública generada, longitud: {len(public_key_pem)}")
        return True

    except Exception as e:
        print(f"Error detallado en generate_rsa_keys: {str(e)}")
        print(f"Tipo de private_key: {type(private_key) if private_key else 'None'}")
        if 'public_key' in locals():
            print(f"Tipo de public_key: {type(public_key)}")
            print(f"Métodos disponibles en public_key: {[m for m in dir(public_key) if 'public' in m.lower()]}")
        raise e

# Inicializar las llaves RSA automáticamente al arrancar el programa
try:
    generate_rsa_keys()
    print("✅ Llaves RSA generadas exitosamente al inicializar el programa")
    print(f"🔑 Estado: initialized={keys_initialized}, has_public_key={public_key_pem is not None}, has_private_key={private_key is not None}")
except Exception as e:
    print(f"❌ Error al generar las llaves RSA: {str(e)}")
    print(f"🔍 Estado de debug: initialized={keys_initialized}, public_key_pem={public_key_pem is not None}, private_key={private_key is not None}")

def decrypt_message(encoded_encrypted_msg):
    """Desencripta un mensaje usando la llave privada RSA"""
    global private_key
    
    if private_key is None:
        raise Exception("No se han generado las llaves RSA. Llama primero a /initialize_keys")
    
    try:
        # Decodificar el mensaje de base64
        decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
        
        # Desencriptar usando la llave privada
        decoded_decrypted_msg = private_key.decrypt(
            decoded_encrypted_msg,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decoded_decrypted_msg.decode('utf-8')
    except Exception as e:
        raise Exception(f"Error al desencriptar el mensaje: {str(e)}")

@app.get("/")
async def get_info():
    client = AsyncTappdClient()
    info = await client.info()
    return JSONResponse(content=info.model_dump())

@app.get("/initialize_keys")
async def initialize_keys():
    """Muestra el estado de inicialización de las llaves RSA"""
    global keys_initialized
    
    if keys_initialized:
        return {
            "message": "Las llaves RSA ya están inicializadas y activas", 
            "status": "success",
            "initialized": True
        }
    else:
        return {
            "message": "Error: Las llaves RSA no pudieron ser inicializadas al arrancar el programa", 
            "status": "error",
            "initialized": False
        }

@app.get("/keys_status")
async def keys_status():
    """Verifica el estado de las llaves RSA"""
    global keys_initialized, public_key_pem, private_key
    
    return {
        "initialized": keys_initialized,
        "has_public_key": public_key_pem is not None,
        "has_private_key": private_key is not None,
        "status": "success" if keys_initialized else "error"
    }

@app.get("/debug_keys")
async def debug_keys():
    """Debug detallado del estado de las llaves"""
    global keys_initialized, public_key_pem, private_key
    
    return {
        "keys_initialized": keys_initialized,
        "public_key_pem_exists": public_key_pem is not None,
        "private_key_exists": private_key is not None,
        "public_key_length": len(public_key_pem) if public_key_pem else 0,
        "public_key_preview": public_key_pem[:100] + "..." if public_key_pem else None,
        "private_key_type": str(type(private_key)) if private_key else None
    }

@app.get("/force_reset_keys")
async def force_reset_keys():
    """SOLO PARA DEBUG: Fuerza el reset e inicialización de llaves"""
    global keys_initialized, public_key_pem, private_key
    
    # Reset variables
    keys_initialized = False
    public_key_pem = None
    private_key = None
    
    try:
        # Regenerar llaves
        result = generate_rsa_keys()
        return {
            "message": "Llaves regeneradas exitosamente", 
            "status": "success",
            "initialized": keys_initialized,
            "has_public_key": public_key_pem is not None,
            "has_private_key": private_key is not None
        }
    except Exception as e:
        return {
            "message": f"Error al regenerar llaves: {str(e)}", 
            "status": "error"
        }

@app.get("/public_key")
async def get_public_key():
    """Retorna la llave pública en formato PEM"""
    global public_key_pem
    
    if public_key_pem is None:
        return {"message": "Las llaves no han sido inicializadas. Llama primero a /initialize_keys", "status": "error"}
    
    return {
        "public_key": public_key_pem,
        "status": "success",
        "message": "Llave pública obtenida exitosamente"
    }

@app.post("/decrypt")
async def decrypt_endpoint(data: dict):
    """Desencripta un mensaje usando la llave privada, verifica la dirección del banco o alias y responde encriptado"""
    try:
        if "encrypted_message" not in data:
            return {"message": "Se requiere el campo 'encrypted_message'", "status": "error"}

        decrypted_message = decrypt_message(data["encrypted_message"])

        # Parsear el mensaje desencriptado como JSON
        try:
            decrypted_json = json.loads(decrypted_message)
        except json.JSONDecodeError:
            return {"message": "El mensaje desencriptado no es un JSON válido", "status": "error"}

        # Verificar si la dirección o alias del banco está en la base de datos
        address = decrypted_json.get("address")
        bank_entry = next((bank for bank in banks_database if bank["address"] == address or address in bank["aliases"]), None)
        if not bank_entry:
            return {"message": "La dirección o alias del banco no es válida o no está registrada", "status": "error"}

        # Generar una respuesta simple en texto
        response_message = f"OK: {address}"

        # Encriptar la respuesta usando la llave pública del banco
        public_key = serialization.load_pem_public_key(bank_entry["public_key"].encode("utf-8"))
        encrypted_response = public_key.encrypt(
            response_message.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_response_base64 = base64.b64encode(encrypted_response).decode("utf-8")

        return {
            "encrypted_response": encrypted_response_base64,
            "status": "success"
        }
    except Exception as e:
        return {"message": f"Error al desencriptar: {str(e)}", "status": "error"}

@app.get("/tdx_quote")
async def tdx_quote():
    client = AsyncTappdClient()
    result = await client.tdx_quote('test')
    return result

@app.get('/derive_key')
async def derive_key():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    return result

@app.get('/eth_account')
async def eth_account():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    account = to_account_secure(result)
    return { 'address': account.address }

@app.get('/sol_account')
async def sol_account():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    keypair = to_keypair_secure(result)
    return { 'address': str(keypair.pubkey()) }

@app.get("/encryption_mode")
async def encryption_mode():
    """Devuelve el modo de encriptación utilizado por RSA"""
    return {
        "padding": "OAEP",
        "mgf": "MGF1",
        "hash_algorithm": "SHA256",
        "status": "success",
        "message": "Modo de encriptación obtenido exitosamente"
    }
