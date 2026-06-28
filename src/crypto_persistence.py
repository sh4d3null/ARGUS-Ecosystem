import os
import hashlib
import base64
import json

class CryptoPersistence:
    def __init__(self, password: str):
        """
        Inicializa el motor criptográfico nativo derivando una clave SHA-256
        a partir de la contraseña del operador y un Salt aleatorio de 16 bytes.
        """
        self.password = password.encode('utf-8')
        self.salt = os.urandom(16)
        self.hash_password = hashlib.sha256(self.password + self.salt).digest()

    def xor_encrypt_decrypt(self, data: bytes) -> bytes:
        """Aplica la operación lógica XOR bit a bit utilizando la clave derivada."""
        return bytes(a ^ b for a, b in zip(data, self.hash_password))

    def encrypt_data(self, data: str) -> str:
        """Cifra el texto plano, concatena el Salt y devuelve una cadena Base64 limpia."""
        encrypted = self.xor_encrypt_decrypt(data.encode('utf-8'))
        return base64.b64encode(self.salt + encrypted).decode('utf-8')

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decodifica el Base64, aísla el Salt dinámico, recalcula la clave y descifra."""
        datos_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
        salt = datos_bytes[:16]
        self.hash_password = hashlib.sha256(self.password + salt).digest()
        decrypted = self.xor_encrypt_decrypt(datos_bytes[16:])
        return decrypted.decode('utf-8')


def guardar_analisis_suite(modulo_nombre, datos_crudos, veredicto, password):
    """
    Empaqueta las evidencias en un formato JSON estructurado, las cifra
    dinámicamente y las almacena de forma persistente delimitadas por saltos de línea.
    """
    persistence = CryptoPersistence(password)
    payload_json = {
        'modulo': modulo_nombre, 
        'datos': datos_crudos, 
        'veredicto': veredicto
    }
    
    # Serializar a JSON y cifrar
    encrypted_data = persistence.encrypt_data(json.dumps(payload_json))

    # Guardar en almacenamiento seguro con salto de línea para evitar colisiones
    with open('analisis_suite.txt', 'a') as f:
        f.write(encrypted_data + '\n')


# --- Bloque de Prueba de Laboratorio Local ---
if __name__ == "__main__":
    pass_operator = "TU_CONTRASEÑA_SUPER_SECRETA_AQUÍ"
    
    print("=== [!] Probando Motor Criptográfico Nativo ===")
    
    # 1. Prueba de la Clase en memoria
    motor = CryptoPersistence(pass_operator)
    evidencia_test = "Evidencia forense de inyección SQL detectada en puerto 80"
    
    cifrado_base64 = motor.encrypt_data(evidencia_test)
    print(f"[+] Texto Cifrado (Base64): {cifrado_base64}")
    
    descifrado_texto = motor.decrypt_data(cifrado_base64)
    print(f"[+] Texto Recuperado: {descifrado_texto}")
    
    # 2. Prueba de la función de persistencia en disco
    print("\n=== [!] Generando persistencia en 'analisis_suite.txt' ===")
    datos_ejemplo_log = {"ip_atacante": "192.168.1.50", "payload": "../etc/passwd"}
    veredicto_eva = "Riesgo Crítico: Intento de Path Traversal confirmado por firmas."
    
    guardar_analisis_suite("Log Auditor", datos_ejemplo_log, veredicto_eva, pass_operator)
    print("[+] Registro cifrado guardado con éxito. Verifica tu carpeta de trabajo.")
