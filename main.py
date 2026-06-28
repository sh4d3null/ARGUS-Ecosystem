import hashlib

def calcular_hash_archivo(ruta_archivo):
    """
    Calcula el hash SHA-256 de un archivo para verificar su integridad.
    Doctrina de Manual: Control de Detección - Monitoreo de Integridad.
    """
    hash_sha256 = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as archivo:
            # Lee el archivo en bloques de 4KB para no saturar la memoria RAM
            for bloque in iter(lambda: archivo.read(4096), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except FileNotFoundError:
        return "Error: Archivo no interceptado en el perímetro local."

if __name__ == "__main__":
    print("👁️ [ARGUS Ecosystem] - Iniciando Módulo de Análisis de Integridad...")
    # Reemplaza 'README.md' por cualquier archivo que quieras auditar en caliente
    archivo_objetivo = "README.md" 
    resultado_hash = calcular_hash_archivo(archivo_objetivo)
    
    print(f"📌 Archivo bajo análisis: {archivo_objetivo}")
    print(f"🔒 Firma Criptográfica (SHA-256): {resultado_hash}")
