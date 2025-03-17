# portscanner
# Escáner de Puertos Avanzado

Una herramienta en Python para escanear puertos en un host, identificar servicios y guardar resultados.

## Características
- Escaneo multi-hilo con `ThreadPoolExecutor` para mayor eficiencia.
- Identificación de servicios comunes (HTTP, SSH, FTP, etc.).
- Salida coloreada con `colorama`.
- Modo interactivo o por línea de comandos.
- Guarda resultados en `open_ports.txt`.

## Requisitos
- Python 3.x
- Bibliotecas: `colorama` (`pip install colorama`)

## Uso
### Línea de comandos
```bash
python port_scanner.py <host> <puerto_inicio> <puerto_fin>
