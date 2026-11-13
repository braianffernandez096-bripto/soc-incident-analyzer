"""Ajustes comunes de las pruebas."""
import os

# El cliente de pruebas de Starlette se presenta como «testserver»; la app solo acepta sus propios nombres (ver ALLOWED_HOSTS).
os.environ.setdefault("ALLOWED_HOSTS", "testserver")
