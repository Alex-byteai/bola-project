#!/usr/bin/env python3
"""
Script para poblar la base de datos con datos de prueba
Útil para resetear los datos después de demostraciones
"""

import requests
import json
from colorama import Fore, Style, init

init(autoreset=True)

VULNERABLE_URL = "http://localhost:3000"
SECURE_URL = "http://localhost:3001"

def create_users_and_orders(base_url, api_name):
    """Crear usuarios y órdenes de prueba"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Poblando {api_name}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Usuarios a crear
    users = [
        {
            "email": "alice@example.com",
            "password": "password123",
            "name": "Alice Johnson"
        },
        {
            "email": "bob@example.com",
            "password": "password123",
            "name": "Bob Smith"
        },
        {
            "email": "charlie@example.com",
            "password": "password123",
            "name": "Charlie Brown"
        }
    ]
    
    # Órdenes para cada usuario
    orders_data = {
        "alice@example.com": [
            {
                "product": "Laptop Dell XPS 15",
                "amount": 1899.99,
                "creditCard": "**** **** **** 1234",
                "address": "123 Main St, Ciudad",
                "phone": "+51 999 888 777"
            },
            {
                "product": "Mouse Logitech MX Master",
                "amount": 99.99,
                "creditCard": "**** **** **** 1234",
                "address": "123 Main St, Ciudad",
                "phone": "+51 999 888 777"
            }
        ],
        "bob@example.com": [
            {
                "product": "iPhone 15 Pro",
                "amount": 1299.99,
                "creditCard": "**** **** **** 5678",
                "address": "456 Oak Ave, Lima",
                "phone": "+51 987 654 321"
            },
            {
                "product": "AirPods Pro",
                "amount": 249.99,
                "creditCard": "**** **** **** 5678",
                "address": "456 Oak Ave, Lima",
                "phone": "+51 987 654 321"
            }
        ],
        "charlie@example.com": [
            {
                "product": "Samsung Galaxy S24",
                "amount": 999.99,
                "creditCard": "**** **** **** 9012",
                "address": "789 Pine Rd, Cusco",
                "phone": "+51 912 345 678"
            },
            {
                "product": "PlayStation 5",
                "amount": 499.99,
                "creditCard": "**** **** **** 9012",
                "address": "789 Pine Rd, Cusco",
                "phone": "+51 912 345 678"
            }
        ]
    }
    
    tokens = {}
    
    # Registrar usuarios y obtener tokens
    for user in users:
        print(f"\n{Fore.YELLOW}[*] Registrando usuario: {user['email']}")
        
        try:
            # Intentar registrar
            response = requests.post(
                f"{base_url}/api/auth/register",
                json=user,
                timeout=5
            )
            
            if response.status_code == 201:
                print(f"{Fore.GREEN}[✓] Usuario registrado")
            else:
                print(f"{Fore.YELLOW}[!] Usuario ya existe, obteniendo token...")
            
            # Login para obtener token
            login_response = requests.post(
                f"{base_url}/api/auth/login",
                json={
                    "email": user['email'],
                    "password": user['password']
                },
                timeout=5
            )
            
            if login_response.status_code == 200:
                token = login_response.json()['token']
                tokens[user['email']] = token
                print(f"{Fore.GREEN}[✓] Token obtenido")
            else:
                print(f"{Fore.RED}[✗] Error al obtener token")
                
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {str(e)}")
    
    # Crear órdenes para cada usuario
    for email, token in tokens.items():
        print(f"\n{Fore.YELLOW}[*] Creando órdenes para {email}")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        for order in orders_data[email]:
            try:
                response = requests.post(
                    f"{base_url}/api/orders",
                    json=order,
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code == 201:
                    order_id = response.json().get('orderId')
                    print(f"{Fore.GREEN}[✓] Orden creada: {order['product']} (ID: {order_id})")
                else:
                    print(f"{Fore.RED}[✗] Error al crear orden: {order['product']}")
                    
            except Exception as e:
                print(f"{Fore.RED}[✗] Error: {str(e)}")
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"Datos poblados exitosamente en {api_name}")
    print(f"{'='*60}{Style.RESET_ALL}")

def verify_data(base_url, api_name):
    """Verificar que los datos se crearon correctamente"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"Verificando datos en {api_name}")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    # Login como Alice
    response = requests.post(
        f"{base_url}/api/auth/login",
        json={"email": "alice@example.com", "password": "password123"}
    )
    
    if response.status_code == 200:
        token = response.json()['token']
        headers = {"Authorization": f"Bearer {token}"}
        
        # Obtener órdenes
        orders_response = requests.get(
            f"{base_url}/api/orders",
            headers=headers
        )
        
        if orders_response.status_code == 200:
            count = orders_response.json()['count']
            print(f"{Fore.GREEN}[✓] {count} órdenes encontradas para Alice")
        else:
            print(f"{Fore.RED}[✗] Error al verificar órdenes")
    else:
        print(f"{Fore.RED}[✗] Error al autenticar")

def main():
    print(f"\n{Fore.YELLOW}{'='*60}")
    print("SCRIPT DE POBLACIÓN DE DATOS")
    print("Base de datos para APIs Vulnerable y Segura")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[!] Este script poblará las bases de datos con datos de prueba")
    print(f"[!] Se crearán 3 usuarios y 6 órdenes totales{Style.RESET_ALL}")
    
    # Poblar API Vulnerable
    try:
        create_users_and_orders(VULNERABLE_URL, "API Vulnerable (Puerto 3000)")
        verify_data(VULNERABLE_URL, "API Vulnerable")
    except Exception as e:
        print(f"{Fore.RED}[✗] Error con API Vulnerable: {str(e)}")
        print(f"Asegúrate de que la API esté corriendo en {VULNERABLE_URL}")
    
    # Poblar API Segura
    try:
        create_users_and_orders(SECURE_URL, "API Segura (Puerto 3001)")
        verify_data(SECURE_URL, "API Segura")
    except Exception as e:
        print(f"{Fore.RED}[✗] Error con API Segura: {str(e)}")
        print(f"Asegúrate de que la API esté corriendo en {SECURE_URL}")
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print("✅ PROCESO COMPLETADO")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}Credenciales de prueba:")
    print("  • alice@example.com   | password123")
    print("  • bob@example.com     | password123")
    print("  • charlie@example.com | password123{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
