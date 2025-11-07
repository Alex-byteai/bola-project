#!/usr/bin/env python3
"""
Test suite para verificar la vulnerabilidad BOLA en la API
"""

import requests
import json
from colorama import Fore, Style, init

init(autoreset=True)

BASE_URL = "http://localhost:3000"

def test_authentication():
    """Test 1: Verificar que la autenticación funciona"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 1: Autenticación")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "alice@example.com", "password": "password123"}
    )
    
    if response.status_code == 200:
        print(f"{Fore.GREEN}✅ PASS: Autenticación exitosa")
        return response.json()['token']
    else:
        print(f"{Fore.RED}❌ FAIL: Error en autenticación")
        return None

def test_own_orders(token):
    """Test 2: Usuario puede ver sus propias órdenes"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 2: Acceso a órdenes propias")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/orders", headers=headers)
    
    if response.status_code == 200:
        orders = response.json()['orders']
        print(f"{Fore.GREEN}✅ PASS: Se obtuvieron {len(orders)} órdenes propias")
        return True
    else:
        print(f"{Fore.RED}❌ FAIL: No se pudieron obtener órdenes")
        return False

def test_bola_vulnerability(token):
    """Test 3: Verificar vulnerabilidad BOLA"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 3: Vulnerabilidad BOLA")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Intentar acceder a orden de otro usuario (ID 3 pertenece a Bob)
    response = requests.get(f"{BASE_URL}/api/orders/3", headers=headers)
    
    if response.status_code == 200:
        print(f"{Fore.RED}🚨 VULNERABILIDAD CONFIRMADA!")
        print(f"{Fore.YELLOW}La API permite acceder a órdenes de otros usuarios")
        order = response.json()['order']
        print(f"\nDatos obtenidos:")
        print(f"  - Orden ID: {order['id']}")
        print(f"  - Usuario: {order['userId']}")
        print(f"  - Producto: {order['product']}")
        print(f"  - Monto: ${order['amount']}")
        return True  # Vulnerabilidad confirmada
    else:
        print(f"{Fore.GREEN}✅ API segura: Acceso denegado correctamente")
        return False  # No vulnerable

def test_unauthorized_update(token):
    """Test 4: Intentar modificar orden ajena"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 4: Modificación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.put(
        f"{BASE_URL}/api/orders/3",
        headers=headers,
        json={"status": "cancelled"}
    )
    
    if response.status_code == 200:
        print(f"{Fore.RED}🚨 VULNERABILIDAD: Se puede modificar órdenes ajenas")
        return True
    else:
        print(f"{Fore.GREEN}✅ Modificación bloqueada correctamente")
        return False

def test_unauthorized_delete(token):
    """Test 5: Intentar eliminar orden ajena"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 5: Eliminación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.delete(f"{BASE_URL}/api/orders/4", headers=headers)
    
    if response.status_code == 200:
        print(f"{Fore.RED}🚨 VULNERABILIDAD: Se puede eliminar órdenes ajenas")
        return True
    else:
        print(f"{Fore.GREEN}✅ Eliminación bloqueada correctamente")
        return False

def main():
    print(f"\n{Fore.YELLOW}{'='*60}")
    print("SUITE DE TESTS - API VULNERABLE (Puerto 3000)")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'vulnerabilities': 0
    }
    
    # Test 1: Autenticación
    token = test_authentication()
    results['total'] += 1
    if token:
        results['passed'] += 1
    else:
        results['failed'] += 1
        print(f"\n{Fore.RED}No se puede continuar sin autenticación")
        return
    
    # Test 2: Órdenes propias
    results['total'] += 1
    if test_own_orders(token):
        results['passed'] += 1
    else:
        results['failed'] += 1
    
    # Test 3: BOLA
    results['total'] += 1
    if test_bola_vulnerability(token):
        results['vulnerabilities'] += 1
    
    # Test 4: Update no autorizado
    results['total'] += 1
    if test_unauthorized_update(token):
        results['vulnerabilities'] += 1
    
    # Test 5: Delete no autorizado
    results['total'] += 1
    if test_unauthorized_delete(token):
        results['vulnerabilities'] += 1
    
    # Resumen
    print(f"\n{Fore.CYAN}{'='*60}")
    print("RESUMEN DE TESTS")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Total de tests: {results['total']}")
    print(f"{Fore.GREEN}Tests pasados: {results['passed']}")
    print(f"{Fore.RED}Tests fallados: {results['failed']}")
    print(f"{Fore.RED}🚨 Vulnerabilidades encontradas: {results['vulnerabilities']}")
    
    if results['vulnerabilities'] > 0:
        print(f"\n{Fore.YELLOW}⚠️  Esta API es VULNERABLE y no debe usarse en producción")
    
    print(f"\n{Fore.CYAN}Recomendación: Prueba la API segura en puerto 3001{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
