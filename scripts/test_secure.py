#!/usr/bin/env python3
"""
Test suite para verificar que la API segura bloquea correctamente BOLA
"""

import requests
from colorama import Fore, Style, init

init(autoreset=True)

BASE_URL = "http://localhost:3001"

def test_authentication():
    """Test 1: Verificar autenticación"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 1: Autenticación")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    response = requests.put(
        f"{BASE_URL}/api/orders/3",
        headers=headers,
        json={"status": "cancelled"}
    )
    
    if response.status_code in [404, 403]:
        print(f"{Fore.GREEN}✅ PASS: Modificación bloqueada correctamente")
        return True
    else:
        print(f"{Fore.RED}❌ FAIL: Se puede modificar órdenes ajenas")
        return False

def test_delete_blocked(token):
    """Test 5: Verificar que no se pueden eliminar órdenes ajenas"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 5: Protección contra eliminación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.delete(f"{BASE_URL}/api/orders/4", headers=headers)
    
    if response.status_code in [404, 403]:
        print(f"{Fore.GREEN}✅ PASS: Eliminación bloqueada correctamente")
        return True
    else:
        print(f"{Fore.RED}❌ FAIL: Se puede eliminar órdenes ajenas")
        return False

def test_own_order_access(token):
    """Test 6: Verificar que SÍ se puede acceder a órdenes propias"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 6: Acceso legítimo a orden propia")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Alice tiene las órdenes con ID 1 y 2
    response = requests.get(f"{BASE_URL}/api/orders/1", headers=headers)
    
    if response.status_code == 200:
        print(f"{Fore.GREEN}✅ PASS: Se puede acceder a órdenes propias")
        return True
    else:
        print(f"{Fore.RED}❌ FAIL: No se puede acceder a órdenes propias")
        return False

def main():
    print(f"\n{Fore.GREEN}{'='*60}")
    print("SUITE DE TESTS - API SEGURA (Puerto 3001)")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0
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
    
    # Test 3: BOLA bloqueado
    results['total'] += 1
    if test_bola_blocked(token):
        results['passed'] += 1
    else:
        results['failed'] += 1
    
    # Test 4: Update bloqueado
    results['total'] += 1
    if test_update_blocked(token):
        results['passed'] += 1
    else:
        results['failed'] += 1
    
    # Test 5: Delete bloqueado
    results['total'] += 1
    if test_delete_blocked(token):
        results['passed'] += 1
    else:
        results['failed'] += 1
    
    # Test 6: Acceso legítimo funciona
    results['total'] += 1
    if test_own_order_access(token):
        results['passed'] += 1
    else:
        results['failed'] += 1
    
    # Resumen
    print(f"\n{Fore.CYAN}{'='*60}")
    print("RESUMEN DE TESTS")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Total de tests: {results['total']}")
    print(f"{Fore.GREEN}Tests pasados: {results['passed']}")
    print(f"{Fore.RED}Tests fallados: {results['failed']}")
    
    if results['failed'] == 0:
        print(f"\n{Fore.GREEN}🎉 ¡EXCELENTE! La API está completamente protegida contra BOLA")
        print(f"{Fore.GREEN}✅ Todas las vulnerabilidades han sido corregidas{Style.RESET_ALL}\n")
    else:
        print(f"\n{Fore.YELLOW}⚠️  Algunos tests fallaron, revisar implementación{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()post(
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

def test_bola_blocked(token):
    """Test 3: Verificar que BOLA está bloqueado"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 3: Protección contra BOLA")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Intentar acceder a orden de otro usuario (ID 3 pertenece a Bob)
    response = requests.get(f"{BASE_URL}/api/orders/3", headers=headers)
    
    if response.status_code == 404 or response.status_code == 403:
        print(f"{Fore.GREEN}✅ PASS: Acceso bloqueado correctamente")
        print(f"{Fore.GREEN}La API protege contra BOLA adecuadamente")
        return True
    else:
        print(f"{Fore.RED}❌ FAIL: Vulnerabilidad BOLA aún presente")
        return False

def test_update_blocked(token):
    """Test 4: Verificar que no se pueden modificar órdenes ajenas"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 4: Protección contra modificación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
    
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.
