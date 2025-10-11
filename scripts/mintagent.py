import os
import sys
import asyncio
import json
from typing import List
from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_account.messages import encode_defunct
from colorama import init, Fore, Style
import aiohttp
from aiohttp_socks import ProxyConnector
from datetime import datetime, timezone

# Initialize colorama
init(autoreset=True)

# Border width
BORDER_WIDTH = 80

# Constants
API_BASE_URL = "https://api-web.nitrograph.com"
COMMUNITY_URL = "https://community.nitrograph.com"
NONCE_URL = f"{API_BASE_URL}/api/auth/nonce"
VERIFY_URL = f"{API_BASE_URL}/api/auth/verify"
MINT_AGENT_URL = f"{API_BASE_URL}/api/credits/mint-agent"
NETWORK_URL = "https://rpc-testnet.nitrograph.foundation/"
CHAIN_ID = 200024
EXPLORER_URL = "https://explorer-testnet.nitrograph.foundation/tx/"
IP_CHECK_URL = "https://api.ipify.org?format=json"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5",
    "Content-Type": "application/json",
    "Origin": "https://community.nitrograph.com",
    "Referer": "https://community.nitrograph.com/",
    "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-site"
}

# Configuration
CONFIG = {
    "DELAY_BETWEEN_ACCOUNTS": 5,
    "RETRY_ATTEMPTS": 3,
    "RETRY_DELAY": 3,
    "THREADS": 2,
    "TIMEOUT": 30
}

# Task to complete
TASK = {
    "taskId": "mint_agent",
    "url": MINT_AGENT_URL,
    "method": "POST",
    "payload": {}
}

# Bilingual vocabulary
LANG = {
    'vi': {
        'title': 'TỰ ĐỘNG MINT NITRO AGENT - NITROGRAPH',
        'info': 'Thông tin',
        'found': 'Tìm thấy',
        'proxies': 'proxy trong proxies.txt',
        'no_proxies': 'Không tìm thấy proxy trong proxies.txt',
        'using_proxy': '🔄 Sử dụng Proxy - [{proxy}] với IP công khai - [{public_ip}]',
        'no_proxy': 'Không có proxy',
        'unknown': 'Không xác định',
        'invalid_proxy': '⚠ Proxy không hợp lệ hoặc không hoạt động: {proxy}',
        'ip_check_failed': '⚠ Không thể kiểm tra IP công khai: {error}',
        'loading_wallets': 'Đang tải ví từ pvkey.txt...',
        'no_wallets': '❌ Không tìm thấy ví trong pvkey.txt',
        'invalid_wallet': '❌ Ví không hợp lệ: {line}',
        'processing_wallets': '⚙ ĐANG XỬ LÝ {count} VÍ',
        'signing_message': 'Đang ký thông điệp...',
        'sign_in_success': '✅ Đăng nhập thành công!',
        'sign_in_failure': '❌ Đăng nhập thất bại: {error}',
        'completing_task': 'Đang thực hiện nhiệm vụ mint_agent...',
        'task_success': '✅ Hoàn thành nhiệm vụ mint Nitro Agent! Transaction Hash: {tx_hash}',
        'task_failure': '❌ Thất bại khi thực hiện nhiệm vụ mint_agent: {error}',
        'pausing': 'Tạm dừng',
        'seconds': 'giây',
        'completed': '✔ HOÀN THÀNH: {successful}/{total} NHIỆM VỤ MINT AGENT',
        'error': 'Lỗi',
        'found_wallets': 'Thông tin: Tìm thấy {count} ví'
    },
    'en': {
        'title': 'AUTOMATIC MINT NITRO AGENT - NITROGRAPH',
        'info': 'Information',
        'found': 'Found',
        'proxies': 'proxies in proxies.txt',
        'no_proxies': 'No proxies found in proxies.txt',
        'using_proxy': '🔄 Using Proxy - [{proxy}] with public IP - [{public_ip}]',
        'no_proxy': 'No proxy',
        'unknown': 'Unknown',
        'invalid_proxy': '⚠ Invalid or non-working proxy: {proxy}',
        'ip_check_failed': '⚠ Unable to check public IP: {error}',
        'loading_wallets': 'Loading wallets from pvkey.txt...',
        'no_wallets': '❌ No wallets found in pvkey.txt',
        'invalid_wallet': '❌ Invalid wallet: {line}',
        'processing_wallets': '⚙ PROCESSING {count} WALLETS',
        'signing_message': 'Signing message...',
        'sign_in_success': '✅ Login successful!',
        'sign_in_failure': '❌ Login failed: {error}',
        'completing_task': 'Completing mint_agent task...',
        'task_success': '✅ Completed mint Nitro Agent task! Transaction Hash: {tx_hash}',
        'task_failure': '❌ Failed to complete mint_agent task: {error}',
        'pausing': 'Pausing',
        'seconds': 'seconds',
        'completed': '✔ COMPLETED: {successful}/{total} MINT AGENT TASKS',
        'error': 'Error',
        'found_wallets': 'Info: Found {count} wallets'
    }
}

# Display functions
def print_border(text: str, color=Fore.CYAN, width=BORDER_WIDTH):
    text = text.strip()
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    padded_text = f" {text} ".center(width - 2)
    print(f"{color}┌{'─' * (width - 2)}┐{Style.RESET_ALL}")
    print(f"{color}│{padded_text}│{Style.RESET_ALL}")
    print(f"{color}└{'─' * (width - 2)}┘{Style.RESET_ALL}")

def print_separator(color=Fore.MAGENTA):
    print(f"{color}{'═' * BORDER_WIDTH}{Style.RESET_ALL}")

def print_message(message: str, color=Fore.YELLOW):
    print(f"{color}{message}{Style.RESET_ALL}")

def print_wallets_summary(count: int, language: str = 'vi'):
    print_border(
        LANG[language]['processing_wallets'].format(count=count),
        Fore.MAGENTA
    )
    print()

# Utility functions
def load_proxies(file_path: str = "proxies.txt", language: str = 'vi') -> List[str]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.YELLOW} ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            with open(file_path, 'w') as f:
                f.write("# Add proxies here, one per line\n# Example: socks5://user:pass@host:port or http://host:port\n")
            return []
        
        proxies = []
        with open(file_path, 'r') as f:
            for line in f:
                proxy = line.strip()
                if proxy and not proxy.startswith('#'):
                    proxies.append(proxy)
        
        if not proxies:
            print(f"{Fore.YELLOW} ⚠ {LANG[language]['no_proxies']}. Using no proxy.{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.YELLOW} ℹ {LANG[language]['found']} {len(proxies)} {LANG[language]['proxies']}{Style.RESET_ALL}")
        return proxies
    except Exception as e:
        print(f"{Fore.RED} ✖ {LANG[language]['error']}: {str(e)}{Style.RESET_ALL}")
        return []

def load_wallets(file_path: str = "pvkey.txt", language: str = 'vi') -> List[LocalAccount]:
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.RED} ✖ {LANG[language]['no_wallets']}{Style.RESET_ALL}")
            sys.exit(1)
        
        wallets = []
        with open(file_path, 'r') as f:
            for line in f:
                private_key = line.strip()
                if private_key and not private_key.startswith('#'):
                    try:
                        account = Account.from_key(private_key)
                        wallets.append(account)
                    except Exception:
                        print(f"{Fore.RED} ✖ {LANG[language]['invalid_wallet'].format(line=private_key)}{Style.RESET_ALL}")
        
        if not wallets:
            print(f"{Fore.RED} ✖ {LANG[language]['no_wallets']}{Style.RESET_ALL}")
            sys.exit(1)
        
        print(f"{Fore.YELLOW} ℹ {LANG[language]['found_wallets'].format(count=len(wallets))}{Style.RESET_ALL}")
        return wallets
    except Exception as e:
        print(f"{Fore.RED} ✖ {LANG[language]['error']}: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

async def get_proxy_ip(proxy: str = None, language: str = 'vi') -> str:
    try:
        connector = ProxyConnector.from_url(proxy) if proxy else None
        async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])) as session:
            async with session.get(IP_CHECK_URL, headers=HEADERS) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('ip', LANG[language]['unknown'])
                print(f"{Fore.YELLOW} ⚠ {LANG[language]['ip_check_failed'].format(error=f'HTTP {response.status}')}{Style.RESET_ALL}")
                return LANG[language]['unknown']
    except Exception as e:
        print(f"{Fore.YELLOW} ⚠ {LANG[language]['ip_check_failed'].format(error=str(e))}{Style.RESET_ALL}")
        return LANG[language]['unknown']

async def get_nonce(address: str, language: str = 'vi', proxy: str = None) -> str:
    headers = HEADERS.copy()
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])) as session:
                async with session.get(NONCE_URL, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("nonce", "")
                    print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error=f'HTTP {response.status}')}{Style.RESET_ALL}")
                    return ""
        except Exception as e:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                await asyncio.sleep(CONFIG['RETRY_DELAY'])
                continue
            print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error=str(e))}{Style.RESET_ALL}")
            return ""
    return ""

def create_session_cookies(token: str) -> str:
    try:
        import base64
        payload_part = token.split('.')[1]
        padding = len(payload_part) % 4
        if padding:
            payload_part += '=' * (4 - padding)
        payload = json.loads(base64.urlsafe_b64decode(payload_part))
        
        session_v1 = token
        session_v4 = {
            "token": token,
            "userId": payload.get("userId", ""),
            "snagUserId": payload.get("snagUserId", ""),
            "address": payload.get("walletAddress", ""),
            "chainId": payload.get("chainId", 200024),
            "expiresAt": payload.get("exp", 0) * 1000,
            "newAccount": payload.get("newAccount", True),
            "refreshToken": ""
        }
        
        import urllib.parse
        session_v4_str = urllib.parse.quote(json.dumps(session_v4))
        
        return f"__nitrograph-session-v1={session_v1}; @nitrograph/session-v4={session_v4_str}"
    except Exception as e:
        print(f"{Fore.YELLOW} ⚠ Warning: Could not parse token for cookies: {str(e)}{Style.RESET_ALL}")
        return f"__nitrograph-session-v1={token}"

async def sign_in(account: LocalAccount, wallet_index: int, language: str = 'vi', proxy: str = None) -> str:
    address = account.address
    print(f"{Fore.CYAN} > {LANG[language]['signing_message']}{Style.RESET_ALL}")
    
    nonce = await get_nonce(address, language, proxy)
    if not nonce:
        print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error='Không lấy được nonce')}{Style.RESET_ALL}")
        return ""
    
    message = f"community.nitrograph.com wants you to sign in with your Ethereum account:\n{address}\n\nSign in to Nitrograph using your wallet\n\nURI: https://community.nitrograph.com\nVersion: 1\nChain ID: {CHAIN_ID}\nNonce: {nonce}\nIssued At: {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}"
    encoded_message = encode_defunct(text=message)
    signature = account.sign_message(encoded_message).signature.hex()
    if not signature.startswith('0x'):
        signature = '0x' + signature
    
    payload = {"message": message, "signature": signature}
    headers = HEADERS.copy()
    
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])) as session:
                async with session.post(VERIFY_URL, headers=headers, json=payload) as response:
                    if response.status == 200:
                        data = await response.json()
                        token = data.get("token", "")
                        print(f"{Fore.GREEN} ✔ {LANG[language]['sign_in_success']}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}    - Địa chỉ ví: {address}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}    - Token: {token[:20]}...{Style.RESET_ALL}")
                        return token
                    else:
                        error_text = await response.text()
                        print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error=f'HTTP {response.status}: {error_text}')}{Style.RESET_ALL}")
                        return ""
        except Exception as e:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                delay = CONFIG['RETRY_DELAY']
                print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error=str(e))}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}   {LANG[language]['pausing']} {delay:.2f} {LANG[language]['seconds']}{Style.RESET_ALL}")
                await asyncio.sleep(delay)
                continue
            print(f"{Fore.RED} ✖ {LANG[language]['sign_in_failure'].format(error=str(e))}{Style.RESET_ALL}")
            return ""
    return ""

async def complete_task(token: str, task: dict, language: str = 'vi', proxy: str = None) -> tuple[bool, str]:
    print(f"{Fore.CYAN} > {LANG[language]['completing_task']}{Style.RESET_ALL}")
    
    cookies = create_session_cookies(token)
    headers = {
        **HEADERS,
        "Authorization": f"Bearer {token}",
        "Cookie": cookies
    }
    
    for attempt in range(CONFIG['RETRY_ATTEMPTS']):
        try:
            connector = ProxyConnector.from_url(proxy) if proxy else None
            async with aiohttp.ClientSession(connector=connector, timeout=aiohttp.ClientTimeout(total=CONFIG['TIMEOUT'])) as session:
                if task['method'] == "POST":
                    async with session.post(task['url'], headers=headers, json=task['payload']) as response:
                        if response.status == 200:
                            data = await response.json()
                            if data.get("success", False):
                                tx_hash = data.get("transactionHash", "N/A")
                                print(f"{Fore.GREEN} ✔ {LANG[language]['task_success'].format(tx_hash=tx_hash)}{Style.RESET_ALL}")
                                print(f"{Fore.YELLOW}    - Explorer: {EXPLORER_URL}{tx_hash}{Style.RESET_ALL}")
                                return True, tx_hash
                            error_message = data.get("message", "Unknown error")
                            print(f"{Fore.RED} ✖ {LANG[language]['task_failure'].format(error=error_message)}{Style.RESET_ALL}")
                            return False, ""
                        error_text = await response.text()
                        print(f"{Fore.RED} ✖ {LANG[language]['task_failure'].format(error=f'HTTP {response.status}: {error_text}')}{Style.RESET_ALL}")
                        return False, ""
                else:
                    print(f"{Fore.RED} ✖ {LANG[language]['task_failure'].format(error='Phương thức không được hỗ trợ')}{Style.RESET_ALL}")
                    return False, ""
        except Exception as e:
            if attempt < CONFIG['RETRY_ATTEMPTS'] - 1:
                await asyncio.sleep(CONFIG['RETRY_DELAY'])
                continue
            print(f"{Fore.RED} ✖ {LANG[language]['task_failure'].format(error=str(e))}{Style.RESET_ALL}")
            return False, ""
    return False, ""

async def process_wallet(index: int, account: LocalAccount, language: str = 'vi', proxies: List[str] = None) -> bool:
    proxy = proxies[index % len(proxies)] if proxies else None
    address = account.address
    print_border(f"Xử lý ví {index + 1}: {address[:8]}...{address[-8:]}", Fore.YELLOW)
    
    # Display proxy info
    public_ip = await get_proxy_ip(proxy, language)
    proxy_display = proxy if proxy else LANG[language]['no_proxy']
    print(f"{Fore.CYAN} 🔄 {LANG[language]['using_proxy'].format(proxy=proxy_display, public_ip=public_ip)}{Style.RESET_ALL}")

    # Sign in
    token = await sign_in(account, index + 1, language, proxy)
    if not token:
        print(f"{Fore.RED} ✖ Bỏ qua ví {index + 1} do đăng nhập thất bại{Style.RESET_ALL}")
        return False

    # Complete task
    success, tx_hash = await complete_task(token, TASK, language, proxy)
    if not success:
        print(f"{Fore.RED} ✖ Bỏ qua ví {index + 1} do thất bại khi thực hiện nhiệm vụ mint_agent{Style.RESET_ALL}")
        return False

    return True

async def run_mintagent(language: str = 'vi'):
    print()
    print_border(LANG[language]['title'], Fore.CYAN)
    print()

    # Load proxies
    proxies = load_proxies('proxies.txt', language)
    print()

    # Load wallets
    wallets = load_wallets('pvkey.txt', language)
    print()

    print_separator()
    print_wallets_summary(len(wallets), language)

    total_wallets = 0
    successful_wallets = 0
    semaphore = asyncio.Semaphore(CONFIG['THREADS'])

    async def sem_process_wallet(index: int, account: LocalAccount):
        nonlocal successful_wallets, total_wallets
        async with semaphore:
            try:
                success = await process_wallet(index, account, language, proxies)
                total_wallets += 1
                if success:
                    successful_wallets += 1
                if index < len(wallets) - 1:
                    delay = CONFIG['DELAY_BETWEEN_ACCOUNTS']
                    print_message(f" ℹ {LANG[language]['pausing']} {delay:.2f} {LANG[language]['seconds']}", Fore.YELLOW)
                    await asyncio.sleep(delay)
            except Exception as e:
                print(f"{Fore.RED} ✖ Lỗi xử lý ví {index + 1}: {str(e)}{Style.RESET_ALL}")
                total_wallets += 1

    tasks = [sem_process_wallet(i, account) for i, account in enumerate(wallets)]
    await asyncio.gather(*tasks, return_exceptions=True)

    print()
    print_border(f"{LANG[language]['completed'].format(successful=successful_wallets, total=total_wallets)}", Fore.GREEN)
    print()

if __name__ == "__main__":
    asyncio.run(run_mintagent('vi'))
