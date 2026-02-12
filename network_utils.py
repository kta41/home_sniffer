import requests

DEVICE_MAP = {
    "127.0.0.1": "LOCAL",
    "192.168.1.1": "ROUTER",
    "192.168.1.15": "MI_PC",
}

geo_cache = {}

def get_ip_label(ip):
    if ip in DEVICE_MAP:
        return f"{ip} ({DEVICE_MAP[ip]})"
    
    if ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        return ip

    if ip in geo_cache:
        return f"{ip} ({geo_cache[ip]})"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=0.3).json()
        if response.get("status") == "success":
            location = f"{response['countryCode']} - {response['city']}"
            geo_cache[ip] = location
            return f"{ip} ({location})"
    except:
        pass

    return ip