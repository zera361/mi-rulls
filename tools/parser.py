import os
import urllib.request
import ipaddress
import collections
from concurrent.futures import ThreadPoolExecutor
import router_pb2

# Направляем парсер на свежесобранные локальные .dat файлы
SOURCES = {
    "Client-Flavor-geosite": "geosite.dat",
    "Client-Flavor-geoip": "geoip.dat"
}

OUTPUT_DIR = "parser-tmp"

def get_domain_type_str(d_type):
    if d_type == 0: return "keyword"
    if d_type == 1: return "regex"
    if d_type == 2: return "domain"
    if d_type == 3: return "full"
    return "unknown"

def format_domain(d):
    prefix = get_domain_type_str(d.type)
    return f"{prefix}:{d.value}" if prefix != "unknown" else d.value

def format_cidr(c):
    try:
        addr = ipaddress.ip_address(c.ip)
        return f"{addr}/{c.prefix}", "IPv4" if isinstance(addr, ipaddress.IPv4Address) else "IPv6"
    except Exception:
        return f"INVALID_IP/{c.prefix}", "invalid"

def process_single_source(folder_name, source_path):
    print(f"Запуск обработки: {folder_name}")
    
    target_folder = os.path.join(OUTPUT_DIR, folder_name)
    os.makedirs(target_folder, exist_ok=True)
    
    # Читаем локальный собранный файл
    try:
        with open(source_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"❌ Не удалось открыть файл {source_path}: {e}")
        return

    is_geoip = "geoip" in folder_name.lower() or "geoip" in source_path.lower()
    
    try:
        if is_geoip:
            parsed_list = router_pb2.GeoIPList.FromString(data)
            attr_name = "cidr"
        else:
            parsed_list = router_pb2.GeoSiteList.FromString(data)
            attr_name = "domain"
    except Exception as e:
        print(f"❌ Не удалось распарсить protobuf для {folder_name}: {e}")
        return

    total_elements = 0
    total_categories = len(parsed_list.entry)
    summary_lines = []
    global_type_counts = collections.Counter()

    for entry in parsed_list.entry:
        cat_name = entry.country_code
        safe_cat_name = "".join([c for c in cat_name if c.isalpha() or c.isdigit() or c in ('-', '_')]).rstrip()
        items = getattr(entry, attr_name)
        
        cat_type_counts = collections.Counter()
        lst_lines = []
        
        for item in items:
            if is_geoip:
                cidr_str, ip_type = format_cidr(item)
                if ip_type != "invalid":
                    lst_lines.append(cidr_str)
                    cat_type_counts[ip_type] += 1
                    global_type_counts[ip_type] += 1
            else:
                t_str = get_domain_type_str(item.type)
                lst_lines.append(format_domain(item))
                cat_type_counts[t_str] += 1
                global_type_counts[t_str] += 1

        elements_count = len(lst_lines)
        total_elements += elements_count
        
        type_details = ", ".join([f"{k}: {v}" for k, v in cat_type_counts.items()])
        summary_lines.append(f"- {cat_name}: {elements_count} элементов ({type_details})")
        
        # 1. Выгрузка .lst файлов
        lst_path = os.path.join(target_folder, f"{safe_cat_name}.lst")
        with open(lst_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lst_lines) + ("\n" if lst_lines else ""))

        # 2. Выгрузка БЕЗОПАСНЫХ .yaml файлов
        yaml_path = os.path.join(target_folder, f"{safe_cat_name}.yaml")
        with open(yaml_path, "w", encoding="utf-8") as f:
            if not lst_lines:
                f.write("payload: []\n")
            else:
                f.write("payload:\n")
                for line in lst_lines:
                    f.write(f"  - '{line}'\n")

    summary_path = os.path.join(target_folder, "_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(f"=== СВОДКА: {folder_name} ===\n")
        f.write(f"Всего категорий: {total_categories}\n")
        f.write(f"Всего элементов: {total_elements}\n\n")
        f.write("Детализация по категориям:\n")
        f.write("\n".join(summary_lines) + "\n")
        
    print(f"✓ Завершено: {folder_name}")

def parse_and_dump_parallel():
    for folder_name, source_path in SOURCES.items():
        process_single_source(folder_name, source_path)

if __name__ == "__main__":
    parse_and_dump_parallel()
    print("Все задачи парсинга выполнены.")
