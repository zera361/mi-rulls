import sys
import json
import urllib.request
import collections
import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
import router_pb2

def log_to_review(message):
    os.makedirs("tools", exist_ok=True)
    with open("tools/review.log", "a", encoding="utf-8") as f:
        f.write(message + "\n")

def get_item_key(item, attr_name):
    if attr_name == "domain":
        return (item.type, item.value)
    return (item.ip, item.prefix)

def optimize_domains(domains_list):
    dom_map = {}
    full_map = {}
    plains = []
    regexes = []
    others = []

    for d in domains_list:
        if d.type == 0: 
            plains.append(d)
        elif d.type == 1: 
            regexes.append(d)
        elif d.type == 2:
            if d.value not in dom_map or len(d.attribute) > len(dom_map[d.value].attribute):
                dom_map[d.value] = d
        elif d.type == 3:
            if d.value not in full_map or len(d.attribute) > len(full_map[d.value].attribute):
                full_map[d.value] = d
        else:
            others.append(d)

    plain_values = [p.value for p in plains]

    final_doms = set()
    sorted_dom_keys = sorted(dom_map.keys(), key=len)
    
    for d_val in sorted_dom_keys:
        parts = d_val.split('.')
        is_subdomain = False
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in final_doms:
                is_subdomain = True
                break
                
        if is_subdomain:
            continue

        if any(p_val in d_val for p_val in plain_values):
            continue

        final_doms.add(d_val)

    final_fulls = set()
    for f_val in full_map.keys():
        parts = f_val.split('.')
        
        is_covered_by_domain = False
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in final_doms:
                is_covered_by_domain = True
                break
                
        if is_covered_by_domain:
            continue

        if any(p_val in f_val for p_val in plain_values):
            continue

        final_fulls.add(f_val)

    optimized = []
    optimized.extend(plains)
    optimized.extend(regexes)
    for d_val in final_doms: 
        optimized.append(dom_map[d_val])
    for f_val in final_fulls: 
        optimized.append(full_map[f_val])
    optimized.extend(others)
    
    return optimized

def optimize_ips(cidr_list):
    ipv4_nets = []
    ipv6_nets = []
    for c in cidr_list:
        try:
            addr = ipaddress.ip_address(c.ip)
            net = ipaddress.ip_network(f"{addr}/{c.prefix}", strict=False)
            if isinstance(net, ipaddress.IPv4Network): 
                ipv4_nets.append(net)
            else: 
                ipv6_nets.append(net)
        except Exception:
            pass
            
    opt_v4 = list(ipaddress.collapse_addresses(ipv4_nets))
    opt_v6 = list(ipaddress.collapse_addresses(ipv6_nets))

    optimized = []
    for net in opt_v4 + opt_v6:
        c = router_pb2.CIDR()
        c.ip = net.network_address.packed
        c.prefix = net.prefixlen
        optimized.append(c)
    return optimized

def parse_json_source_geoip(data, allowed_cats_set):
    provider_cidrs = []
    for provider, info in data.items():
        prov_upper = provider.upper()
        if prov_upper not in allowed_cats_set:
            continue
            
        cidrs = info.get("cidrs", []) or info.get("ips", []) or []
        for c in cidrs:
            if isinstance(c, str) and '/' in c:
                try:
                    net = ipaddress.ip_network(c.strip(), strict=False)
                    cidr_proto = router_pb2.CIDR()
                    cidr_proto.ip = net.network_address.packed
                    cidr_proto.prefix = net.prefixlen
                    provider_cidrs.append((cidr_proto, prov_upper))
                except Exception:
                    continue
    return provider_cidrs

def parse_json_source_geosite(data, allowed_cats_set):
    proto_domains = []
    type_mapping = {
        "plain": router_pb2.Domain.Plain,
        "keyword": router_pb2.Domain.Plain,
        "regex": router_pb2.Domain.Regex,
        "domain": router_pb2.Domain.Domain,
        "full": router_pb2.Domain.Full
    }

    for category, content in data.items():
        cat_upper = category.upper()
        if cat_upper not in allowed_cats_set:
            continue
            
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, str):
                    continue
                d_type = router_pb2.Domain.Domain
                d_value = item.strip()
                if ":" in d_value:
                    prefix, value = d_value.split(":", 1)
                    if prefix.lower() in type_mapping:
                        d_type = type_mapping[prefix.lower()]
                        d_value = value.strip()
                if d_value:
                    d_proto = router_pb2.Domain()
                    d_proto.type = d_type
                    d_proto.value = d_value
                    proto_domains.append((d_proto, cat_upper))
    return proto_domains

def download_and_parse(source, list_class):
    print(f"Загрузка: {source['url']}")
    try:
        req = urllib.request.Request(source['url'], headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            data = response.read()
        
        url_lower = source['url'].lower()
        if url_lower.endswith('.json'):
            return source, json.loads(data.decode('utf-8'))
        else:
            parsed_list = list_class.FromString(data)
            return source, parsed_list
    except Exception as e:
        print(f"❌ Ошибка загрузки {source['url']}: {e}")
        return source, None

def process_dat(config, list_class, attr_name):
    category_items = collections.defaultdict(list)
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda src: download_and_parse(src, list_class), config))

    for source, parsed_data in results:
        if parsed_data is None:
            continue
            
        url_lower = source['url'].lower()
        
        if url_lower.endswith('.json'):
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                dst_cat = rule['dst'].upper()
                if attr_name == "cidr":
                    fetched = parse_json_source_geoip(parsed_data, src_cats)
                else:
                    fetched = parse_json_source_geosite(parsed_data, src_cats)
                items = [i for i, c in fetched]
                category_items[dst_cat].extend(items)
        else:
            for rule in source['rules']:
                src_cats = {c.upper() for c in rule['src']}
                dst_cat = rule['dst'].upper()
                for entry in parsed_data.entry:
                    current_cat = entry.country_code.upper()
                    if "*" in src_cats or current_cat in src_cats:
                        target = current_cat if dst_cat == "*" else dst_cat
                        items = getattr(entry, attr_name)
                        category_items[target].extend(items)
                    
    out_list = list_class()
    for cat, items in category_items.items():
        entry = out_list.entry.add()
        entry.country_code = cat.upper() 
        target_list = getattr(entry, attr_name)
        
        optimized_items = optimize_domains(items) if attr_name == "domain" else optimize_ips(items)
        target_list.extend(optimized_items)
                    
    return out_list

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python builder.py config.json")
        sys.exit(1)

    with open(sys.argv[1], 'r') as f:
        config = json.load(f)

    if 'geosite' in config:
        geosite = process_dat(config['geosite'], router_pb2.GeoSiteList, "domain")
        with open("geosite.dat", "wb") as f: 
            f.write(geosite.SerializeToString())
        print("[УСПЕХ] Файл geosite.dat успешно сгенерирован.")
        
    if 'geoip' in config:
        geoip = process_dat(config['geoip'], router_pb2.GeoIPList, "cidr")
        with open("geoip.dat", "wb") as f: 
            f.write(geoip.SerializeToString())
        print("[УСПЕХ] Файл geoip.dat успешно сгенерирован.")
        
    print("Сборка успешно завершена.")
