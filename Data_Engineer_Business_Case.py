import requests
import zipfile
import io
import os
import json
import psycopg2
from dateutil.parser import parse as parse_date
import re
import time
import glob
import sys
from datetime import datetime
import traceback
import concurrent.futures
from functools import partial
from config import (
    PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD,
    OLLAMA_API_URL, OLLAMA_MODEL,
    ZIP_URL, EXTRACT_DIR,
    OS_CACHE_FILE, OS_REFERENCE_LIST, OS_ALIASES
)

original_print = print

# Terminal çıktılarını dosyaya da yazacak yeni print fonksiyonu
def custom_print(*args, **kwargs):
    # Önce orjinal print ile konsola yaz
    original_print(*args, **kwargs)
    
    # Ardından dosyaya yaz
    with open("terminal_log.txt", "a", encoding="utf-8") as log_file:
        # kwargs içinde file parametresi varsa çıkar
        file_kwargs = kwargs.copy()
        if 'file' in file_kwargs:
            del file_kwargs['file']
        original_print(*args, file=log_file, **file_kwargs)

print = custom_print
os_cache = {}

def load_cache():
    global os_cache
    try:
        if os.path.exists(OS_CACHE_FILE):
            with open(OS_CACHE_FILE, 'r', encoding='utf-8') as f:
                os_cache = json.load(f)
                print(f"✅ Loaded {len(os_cache)} OS mappings from cache")
        else:
            os_cache = {}
    except Exception as e:
        print(f"❌ Error loading cache: {e}")
        os_cache = {}

# Save cache to file
def save_cache():
    try:
        with open(OS_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(os_cache, f, indent=2)
            print(f"✅ Saved {len(os_cache)} OS mappings to cache")
    except Exception as e:
        print(f"❌ Error saving cache: {e}")

def normalize_os_name(os_name):
    """
    OS isimlerini normalize eder, bilinen kısaltmaları ve alternatifleri 
    standart formata dönüştürür
    """
    if not os_name:
        return os_name
    
    # Küçük harfe çevir
    lower_name = os_name.lower()
    
    # Önbellekten kontrol et
    if lower_name in os_cache:
        return os_cache[lower_name]
    
    # Kısaltma veya alternatif isim eşleştirmesi
    if lower_name in OS_ALIASES:
        result = OS_ALIASES[lower_name]
        os_cache[lower_name] = result
        return result
    
    # Red Hat Enterprise Linux varyasyonları
    if "red hat enterprise linux" in lower_name or "rhel" in lower_name:
        # Sürüm numarasını bul
        if "9" in lower_name:
            result = "Red Hat Enterprise Linux 9"
        elif "8" in lower_name:
            result = "Red Hat Enterprise Linux 8"
        elif "7" in lower_name:
            result = "Red Hat Enterprise Linux 7"
        else:
            result = "Red Hat Enterprise Linux"
        os_cache[lower_name] = result
        return result
    
    # Ubuntu varyasyonları
    if "ubuntu" in lower_name:
        # Sürüm numarasını bul
        for version in ["18.04", "18.10", "19.04", "19.10", "20.04", "20.10", 
                       "21.04", "21.10", "22.04", "22.10", "23.04", "23.10", "24.04"]:
            if version in lower_name:
                result = f"Ubuntu {version}"
                os_cache[lower_name] = result
                return result
        
    # Windows varyasyonları
    if "windows" in lower_name:
        if "server" in lower_name:
            for version in ["2008", "2008 r2", "2012", "2012 r2", "2016", "2019", "2022", "2025"]:
                if version in lower_name or version.replace(" ", "") in lower_name:
                    result = f"Windows Server {version.upper() if 'r2' in version else version}"
                    os_cache[lower_name] = result
                    return result
            result = "Windows Server"
        elif "11" in lower_name:
            result = "Windows 11"
        elif "10" in lower_name:
            result = "Windows 10"
        elif "8.1" in lower_name:
            result = "Windows 8.1"
        elif "7" in lower_name and not "200" in lower_name:  # Avoid confusing Windows 7 with Server 2007
            result = "Windows 7"
        else:
            result = "Windows"
        os_cache[lower_name] = result
        return result
    
    # CentOS varyasyonları
    if "centos" in lower_name:
        if "9" in lower_name:
            result = "CentOS 9"
        elif "8" in lower_name:
            result = "CentOS 8"
        elif "7" in lower_name:
            result = "CentOS 7"
        else:
            result = "CentOS"
        os_cache[lower_name] = result
        return result
    
    # Debian varyasyonları
    if "debian" in lower_name:
        if "12" in lower_name:
            result = "Debian 12"
        elif "11" in lower_name:
            result = "Debian 11"
        elif "10" in lower_name:
            result = "Debian 10"
        elif "9" in lower_name:
            result = "Debian 9"
        else:
            result = "Debian"
        os_cache[lower_name] = result
        return result
    
    # MacOS varyasyonları
    if "macos" in lower_name or "mac os" in lower_name:
        if "sonoma" in lower_name or "14" in lower_name:
            result = "MacOS 14 Sonoma"
        elif "ventura" in lower_name or "13" in lower_name:
            result = "MacOS 13 Ventura"
        elif "monterey" in lower_name or "12" in lower_name:
            result = "MacOS 12 Monterey"
        elif "big sur" in lower_name or "11" in lower_name:
            result = "MacOS 11 Big Sur"
        else:
            result = "MacOS"
        os_cache[lower_name] = result
        return result
    
    # Rocky Linux varyasyonları
    if "rocky" in lower_name:
        if "9" in lower_name:
            result = "Rocky Linux 9"
        elif "8" in lower_name:
            result = "Rocky Linux 8"
        else:
            result = "Rocky Linux"
        os_cache[lower_name] = result
        return result
    
    # SUSE varyasyonları
    if "suse" in lower_name or "sles" in lower_name:
        result = "SUSE 15"
        os_cache[lower_name] = result
        return result
    if os_name and os_name[0].islower():
        return os_name[0].upper() + os_name[1:]
    return os_name

def download_zip(url):
    """Downloads a ZIP file from URL and returns a BytesIO object."""
    print("Downloading ZIP file...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    return io.BytesIO(response.content)

def extract_zip(zip_bytes, extract_to):
    """Extracts ZIP file to the specified directory."""
    print("Extracting ZIP file...")
    with zipfile.ZipFile(zip_bytes) as z:
        z.extractall(extract_to)
    print(f"✅ Files extracted to '{extract_to}' directory.")

def extract_os_info(cve_data):
    """Extract OS information from various fields in the CVE data"""
    os_info = []
    
    # CVE JSON formatını doğru şekilde işle
    # Açıklama bilgilerini çıkar
    description = ""
    if isinstance(cve_data, dict) and "containers" in cve_data and "cna" in cve_data["containers"]:
        for desc in cve_data.get("containers", {}).get("cna", {}).get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                if description:
                    break
    
    # Affected kısmından platform bilgilerini çıkar
    affected_items = cve_data.get("containers", {}).get("cna", {}).get("affected", [])
    product = ""
    vendor = ""
    platforms = []
    versions = []
    
    for affected in affected_items:
        # Product bilgisi
        if "product" in affected:
            product = affected["product"]
            
        # Vendor bilgisi
        if "vendor" in affected:
            vendor = affected["vendor"]
            
        # Platform bilgileri
        if "platforms" in affected:
            platforms = affected["platforms"]
            
        # Version bilgileri
        if "versions" in affected:
            for ver in affected["versions"]:
                if "version" in ver and ver["version"] != "N/A":
                    versions.append(ver["version"])
    
    # 1. Açıklamadan OS bilgilerini çıkar
    if description:
        description_os = extract_os_from_text(description)
        if description_os:
            os_info.extend(description_os)
    
    # 2. Platform bilgilerinden çıkar
    if platforms:
        platform_str = json.dumps(platforms)
        platform_os = extract_os_from_text(platform_str)
        if platform_os:
            os_info.extend(platform_os)
    
    # 3. Product ve Vendor'dan çıkar
    if product:
        if "PAN-OS" in product:
            os_info.append("pan-os")
        elif "Linux" in product or "linux" in product.lower():
            os_info.append("linux")
        elif "Windows" in product:
            os_info.append("windows")
        elif "macOS" in product or "Mac OS" in product:
            os_info.append("macos")
        
        product_os = extract_os_from_text(product)
        if product_os:
            os_info.extend(product_os)
    
    if vendor:
        vendor_lower = vendor.lower()
        if "microsoft" in vendor_lower:
            os_info.append("windows")
        elif "apple" in vendor_lower:
            os_info.append("macos")
        elif "red hat" in vendor_lower or "redhat" in vendor_lower:
            os_info.append("red hat enterprise linux")
        elif "debian" in vendor_lower:
            os_info.append("debian")
        elif "ubuntu" in vendor_lower or "canonical" in vendor_lower:
            os_info.append("ubuntu")
        elif "centos" in vendor_lower:
            os_info.append("centos")
    
    # 4. Version bilgilerinden çıkar
    if versions:
        versions_str = ", ".join(versions)
        
        # Linux kernel version patterns
        kernel_version_pattern = r'\b\d+\.\d+(?:\.\d+)?\b'
        kernel_matches = re.findall(kernel_version_pattern, versions_str)
        
        if kernel_matches and ("Linux" in product or "linux" in product.lower() or "kernel" in description.lower()):
            os_info.append("linux")
            os_info.append("linux kernel")
            
            # Linux distros tahmin et
            if any(v.startswith('5.') for v in kernel_matches):
                os_info.extend(["Ubuntu 20.04", "Red Hat Enterprise Linux 8", "Debian 11"])
            if any(v.startswith('6.') for v in kernel_matches):
                os_info.extend(["Ubuntu 22.04", "Red Hat Enterprise Linux 9"])
    
    # Metinlerde özel durumlar
    # Linux Kernel CVEs
    if "kernel" in description.lower() or "Linux kernel" in description:
        os_info.append("linux")
        os_info.append("linux kernel")
        
        if "Linux kernel" in description or "linux kernel" in description.lower():
            os_info.extend([
                "Ubuntu 20.04", "Ubuntu 22.04", 
                "Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 9",
                "Debian 10", "Debian 11",
                "CentOS 7", "CentOS 8"
            ])
    
    # Android
    if "Android" in description or "android" in description.lower():
        os_info.append("android")

    # Windows
    if "Windows" in description or "windows" in description.lower():
        if "Windows 10" in description:
            os_info.append("Windows 10")
        elif "Windows 11" in description:
            os_info.append("Windows 11")
        elif "Windows Server" in description:
            os_info.append("Windows Server")
        else:
            os_info.append("windows")
    
    # RHEL kısaltması için
    if "RHEL" in description or "rhel" in description.lower():
        if "RHEL 9" in description or "rhel 9" in description.lower():
            os_info.append("rhel 9")
        elif "RHEL 8" in description or "rhel 8" in description.lower():
            os_info.append("rhel 8")
        elif "RHEL 7" in description or "rhel 7" in description.lower():
            os_info.append("rhel 7")
        else:
            os_info.append("rhel")
    
    # PAN-OS için
    if "PAN-OS" in description or "pan-os" in description.lower():
        os_info.append("pan-os")
        
    # SLES için
    if "SLES" in description or "sles" in description.lower() or "SUSE Linux Enterprise Server" in description:
        os_info.append("sles")
    
    # Benzersiz değerleri döndür
    return list(set(os_info))

def extract_os_from_text(text):
    """Extract potential OS mentions from text using regex patterns"""
    if not text:
        return []
    
    os_patterns = [
        # Windows patterns
        r'\bwindows\s+(?:\d+|server\s+\d+|server\s+\d+\s+r2)\b',
        r'\bwindows\s+(?:xp|vista|7|8|8\.1|10|11)\b',
        r'\bwin(?:dows)?\s*(?:xp|vista|7|8|8\.1|10|11)\b',
        r'\bwin(?:dows)?\s*server\b',
        
        # macOS patterns
        r'\bmacos\s+(?:\d+|[\w\s]+)\b',
        r'\bmac\s*os\s*(?:x|sierra|high sierra|mojave|catalina|big sur|monterey|ventura|sonoma)\b',
        r'\bos\s*x\b',
        
        # Linux distro patterns
        r'\bdebian\s+\d+(?:\.\d+)?\b',
        r'\bubuntu\s+\d+\.\d+(?:\.\d+)?\b',
        r'\bcentos\s+\d+(?:\.\d+)?\b',
        r'\bred\s*hat\s+enterprise\s+linux\s+\d+(?:\.\d+)?\b',
        r'\brhel\s+\d+(?:\.\d+)?\b',
        r'\brocky\s+linux\s+\d+(?:\.\d+)?\b',
        r'\bsuse\s+(?:linux|enterprise)?\s*\d+(?:\.\d+)?\b',
        r'\bfedora\s+\d+\b',
        
        # Common abbreviations
        r'\brhel\b',
        r'\bsles\b',
        
        # Special cases
        r'\bpan-os\b',
        r'\blinux\s*kernel\b',
        r'\bandroid\b'
    ]
    
    potential_os = []
    for pattern in os_patterns:
        matches = re.finditer(pattern, text.lower())
        for match in matches:
            potential_os.append(match.group(0))
    
    # Add extra checking for version patterns that follow OS mentions
    if "linux" in text.lower() or "kernel" in text.lower():
        # Look for version pattern like "5.10" or "6.1.91"
        kernel_version_pattern = r'\b(\d+\.\d+(?:\.\d+)?)\b'
        kernel_matches = re.findall(kernel_version_pattern, text)
        if kernel_matches:
            potential_os.append("linux")
            # Add versions to help with mapping
            for version in kernel_matches:
                major_version = version.split('.')[0]
                if major_version == "5":
                    potential_os.extend(["ubuntu 20.04", "debian 11", "red hat enterprise linux 8"])
                elif major_version == "6":
                    potential_os.extend(["ubuntu 22.04", "red hat enterprise linux 9"])
    
    return potential_os

def batch_process_os_names(os_list, model_name="llama2"):
    """
    Process a list of OS names in batch using Ollama API
    Returns a dictionary mapping original OS names to standardized names
    """
    print(f"Processing {len(os_list)} OS names for matching")
    
    print("Applying rule-based matching and checking cache...")
    rule_based_results = {}
    still_uncached = []
    
    for os_name in os_list:
        if os_name in os_cache:
            rule_based_results[os_name] = os_cache[os_name]
            continue
            
        # Rule-based normalize
        normalized = normalize_os_name(os_name)
        
        for ref_os in OS_REFERENCE_LIST:
            if normalized.lower() == ref_os.lower():
                rule_based_results[os_name] = ref_os
                os_cache[os_name] = ref_os
                break
        else:
            still_uncached.append(os_name)
    
    standardized_os = rule_based_results.copy()
    matched_count = len(rule_based_results)
    
    if not still_uncached:
        return standardized_os
    
    batch_size = 10  # Daha küçük batch boyutu
    batches = [still_uncached[i:i + batch_size] for i in range(0, len(still_uncached), batch_size)]
    
    max_workers = min(4, len(batches))
    

    reference_list_str = "\n".join(OS_REFERENCE_LIST)
    
    def process_batch(batch, batch_idx):
        """Tek bir batch'i işleyen fonksiyon"""
        print(f"Processing batch {batch_idx+1}/{len(batches)} ({len(batch)} OS names)")
        
        prompt = f"""
TASK: Match each input operating system name to the EXACT operating system from the reference list below.
If no exact match exists, return "NO_MATCH".

REFERENCE OS LIST:
{reference_list_str}

INPUT OS NAMES TO MATCH:
{", ".join(batch)}

INSTRUCTIONS:
1. Return matches in JSON format: {{"original_os": "matched_reference_os"}}
2. Use ONLY names from the reference list - no variations or modifications
3. If uncertain or no match exists, use "NO_MATCH"
4. Be strict with version numbers - they must match exactly
5. Include common abbreviations (e.g., "RHEL 8" matches to "Red Hat Enterprise Linux 8")

JSON RESULT:
"""
        
        # Ollama API'ye istek gönder
        start_time = time.time()
        
        response = requests.post(
            OLLAMA_API_URL,
            json={
                "model": model_name,
                "prompt": prompt,
                "stream": False
            }
        )
        
        end_time = time.time()
        batch_results = {}
        
        if response.status_code == 200:
            try:
                # Yanıttan JSON çıkar
                response_text = response.json().get("response", "")
                
                json_pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
                json_matches = re.findall(json_pattern, response_text, re.DOTALL)
                
                if json_matches:
                    json_str = json_matches[0]
                else:
                    json_pattern = r'({[\s\S]*?})'
                    json_matches = re.findall(json_pattern, response_text, re.DOTALL)
                    if json_matches:
                        json_str = json_matches[0]
                    else:
                       
                        print(f"⚠️ No JSON found in response for batch {batch_idx+1}")
                        print(f"Response text: {response_text[:200]}...")
                        return {}
                
                
                json_str = json_str.strip()
                def repair_json(json_str):
                    """Bozuk JSON string'i düzeltir (eksik virgüller, tırnak işaretleri, vb.)"""
                    fixed_str = re.sub(r'("[^"]+"\s*:\s*"[^"]*")\s*(")', r'\1,\2', json_str)
                    fixed_str = re.sub(r'("[^"]+"\s*:\s*"[^"]*")\s*}', r'\1}', fixed_str)
                    
                    # JSON içindeki gereksiz yorum ve boşlukları temizle
                    fixed_str = re.sub(r'//.*?\n', '\n', fixed_str)
                    fixed_str = re.sub(r'/\*.*?\*/', '', fixed_str, flags=re.DOTALL)
                    
                    # Fazladan virgülleri temizle (son öğeden sonra)
                    fixed_str = re.sub(r',\s*}', '}', fixed_str)
                    fixed_str = re.sub(r',\s*]', ']', fixed_str)
                    
                    return fixed_str
                
                try:
                    batch_results = json.loads(json_str)
                except json.JSONDecodeError as e:
                    print(f"⚠️ JSON parsing error in first attempt: {e}")
                    print(f"Attempting to repair and parse JSON for batch {batch_idx+1}")
                    
                    repaired_json = repair_json(json_str)
                    
                    try:
                        batch_results = json.loads(repaired_json)
                        print(f"✅ Successfully parsed JSON after repair")
                    except json.JSONDecodeError as e2:
                        print(f"❌ JSON repair failed: {e2}")
                        
                        start_idx = json_str.find('{')
                        end_idx = json_str.rfind('}') + 1
                        
                        if start_idx >= 0 and end_idx > start_idx:
                            try:
                                print("📝 Attempting manual JSON construction")
                                manual_json = {}
                                
                                pairs = re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', json_str)
                                if pairs:
                                    for key, value in pairs:
                                        manual_json[key] = value
                                    
                                    if manual_json:
                                        batch_results = manual_json
                                        print(f"✅ Successfully extracted {len(manual_json)} key-value pairs manually")
                                    else:
                                        print(f"❌ Manual extraction found no valid pairs")
                                        print(f"Problem JSON string: {json_str[:150]}...")
                                        return {}
                                else:
                                    print(f"❌ Could not find key-value pairs for manual extraction")
                                    print(f"Problem JSON string: {json_str[:150]}...")
                                    return {}
                                
                            except Exception as e3:
                                print(f"❌ Manual JSON construction failed: {e3}")
                                print(f"Problem JSON string: {json_str[:150]}...")
                                return {}
                        else:
                            print(f"❌ Could not find valid JSON structure")
                            return {}
                
                # Sonuçları doğrula - referans listesinde olmayan eşleşmeler "NO_MATCH" olmalı
                for original, matched in list(batch_results.items()):
                    if matched != "NO_MATCH" and matched not in OS_REFERENCE_LIST:
                        print(f"⚠️ Invalid match: '{matched}' not in reference list. Setting to NO_MATCH.")
                        batch_results[original] = "NO_MATCH"
            except Exception as e:
                print(f"❌ Error processing batch {batch_idx+1}: {e}")
                # Hata detaylarını logla
                print(f"Response status: {response.status_code}")
                print(f"Response preview: {response.text[:200]}...")
                # Hata durumunda boş sonuç döndür
                return {}
        else:
            print(f"❌ Ollama API error: {response.status_code}")
            if response.text:
                print(f"Error details: {response.text[:200]}...")
            
        print(f"✅ Batch {batch_idx+1} processed in {end_time - start_time:.2f} seconds")
        return batch_results
    
    all_batch_results = {}
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_batch = {
                executor.submit(process_batch, batch, i): i 
                for i, batch in enumerate(batches)
            }
            
            for future in concurrent.futures.as_completed(future_to_batch):
                batch_idx = future_to_batch[future]
                try:
                    batch_results = future.result()
                    all_batch_results.update(batch_results)
                except Exception as e:
                    print(f"❌ Error in batch {batch_idx}: {e}")
    except Exception as e:
        print(f"❌ Error in parallel processing: {e}")
    
    # Sonuçları işle
    for original, matched in all_batch_results.items():
        # "NO_MATCH" olanları None olarak kaydet
        value = None if matched == "NO_MATCH" else matched
        standardized_os[original] = value
        os_cache[original] = value
    
    # Önbelleği kaydet
    save_cache()
    
    final_matched = sum(1 for v in standardized_os.values() if v is not None)
    print(f"✅ Total OS matches: {final_matched}/{len(os_list)} ({final_matched/len(os_list)*100:.1f}%)")
    
    return standardized_os

def match_os_with_llm(extracted_os_list):
    """LLM kullanarak OS isimlerini standartlaştır"""
    if not extracted_os_list:
        return [], extracted_os_list
    
    # Önbelleği yükle
    if not os_cache:
        load_cache()
    
    print(f"🔍 Starting OS matching for {len(extracted_os_list)} unique OS names")
    
    # Tekrarlayan girdileri kaldır
    unique_os_names = list(set(extracted_os_list))
    print(f"🔍 Processing {len(unique_os_names)} unique OS names after removing duplicates")
    
    # Batch processing ile toplu işleme yap
    standardized_results = batch_process_os_names(unique_os_names)
    
    # Eşleşen ve eşleşmeyen listeleri ayır
    matched_os = []
    unmatched_os = []
    
    for os_name in extracted_os_list:
        standard_name = standardized_results.get(os_name)
        if standard_name:
            matched_os.append({
                "original": os_name,
                "matched": standard_name
            })
        else:
            unmatched_os.append(os_name)
    
    if matched_os:
        print(f"✅ Matched OS examples: {[m['matched'] for m in matched_os[:5]]}")
    if unmatched_os:
        print(f"⚠️ Unmatched OS examples: {unmatched_os[:5]}")
    
    return matched_os, unmatched_os

def process_cve_files(extract_dir):
    """Process all CVE JSON files in the extracted directory"""
    cve_data_list = []

    linux_kernel_cves = []
    windows_cves = []
    other_os_cves = []
    
    all_os_strings = set()
    cve_os_mapping = {}
    
    try:
        print(f"🔍 Scanning all CVE files in {extract_dir} (2024)")
        
        # JSON dosyalarını bul - tüm alt klasörlerdeki tüm JSON dosyalarını tara
        json_pattern = os.path.join(extract_dir, "**", "*.json")
        json_files = glob.glob(json_pattern, recursive=True)
        
        # Dosyaları işle
        total_files = len(json_files)
        processed_files = 0
        processed_cves = 0

        import time
        start_time = time.time()

        print(f"📋 Found {total_files} JSON files in 2024 data")
        print(f"⏱️ Starting process at {time.strftime('%H:%M:%S')}")

        # İlk tarama döngüsüne ilerleme göstergesi ekle
        for json_file in json_files:
            processed_files += 1
            
            # Her 10 dosyada bir ilerleme durumunu göster
            if processed_files % 10 == 0:
                elapsed = time.time() - start_time
                estimated_total = (elapsed / processed_files) * total_files
                remaining = estimated_total - elapsed
                print(f"⏳ Processing file {processed_files}/{total_files} ({processed_files/total_files*100:.1f}%) - Est. remaining: {remaining/60:.1f} min")
            
            try:
                with open(json_file, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                
                # Dosyadaki CVE kaydını çıkar
                if 'cveMetadata' in data and 'cveId' in data['cveMetadata']:
                    cve_id = data['cveMetadata']['cve_id'] if 'cve_id' in data['cveMetadata'] else data['cveMetadata']['cveId']
                    
                    # Açıklama ve diğer bilgileri çıkar
                    description = ""
                    if 'containers' in data and 'cna' in data['containers'] and 'descriptions' in data['containers']['cna']:
                        for desc in data['containers']['cna']['descriptions']:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                    
                    # OS bilgilerini çıkar
                    extracted_os = extract_os_info(data)
                    
                    # OS bilgilerini koleksiyona ekle
                    if extracted_os:
                        all_os_strings.update(extracted_os)
                        cve_os_mapping[cve_id] = extracted_os
                    
                    # CVE'yi uygun kategoriye ekle
                    if any(kw in description.lower() for kw in ["linux kernel", "kernel", "linux driver"]):
                        linux_kernel_cves.append((cve_id, json_file, description))
                    elif "windows" in description.lower():
                        windows_cves.append((cve_id, json_file, description))
                    else:
                        other_os_cves.append((cve_id, json_file, description))
            
            except json.JSONDecodeError:
                print(f"⚠️ Invalid JSON in file: {json_file}")
                continue
            except Exception as e:
                print(f"⚠️ Error processing file {json_file}: {e}")
                continue
        
        print(f"Scanned {processed_files} files")
        print(f"Found {len(linux_kernel_cves)} Linux kernel CVEs")
        print(f"Found {len(windows_cves)} Windows CVEs")
        print(f"Found {len(other_os_cves)} other CVEs")
        
        # Benzersiz OS isimlerini toplu işleyelim
        print(f"Processing {len(all_os_strings)} unique OS strings in batch")
        all_os_list = list(all_os_strings)
        standardized_os_results = batch_process_os_names(all_os_list)
        cve_records_to_process = []
        
        for cve_id, json_file, description in linux_kernel_cves:
            cve_records_to_process.append((cve_id, json_file, description))
        for cve_id, json_file, description in windows_cves:
            cve_records_to_process.append((cve_id, json_file, description))
        for cve_id, json_file, description in other_os_cves:
            cve_records_to_process.append((cve_id, json_file, description))
        
        print(f"🔍 Processing a total of {len(cve_records_to_process)} CVE records...")
        
        # Şimdi belirlenen CVE'leri işleyelim
        for cve_id, json_file, description in cve_records_to_process:
            try:
                with open(json_file, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                
                # Vuln_status bilgisini çıkar
                vuln_status = data['cveMetadata']['state'] if 'state' in data['cveMetadata'] else ""
                
                # Tarih bilgilerini çıkar
                published_date = None
                last_modified_date = None
                
                if 'datePublished' in data['cveMetadata']:
                    published_date = parse_date(data['cveMetadata']['datePublished'])
                
                if 'dateUpdated' in data['cveMetadata']:
                    last_modified_date = parse_date(data['cveMetadata']['dateUpdated'])
                
                # CVSS skorlarını çıkar
                cvss_v2 = None
                cvss_v3_0 = None
                cvss_v3_1 = None
                cvss_v4_0 = None
                
                if 'containers' in data and 'cna' in data['containers'] and 'metrics' in data['containers']['cna']:
                    for metric in data['containers']['cna']['metrics']:
                        if 'cvssV2' in metric:
                            cvss_v2 = metric['cvssV2'].get('baseScore')
                        if 'cvssV3_0' in metric:
                            cvss_v3_0 = metric['cvssV3_0'].get('baseScore')
                        if 'cvssV3_1' in metric:
                            cvss_v3_1 = metric['cvssV3_1'].get('baseScore')
                        if 'cvssV4_0' in metric:
                            cvss_v4_0 = metric['cvssV4_0'].get('baseScore')
                
                # Ürün ve tedarikçi bilgilerini çıkar
                product = None
                vendor = None
                platforms = None
                versions = None
                
                if 'containers' in data and 'cna' in data['containers'] and 'affected' in data['containers']['cna']:
                    for affected in data['containers']['cna']['affected']:
                        product = affected.get('product')
                        vendor = affected.get('vendor')
                        platforms = json.dumps(affected.get('platforms')) if 'platforms' in affected else None
                        
                        if 'versions' in affected:
                            version_info = []
                            for ver in affected['versions']:
                                if 'version' in ver and ver['version'] != 'N/A':
                                    version_info.append(ver['version'])
                            
                            if version_info:
                                versions = ', '.join(version_info)
                
                # OS bilgilerini hazır eşleştirmeden al
                extracted_os = cve_os_mapping.get(cve_id, [])
                
                # Eşleşen ve eşleşmeyen OS listelerini hazırla
                matched_os = []
                unmatched_os = []
                
                for os_string in extracted_os:
                    standard_name = standardized_os_results.get(os_string, "")
                    if standard_name:
                        matched_os.append({
                            "original": os_string,
                            "matched": standard_name
                        })
                    else:
                        unmatched_os.append(os_string)
                
                # CVE kaydını oluştur
                cve_entry = {
                    "cve_id": cve_id,
                    "description": description,
                    "vuln_status": vuln_status,
                    "published_date": published_date,
                    "last_modified_date": last_modified_date,
                    "cvss_v2": cvss_v2,
                    "cvss_v3_0": cvss_v3_0,
                    "cvss_v3_1": cvss_v3_1,
                    "cvss_v4_0": cvss_v4_0,
                    "product": product,
                    "vendor": vendor,
                    "platforms": platforms,
                    "versions": versions,
                    "matched_os": matched_os,
                    "unmatched_os": unmatched_os
                }
                
                print(f"DEBUG - Description: {description[:50]}...")
                print(f"DEBUG - Created CVE entry: {cve_id}")
                print(f"DEBUG - Found OS information for {cve_id}: {extracted_os}")
                print(f"DEBUG - Matched OS: {[m['matched'] for m in matched_os]}")
                print(f"DEBUG - Unmatched OS: {unmatched_os}")
                
                cve_data_list.append(cve_entry)
                processed_cves += 1
                
                print(f"Record {processed_cves}: {cve_id} | Description: {description[:50]}...")
            
            except Exception as e:
                print(f"Error processing CVE {cve_id}: {e}")
                continue
    
    except Exception as e:
        print(f"Error during CVE processing: {e}")
    
    print(f"Total {processed_cves} CVE records processed.")
    print(f"Total {len(cve_data_list)} CVE entries added to list.")
    print(f"Final cve_data_list size: {len(cve_data_list)}")
    
    return cve_data_list

def setup_database():
    """Set up database schema with tables for CVE records and OS matches"""
    try:
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
        cur = conn.cursor()

        # Create main CVE records table
        create_cve_table = """
        CREATE TABLE IF NOT EXISTS cve_records (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) UNIQUE,
            description TEXT,
            vuln_status VARCHAR(50),
            published_date TIMESTAMP,
            last_modified_date TIMESTAMP,
            cvss_v2 REAL,
            cvss_v3_0 REAL,
            cvss_v3_1 REAL,
            cvss_v4_0 REAL,
            product TEXT,
            vendor TEXT,
            platforms TEXT,
            versions TEXT
        );
        """
        
        # Create OS reference table
        create_os_ref_table = """
        CREATE TABLE IF NOT EXISTS os_reference (
            id SERIAL PRIMARY KEY,
            os_name VARCHAR(100) UNIQUE
        );
        """
        
        # Create matched OS table (normalized)
        create_matched_os_table = """
        CREATE TABLE IF NOT EXISTS matched_os (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) REFERENCES cve_records(cve_id),
            os_id INTEGER REFERENCES os_reference(id),
            original_text VARCHAR(255)
        );
        """
        
        # Create unmatched OS table
        create_unmatched_os_table = """
        CREATE TABLE IF NOT EXISTS unmatched_os (
            id SERIAL PRIMARY KEY,
            cve_id VARCHAR(50) REFERENCES cve_records(cve_id),
            original_text VARCHAR(255)
        );
        """
        
        cur.execute(create_cve_table)
        cur.execute(create_os_ref_table)
        cur.execute(create_matched_os_table)
        cur.execute(create_unmatched_os_table)
        
        # Populate OS reference table with the reference list
        for os_name in OS_REFERENCE_LIST:
            cur.execute(
                "INSERT INTO os_reference (os_name) VALUES (%s) ON CONFLICT (os_name) DO NOTHING;",
                (os_name,)
            )
        
        conn.commit()
        print("✅ Database schema created successfully.")
        
        # Verify tables created correctly
        print("🔍 Verifying database tables...")
        cur.execute("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public';")
        tables = cur.fetchall()
        print(f"📊 Tables found: {tables}")
        
        cur.close()
        conn.close()
    except Exception as e:
        print(f"❌ ERROR setting up database: {e}")
        return None, None  # Hata durumunda None değerleri dön
    
    return conn, cur  # Başarı durumunda bağlantı ve cursor döndür

def insert_into_postgres(cve_data_list):
    """Insert data into PostgreSQL database using the normalized schema."""
    print("🔗 Connecting to PostgreSQL database...")
    
    if not cve_data_list:
        print("❌ No CVE data to insert!")
        return
    
    try:
        # Set up database schema first
        conn, cur = setup_database()
        
        if not conn or not cur:
            print("❌ Database connection failed!")
            return
        
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
        cur = conn.cursor()
        
        print("🔍 Testing basic database insertion...")
        cur.execute("INSERT INTO os_reference (os_name) VALUES ('TEST_OS') ON CONFLICT (os_name) DO NOTHING RETURNING id;")
        test_result = cur.fetchone()
        print(f"📊 Test insertion result: {test_result}")
        conn.commit()

        insert_cve_query = """
        INSERT INTO cve_records (
            cve_id, description, vuln_status, published_date, last_modified_date,
            cvss_v2, cvss_v3_0, cvss_v3_1, cvss_v4_0,
            product, vendor, platforms, versions
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (cve_id) DO NOTHING
        RETURNING id;
        """

        inserted_count = 0
        for i, entry in enumerate(cve_data_list):
            # Insert CVE record
            try:
                print(f"DEBUG - Inserting CVE #{i+1}: {entry['cve_id']}")
                # Check if cve_id is valid (not None or empty)
                if not entry['cve_id']:
                    print(f"WARNING: Skipping entry with empty CVE ID: {entry}")
                    continue
                
                # Print actual values being inserted
                print(f"DEBUG - Insertion values: {(entry['cve_id'], entry['description'][:50] if entry['description'] else None, entry['vuln_status'], entry['published_date'], entry['last_modified_date'], entry['cvss_v2'], entry['cvss_v3_0'], entry['cvss_v3_1'], entry['cvss_v4_0'], entry['product'], entry['vendor'], entry['platforms'], entry['versions'])}")
                
                cur.execute(insert_cve_query, (
                    entry["cve_id"],
                    entry["description"],
                    entry["vuln_status"],
                    entry["published_date"],
                    entry["last_modified_date"],
                    entry["cvss_v2"],
                    entry["cvss_v3_0"],
                    entry["cvss_v3_1"],
                    entry["cvss_v4_0"],
                    entry["product"],
                    entry["vendor"],
                    entry["platforms"],
                    entry["versions"]
                ))
                result = cur.fetchone()
                
                if result:  # If the record was inserted (not a duplicate)
                    inserted_count += 1
                    print(f"DEBUG - Record inserted with ID: {result[0]}")
                    
                    # Insert matched OS records
                    for matched in entry.get("matched_os", []):
                        # Get OS reference ID
                        cur.execute("SELECT id FROM os_reference WHERE os_name = %s", (matched["matched"],))
                        os_ref = cur.fetchone()
                        if os_ref:
                            os_id = os_ref[0]
                            cur.execute(
                                "INSERT INTO matched_os (cve_id, os_id, original_text) VALUES (%s, %s, %s) RETURNING id;",
                                (entry["cve_id"], os_id, matched["original"])
                            )
                            match_result = cur.fetchone()
                            print(f"DEBUG - Inserted matched OS: {matched['matched']}, ID: {match_result[0] if match_result else 'None'}")
                    
                    # Insert unmatched OS records
                    for unmatched in entry.get("unmatched_os", []):
                        cur.execute(
                            "INSERT INTO unmatched_os (cve_id, original_text) VALUES (%s, %s) RETURNING id;",
                            (entry["cve_id"], unmatched)
                        )
                        unmatch_result = cur.fetchone()
                        print(f"DEBUG - Inserted unmatched OS: {unmatched}, ID: {unmatch_result[0] if unmatch_result else 'None'}")
                else:
                    print(f"DEBUG - Record already exists: {entry['cve_id']}")
                
                # Commit after each record to ensure data is saved
                conn.commit()
                
            except Exception as e:
                print(f"ERROR inserting {entry.get('cve_id', 'unknown')}: {e}")
                conn.rollback()  # Rollback the transaction in case of error

        # Final commit
        conn.commit()
        
        # Query the database to verify inserted records
        print("Verifying CVE records...")
        cur.execute("SELECT COUNT(*) FROM cve_records;")
        total_records = cur.fetchone()[0]
        print(f"Total records in database: {total_records}")
        
        print("Verifying unmatched OS records...")
        cur.execute("SELECT COUNT(*) FROM unmatched_os;")
        unmatched_count = cur.fetchone()[0]
        print(f"Total unmatched OS records: {unmatched_count}")
        
        print("Verifying matched OS records...")
        cur.execute("SELECT COUNT(*) FROM matched_os;")
        matched_count = cur.fetchone()[0]
        print(f"Total matched OS records: {matched_count}")
        
        print(f"{inserted_count} records inserted into database.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"ERROR with database operations: {e}")
        # Hata durumunda cursor ve connection'ı kontrol et ve kapat
        try:
            if cur and not cur.closed:
                cur.close()
            if conn and not conn.closed:
                conn.close()
        except Exception as close_error:
            print(f"ERROR closing connection: {close_error}")

def main():
    """Main function to run the CVE data processing pipeline"""
    
    try:
        # Log dosyasını sıfırla
        with open("terminal_log.txt", "w", encoding="utf-8") as log_file:
            log_file.write("=== CVE Data Processing Log ===\n")
            log_file.write(f"Çalışma Başlangıç Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Cache'i yükle
        load_cache()
        
        # Veri indirme ve çıkarma adımlarını atlıyoruz, zaten mevcut olan klasörü kullanacağız
        # print("Downloading ZIP file...")
        zip_data = download_zip(ZIP_URL)
        
        # print("Extracting ZIP file...")
        extract_dir = "cvelist_extracted"
        extract_zip(zip_data, extract_dir)
        print(f"Using existing files from '{extract_dir}' directory.")
        
        year_2024_dir = os.path.join(extract_dir, "cvelistV5-main", "cves", "2024")
        if not os.path.exists(year_2024_dir):
            print(f"ERROR: 2024 CVE directory not found! Expected at: {year_2024_dir}")
            return
        
        print(f"Processing only 2024 CVEs from: {year_2024_dir}")
        cve_data = process_cve_files(year_2024_dir)
        
        print(f"DEBUG - After processing, cve_data has {len(cve_data)} entries")
        
        # Cache'i kaydet
        save_cache()
        
        # Setup and connect to PostgreSQL database
        print("Connecting to PostgreSQL database...")
        try:
            conn, cur = setup_database()
            if conn and cur:
                insert_into_postgres(cve_data)
            else:
                print("Could not establish database connection. Check your PostgreSQL configuration.")
        except Exception as db_error:
            print(f"Database error: {db_error}")
            print("Continuing without database operations...")
        
        # Log dosyasına tamamlandı bilgisi ekle
        with open("terminal_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"\nÇalışma Bitiş Zamanı: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_file.write("=== İşlem Tamamlandı ===\n")
    except Exception as e:
        print(f"ERROR in main process: {e}")
        traceback.print_exc()
        
        # Hata detaylarını log dosyasına da yaz
        with open("terminal_log.txt", "a", encoding="utf-8") as log_file:
            log_file.write(f"\nERROR in main process: {e}\n")
            traceback.print_exc(file=log_file)
            log_file.write("\n=== Hata ile Sonlandı ===\n")

if __name__ == "__main__":
    main()
