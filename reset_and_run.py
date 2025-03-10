import psycopg2
import os
import time
import subprocess
from config import PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD

def connect_to_db():
    """Veritabanına bağlan"""
    try:
        conn = psycopg2.connect(
            host=PG_HOST,
            port=PG_PORT,
            dbname=PG_DATABASE,
            user=PG_USER,
            password=PG_PASSWORD
        )
        return conn
    except Exception as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        return None

def reset_database():
    """Veritabanındaki tabloları sil"""
    conn = connect_to_db()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        
        print("Veritabanı tabloları siliniyor...")
        cur.execute("DROP TABLE IF EXISTS matched_os CASCADE;")
        cur.execute("DROP TABLE IF EXISTS unmatched_os CASCADE;")
        cur.execute("DROP TABLE IF EXISTS os_reference CASCADE;")
        cur.execute("DROP TABLE IF EXISTS cve_records CASCADE;")
        
        conn.commit()
        print("Veritabanı tabloları başarıyla silindi.")
        
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Veritabanı sıfırlama hatası: {e}")
        return False

def run_main_code():
    """Data_Engineer_Business_Case.py kodunu çalıştır"""
    print("\nData_Engineer_Business_Case.py çalıştırılıyor...\n")
    
    # İşlem başlangıç zamanı
    start_time = time.time()
    
    # Ana kodu çalıştır
    try:
        subprocess.run(["python", "Data_Engineer_Business_Case.py"], check=True)
        
        # İşlem bitiş zamanı ve toplam süre
        end_time = time.time()
        duration = end_time - start_time
        print(f"\nİşlem tamamlandı. Toplam süre: {duration:.2f} saniye ({duration/60:.2f} dakika)")
        
        # OS eşleştirme raporunu göster
        print("\nOS eşleştirme raporu oluşturuluyor...")
        subprocess.run(["python", "check_os_records.py"], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"Kod çalıştırma hatası: {e}")
    except Exception as e:
        print(f"Beklenmeyen hata: {e}")

if __name__ == "__main__":
    # Kullanıcı onayı al
    print("DİKKAT: Bu işlem veritabanını sıfırlayacak ve tüm verileri sıfırdan işleyecektir.")
    confirm = input("Devam etmek istiyor musunuz? (e/h): ")
    
    if confirm.lower() == 'e':
        # Veritabanını sıfırla
        if reset_database():
            # Ana kodu çalıştır
            run_main_code()
    else:
        print("İşlem iptal edildi.") 