import psycopg2
import json
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

def check_os_records():
    """OS kayıtlarını kontrol et ve göster"""
    conn = connect_to_db()
    if not conn:
        return
    
    try:
        cur = conn.cursor()
        
        print("\n=== OS REFERENCE LIST ===")
        cur.execute("SELECT id, os_name FROM os_reference ORDER BY os_name;")
        os_refs = cur.fetchall()
        for os_id, os_name in os_refs:
            print(f"ID: {os_id} - OS: {os_name}")
        
        print("\n=== MATCHED OS RECORDS (SAMPLE) ===")
        cur.execute("""
            SELECT m.cve_id, r.os_name, m.original_text 
            FROM matched_os m
            JOIN os_reference r ON m.os_id = r.id
            ORDER BY m.cve_id
            LIMIT 20;
        """)
        matched = cur.fetchall()
        for cve_id, os_name, original_text in matched:
            print(f"CVE: {cve_id} | Original: {original_text} | Matched: {os_name}")
        
        print("\n=== OS MATCH COUNTS ===")
        cur.execute("""
            SELECT r.os_name, COUNT(m.id) as count 
            FROM matched_os m
            JOIN os_reference r ON m.os_id = r.id
            GROUP BY r.os_name
            ORDER BY count DESC;
        """)
        os_counts = cur.fetchall()
        for os_name, count in os_counts:
            print(f"{os_name}: {count} matches")
        
        print("\n=== UNMATCHED OS RECORDS (SAMPLE) ===")
        cur.execute("""
            SELECT cve_id, original_text 
            FROM unmatched_os
            ORDER BY cve_id
            LIMIT 20;
        """)
        unmatched = cur.fetchall()
        for cve_id, original_text in unmatched:
            print(f"CVE: {cve_id} | Unmatched: {original_text}")
        
        print("\n=== UNIQUE UNMATCHED OS NAMES ===")
        cur.execute("""
            SELECT original_text, COUNT(*) as count
            FROM unmatched_os
            GROUP BY original_text
            ORDER BY count DESC;
        """)
        unmatched_counts = cur.fetchall()
        for os_name, count in unmatched_counts:
            print(f"{os_name}: {count} occurrences")
            
        print("\n=== OS MATCHING SUMMARY ===")
        cur.execute("SELECT COUNT(*) FROM matched_os;")
        matched_count = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM unmatched_os;")
        unmatched_count = cur.fetchone()[0]
        
        total_os_mentions = matched_count + unmatched_count
        match_percentage = (matched_count / total_os_mentions) * 100 if total_os_mentions > 0 else 0
        
        print(f"Total OS mentions: {total_os_mentions}")
        print(f"Matched OS records: {matched_count} ({match_percentage:.2f}%)")
        print(f"Unmatched OS records: {unmatched_count} ({100-match_percentage:.2f}%)")
        
        with open("os_records_report.txt", "w", encoding="utf-8") as f:
            f.write("=== OS MATCHING REPORT ===\n\n")
            
            f.write("=== OS MATCH COUNTS ===\n")
            for os_name, count in os_counts:
                f.write(f"{os_name}: {count} matches\n")
            
            f.write("\n=== UNIQUE UNMATCHED OS NAMES ===\n")
            for os_name, count in unmatched_counts:
                f.write(f"{os_name}: {count} occurrences\n")
            
            f.write("\n=== OS MATCHING SUMMARY ===\n")
            f.write(f"Total OS mentions: {total_os_mentions}\n")
            f.write(f"Matched OS records: {matched_count} ({match_percentage:.2f}%)\n")
            f.write(f"Unmatched OS records: {unmatched_count} ({100-match_percentage:.2f}%)\n")
        
        print(f"\nDetaylı rapor 'os_records_report.txt' dosyasına kaydedildi.")
        
    except Exception as e:
        print(f"Sorgu hatası: {e}")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    check_os_records() 