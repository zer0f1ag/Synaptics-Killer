import os
import sys
import time
import shutil
import psutil
import pefile
from oletools.olevba import VBA_Parser
from openpyxl import load_workbook
from datetime import datetime
import winreg as reg

# =========================
# 설정
# =========================

TARGET_DESC = "Synaptics Pointing Device Driver"
RESOURCE_NAME = "EXERESX"

SCAN_DIRS = [
    os.path.join(os.environ["USERPROFILE"], "Desktop"),
    os.path.join(os.environ["USERPROFILE"], "Documents"),
    os.path.join(os.environ["USERPROFILE"], "Downloads"),
]

LOG_FILE = "infected_files.log"
REPORT_FILE = "report.txt"
target_processes = ['Synaptics.exe', 'EXCEL.EXE']
RECOVERED_FILES = []  # (원본 파일, recovered 파일)
CLEANED_XLSM_FILES = []  # (원본 xlsm, clean 파일)

# =========================
# 유틸
# =========================

def log(msg):
    print(msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def safe_rename(src, dst):
    for _ in range(3):
        try:
            if os.path.exists(dst):
                os.remove(dst)
            os.rename(src, dst)
            return True
        except PermissionError:
            time.sleep(1)
    return False


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def typewriter_centered(text, width=70, delay=0.05):
    text_length = len(text)
    padding = (width - text_length) // 2
    sys.stdout.write(" " * padding)
    sys.stdout.flush()
    
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print() 


def show_banner_vertical(delay=0.1):
    banner = r"""
   _____                         _   _                 _  ___ _ _           
  / ____|                       | | (_)               | |/ (_) | |          
 | (___  _   _ _ __   __ _ _ __ | |_ _  ___ ___ ______| ' / _| | | ___ _ __ 
  \___ \| | | | '_ \ / _` | '_ \| __| |/ __/ __|______|  < | | | |/ _ \ '__|
  ____) | |_| | | | | (_| | |_) | |_| | (__\__ \      | . \| | | |  __/ |   
 |_____/ \__, |_| |_|\__,_| .__/ \__|_|\___|___/      |_|\_\_|_|_|\___|_|   
          __/ |           | |                                               
         |___/            |_|                                               

         
""".strip("\n")

    lines = banner.splitlines()
    
    for line in lines:
        print(line)     
        time.sleep(delay)  

    nickname = "\033[92mDeveloped by: zer0f1ag\033[0m"
    typewriter_centered(nickname, width=70, delay=0.05)


def show_menu():
    print("\n")
    print("[1] Restore without creating .bak file")
    print("[2] Restore with creating .bak file")
    print("[3] Exit")
    print()

# =========================
# EXE 복구
# =========================

def get_file_description(pe):
    try:
        for fileinfo in pe.FileInfo:
            for entry in fileinfo:
                if entry.Key == b"StringFileInfo":
                    for st in entry.StringTable:
                        return st.entries.get(b"FileDescription", b"").decode(errors="ignore")
    except Exception:
        pass
    return None

def extract_exeresx_recursive(entry, pe, out_path):
    try:
        if hasattr(entry, "directory") and entry.directory:
            for sub in entry.directory.entries:
                if extract_exeresx_recursive(sub, pe, out_path):
                    return True
        elif hasattr(entry, "data") and entry.data:
            data_rva = entry.data.struct.OffsetToData
            size = entry.data.struct.Size
            data = pe.get_data(data_rva, size)
            if data[:2] != b'MZ':
                log("    [-] EXERESX is not a valid EXE")
                return False
            with open(out_path, "wb") as f:
                f.write(data)
            return True
    except Exception as e:
        log(f"    [-] Exception in extract_exeresx_recursive: {e}")
    return False

def extract_exeresx(pe, out_path):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        log("[-] No resource section")
        return False

    RCData_ID = pefile.RESOURCE_TYPE.get('RCData', 10)

    try:
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            name = entry.name.string if entry.name else ""
            if RESOURCE_NAME.lower() in name.lower() or entry.struct.Id == RCData_ID:
                if extract_exeresx_recursive(entry, pe, out_path):
                    log(f"[RECOVERED EXE] EXERESX extracted -> {out_path}")
                    return True
    except Exception as e:
        log(f"    [-] Exception in extract_exeresx: {e}")

    log("[-] EXERESX not found")
    return False

def recover_exe(path):
    log(f"[CHECK EXE] {path}")

    try:
        pe = pefile.PE(path)
    except Exception as e:
        log(f"    [-] PE load failed: {e}")
        return

    desc = get_file_description(pe)
    if not desc or "Synaptics" not in desc:
        log("    [SKIP] Not Synaptics")
        pe.close()
        return

    log(f"    [DESC] {desc}")
    recovered_path = path + ".recovered.exe"
    if extract_exeresx(pe, recovered_path):
        RECOVERED_FILES.append((path, recovered_path))
        log(f"[SUCCESS] Recovered EXE scheduled -> {recovered_path}")
    else:
        log("    [-] Recovery failed")
    pe.close() 

# =========================
# XLSM 복구
# =========================

def is_malicious_xlsm(path):
    try:
        vbaparser = VBA_Parser(path)
        if vbaparser.detect_vba_macros():
            log(f"[VBA FOUND] {path}")
            return True
    except Exception as e:
        log(f"    [-] VBA check error: {e}")
    return False

def clean_xlsm(path):
    try:
        wb = load_workbook(path, keep_vba=False)
        cleaned_path = path.replace(".xlsm", "_clean.xlsx")
        wb.save(cleaned_path)
        wb.close() 
        CLEANED_XLSM_FILES.append((path, cleaned_path))
        log(f"[RECOVERED XLSM] Scheduled -> {cleaned_path}")
    except Exception as e:
        log(f"    [-] XLSM recovery failed: {e}")

# =========================
# 스캔
# =========================

def scan():
    found_any = False
    for base in SCAN_DIRS:
        log(f"\n[SCAN DIR] {base}")
        if not os.path.exists(base):
            continue
        for root, _, files in os.walk(base):
            for file in files:
                full = os.path.join(root, file)
                if file.lower().endswith(".exe"):
                    found_any = True
                    recover_exe(full)
                elif file.lower().endswith(".xlsm"):
                    found_any = True
                    if is_malicious_xlsm(full):
                        clean_xlsm(full)
    if not found_any:
        log("[!] No EXE or XLSM files found")

# =========================
# 덮어쓰기
# =========================

def replace_files(no_bak=False):
    # ====== EXE 파일 처리 ======
    for original, recovered in RECOVERED_FILES:
        try:
            if no_bak:
                if os.path.exists(original):
                    os.remove(original)
                    log(f"[NO BACKUP] Removed original file -> {original}")
                if safe_rename(recovered, original):
                    log(f"[REPLACED] {recovered} -> {original}")
                else:
                    log(f"    [-] Replace failed for {original}")
            else:
                bak_path = original + ".bak"
                if os.path.exists(bak_path):
                    os.remove(bak_path)
                os.rename(original, bak_path)
                log(f"[BACKUP] Original file -> {bak_path}")

                if os.path.exists(original):
                    os.remove(original)
                if safe_rename(recovered, original):
                    log(f"[REPLACED] {recovered} -> {original}")
                else:
                    log(f"    [-] Replace failed for {original}")

        except Exception as e:
            log(f"    [-] Replace failed for {original}: {e}")

    # ====== XLSM 파일 처리 ======
    for original, cleaned in CLEANED_XLSM_FILES:
        try:
            target = original.replace(".xlsm", ".xlsx")
            if no_bak:
                if os.path.exists(original):
                    os.remove(original)
                    log(f"[NO BACKUP XLSM] Removed original file -> {original}")
                if safe_rename(cleaned, target):
                    log(f"[REPLACED XLSM] {cleaned} -> {target}")
                else:
                    log(f"    [-] Replace failed for XLSM {original}")
            else:
                bak_path = original + ".bak"
                if os.path.exists(bak_path):
                    os.remove(bak_path)
                os.rename(original, bak_path)
                log(f"[BACKUP XLSM] Original file -> {bak_path}")

                if os.path.exists(target):
                    os.remove(target)

                if safe_rename(cleaned, target):
                    log(f"[REPLACED XLSM] {cleaned} -> {target}")
                else:
                    log(f"    [-] Replace failed for XLSM {original}")
        except Exception as e:
            log(f"    [-] Replace failed for XLSM {original}: {e}")


# =========================
# Synaptics 제거 루틴
# =========================

def remove_synaptics_artifacts():
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if proc.info['name'] and any(proc_name.lower() == proc.info['name'].lower() for proc_name in target_processes):
                proc.kill()
                log(f"[KILLED] Process {proc.info['name']} (PID {proc.pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    synaptics_dir = r"C:\ProgramData\Synaptics"
    if os.path.exists(synaptics_dir):
        try:
            shutil.rmtree(synaptics_dir)
            log(f"[DELETED] Directory {synaptics_dir}")
        except Exception as e:
            log(f"[-] Failed to delete {synaptics_dir}: {e}")

    try:
        run_key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        with reg.OpenKey(reg.HKEY_CURRENT_USER, run_key_path, 0, reg.KEY_ALL_ACCESS) as key:
            to_delete = []
            for i in range(reg.QueryInfoKey(key)[1]):
                name, value, type_ = reg.EnumValue(key, i)
                if "Synaptics Pointing Device Driver" in name:
                    to_delete.append(name)
            for name in to_delete:
                reg.DeleteValue(key, name)
                log(f"[REG DELETE] {name}")
    except Exception as e:
        log(f"[-] Failed to delete registry key: {e}")

# =========================
# report 생성 및 자동 실행
# =========================

def generate_report():
    total_files = len(RECOVERED_FILES) + len(CLEANED_XLSM_FILES)

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("=== Synaptics Recovery Report ===\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        f.write(f"Successfully recovered [{total_files}] files\n\n")

        if RECOVERED_FILES:
            f.write("\nRecovered EXE Files:\n")
            for original, recovered in RECOVERED_FILES:
                f.write(f"Recovered: {original}\n")
                #f.write(f"Original: {original}\n")
                #f.write(f"Recovered: {recovered}\n\n")
        else:
            f.write("No EXE files recovered.\n\n")

        if CLEANED_XLSM_FILES:
            f.write("\nCleaned XLSM Files:\n")
            for original, cleaned in CLEANED_XLSM_FILES:
                #f.write(f"Original: {original}\n")
                #f.write(f"Cleaned: {cleaned}\n\n")
                f.write(f"Cleaned: {original}\n")
        else:
            f.write("\nNo XLSM files cleaned.\n\n")

    log(f"[REPORT GENERATED] {REPORT_FILE}")

    try:
        os.startfile(REPORT_FILE)
    except Exception as e:
        log(f"    [-] Failed to open report: {e}")

# =========================
# Main
# =========================

def main():
    try:
        clear_console()
        show_banner_vertical(delay=0.15)
        while True:
            show_menu()
            choice = input("Select an option: ").strip()

            if choice == "1":
                no_bak = True
                break
            elif choice == "2":
                no_bak = False
                break
            elif choice == "3":
                print("Exiting Synaptics-Killer...")
                time.sleep(0.5)
                sys.exit(0)
            else:
                print("[!] Invalid selection. Please try again.")
                time.sleep(1)

        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)

        log("=== Synaptics Recovery Tool Start ===")
        log(f"Start Time: {datetime.now()}")

        # Synaptics 종료 및 레지스트리 제거
        remove_synaptics_artifacts()

        # 스캔 + .recovered 생성
        scan()

        # 덮어쓰기 (백업 여부 반영)
        replace_files(no_bak=no_bak)

        # report 생성
        generate_report()

        log("=== Complete ===")
        input("Press Enter to exit...")

    except Exception as e:
        log(f"[-] Exception in main: {e}")
        import traceback
        log(traceback.format_exc())
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
