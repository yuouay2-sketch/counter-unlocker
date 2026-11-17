import ctypes
import datetime
import hashlib
import os
import platform
import shutil
import signal
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "Counter Unlocker"
APP_VERSION = "1.5.0"
IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

if not (IS_WINDOWS or IS_MAC):
    print("Counter Unlocker поддерживает только Windows и macOS.")
    sys.exit(1)


# =============================================================
#  ПУТИ
# =============================================================
def _resolve_data_dir():
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/AppData/Local")
        return os.path.join(base, "CounterUnlocker")
    return os.path.join(os.path.expanduser("~/Library/Application Support"), "CounterUnlocker")


def _resolve_config_dir():
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~/AppData/Roaming")
        return os.path.join(base, "CounterUnlocker")
    return os.path.join(os.path.expanduser("~/Library/Preferences"), "CounterUnlocker")


DATA_DIR = _resolve_data_dir()
CONFIG_DIR = _resolve_config_dir()
QUARANTINE_DIR = os.path.join(DATA_DIR, "Quarantine")
LOG_DIR = os.path.join(DATA_DIR, "Logs")
SIGNATURES_DIR = os.path.join(DATA_DIR, "Signatures")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.ini")

for _d in (DATA_DIR, CONFIG_DIR, QUARANTINE_DIR, LOG_DIR, SIGNATURES_DIR):
    os.makedirs(_d, exist_ok=True)


# =============================================================
#  ПАЛИТРЫ
# =============================================================
DARK = {
    "bg": "#1a1a26", "surface": "#232331", "surface_alt": "#2c2c3f",
    "surface_hi": "#35354d", "header_top": "#1f1440", "header_bot": "#0f8b8d",
    "accent": "#7c5cff", "accent_hi": "#9678ff",
    "danger": "#ff5c7c", "danger_hi": "#ff7a95",
    "success": "#4ade80", "success_hi": "#6ce89a",
    "warn": "#fbbf24", "text": "#e5e5f0", "text_dim": "#9494a8",
    "border": "#3a3a55", "console_bg": "#0f0f18", "console_fg": "#c8d0d8",
}
LIGHT = {
    "bg": "#f5f6fa", "surface": "#ffffff", "surface_alt": "#eef0f6",
    "surface_hi": "#e1e4ee", "header_top": "#5b3ec7", "header_bot": "#0e7a7c",
    "accent": "#5b3ec7", "accent_hi": "#6f52d8",
    "danger": "#d63b5b", "danger_hi": "#e5546f",
    "success": "#1a9d5b", "success_hi": "#26b86e",
    "warn": "#c48a00", "text": "#1c1c28", "text_dim": "#5f6075",
    "border": "#d0d3dd", "console_bg": "#1c1c28", "console_fg": "#d8dce8",
}


def load_settings():
    s = {"theme": "dark", "geometry": "1100x780"}
    try:
        if os.path.isfile(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        s[k] = v
    except Exception:
        pass
    return s


def save_settings(s):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            for k, v in s.items():
                f.write(f"{k}={v}\n")
    except Exception:
        pass


# =============================================================
#  СИГНАТУРЫ
# =============================================================
def load_signatures():
    sigs = set()
    path = os.path.join(SIGNATURES_DIR, "hashes.txt")
    if not os.path.isfile(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write("# SHA-256 в hex, по одному в строке\n"
                    "# EICAR test file:\n"
                    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n")
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    sigs.add(line)
    except Exception:
        pass
    return sigs


SUSPICIOUS_PATTERNS_EXACT = [
    b"DisableTaskMgr", b"DisableRegistryTools", b"DisableCMD",
    b"NoControlPanel", b"NoFolderOptions", b"NoRun",
]
SUSPICIOUS_PATTERNS_CASE = [
    b"powershell -enc", b"powershell -encodedcommand",
    b"genieo", b"vsearch", b"installmac", b"searchprotect",
    b"spigot", b"mackeeper", b"conduit", b"trovi",
]
SUSPICIOUS_EXTENSIONS = {
    ".scr", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".ps1", ".bat", ".cmd", ".pif", ".dmg", ".pkg",
}


# =============================================================
#  БАЗА ОТЛАДЧИКОВ
# =============================================================
DEBUGGER_PROCESSES = {
    "windows": [
        "x64dbg", "x32dbg", "x96dbg", "ollydbg",
        "windbg", "cdb.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "cheatengine", "cheat engine",
        "processhacker", "procexp", "systeminformer",
        "hxd", "010editor",
        "dnspy", "ilspy",
        "scylla", "pe-bear", "lordpe", "die.exe", "detect it easy",
        "immunity debugger", "immunitydebugger",
        "apimonitor", "api monitor",
        "radare2", "rabin2",
        "frida", "frida-server",
        "ghidra",
        "devenv.exe",
        "ida", "ida64",
    ],
    "macos": [
        "lldb", "gdb",
        "dtrace", "dtruss",
        "hopper",
        "ida", "ida64", "idaq",
        "radare2", "r2", "rabin2", "radiff2",
        "objdump", "otool",
        "sample",
        "frida", "frida-server",
        "lldb-rpc-server",
        "class-dump",
        "jtool", "jtool2",
        "vmmap", "heap",
        "strings",
        "ghidra",
    ],
}


def _platform_key():
    return "windows" if IS_WINDOWS else "macos"


# =============================================================
#  ANTI-DEBUG
# =============================================================
def get_running_processes():
    names = set()
    try:
        if IS_WINDOWS:
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                               capture_output=True, text=True, timeout=15,
                               encoding="cp866", errors="ignore")
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    first = line.split('","', 1)[0].strip('"').lower()
                    if first:
                        names.add(first)
        else:
            r = subprocess.run(["ps", "-A", "-o", "comm="],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line:
                        names.add(os.path.basename(line).lower())
    except Exception:
        pass
    return names


def detect_debuggers():
    running = get_running_processes()
    patterns = DEBUGGER_PROCESSES.get(_platform_key(), [])
    hits = []
    for proc in running:
        for pat in patterns:
            if pat in proc:
                hits.append((proc, pat))
                break
    return hits


def is_self_debugged():
    signals = []
    if IS_WINDOWS:
        try:
            k32 = ctypes.windll.kernel32
            if k32.IsDebuggerPresent():
                signals.append("IsDebuggerPresent() = True")
            handle = k32.GetCurrentProcess()
            remote = ctypes.c_int(0)
            if k32.CheckRemoteDebuggerPresent(handle, ctypes.byref(remote)) and remote.value:
                signals.append("CheckRemoteDebuggerPresent = True")
        except Exception:
            pass
    elif IS_MAC:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            PT_DENY_ATTACH = 31
            ctypes.set_errno(0)
            if libc.ptrace(PT_DENY_ATTACH, 0, None, 0) != 0:
                if ctypes.get_errno() == 1:
                    signals.append("ptrace(PT_DENY_ATTACH) refused")
        except Exception:
            pass
    return (len(signals) > 0, signals)


# =============================================================
#  ХЕЛПЕРЫ
# =============================================================
def _run(cmd, timeout=20, encoding=None):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           text=True, encoding=encoding, errors="ignore")
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return False, f"команда не найдена: {cmd[0]}"
    except Exception as e:
        return False, str(e)


def _mac_sudo(cmd_str):
    script = f'do shell script "{cmd_str}" with administrator privileges'
    return _run(["osascript", "-e", script], timeout=60)


# ---------- Windows ----------
def reg_add(hive, path, name, rtype, value):
    if not IS_WINDOWS:
        return False, "Только Windows"
    if name:
        cmd = ["reg", "add", f"{hive}\\{path}", "/v", name, "/t", rtype, "/d", str(value), "/f"]
    else:
        cmd = ["reg", "add", f"{hive}\\{path}", "/ve", "/t", rtype, "/d", str(value), "/f"]
    return _run(cmd)


def reg_delete(hive, path, name=None, recursive=True):
    if not IS_WINDOWS:
        return False, "Только Windows"
    cmd = ["reg", "delete", f"{hive}\\{path}"]
    if name:
        cmd += ["/v", name]
    if recursive:
        cmd += ["/f"]
    return _run(cmd)


def reg_query(hive, path):
    if not IS_WINDOWS:
        return False, ""
    return _run(["reg", "query", f"{hive}\\{path}"])


def sc_run(*args):
    if not IS_WINDOWS:
        return False, "Только Windows"
    return _run(["sc"] + list(args), encoding="cp866")


def unlock_task_manager():
    return reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                   "DisableTaskMgr", "REG_DWORD", "0")

def unlock_registry_editor():
    return reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                   "DisableRegistryTools", "REG_DWORD", "0")

def unlock_cmd():
    return reg_add("HKCU", r"Software\Policies\Microsoft\Windows\System",
                   "DisableCMD", "REG_DWORD", "0")

def unlock_control_panel():
    return reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                   "NoControlPanel", "REG_DWORD", "0")

def unlock_folder_options():
    return reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                   "NoFolderOptions", "REG_DWORD", "0")

def unlock_run_dialog():
    return reg_add("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                   "NoRun", "REG_DWORD", "0")

def restore_exe_association():
    reg_delete("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.exe\UserChoice")
    return reg_add("HKCR", ".exe", "", "REG_SZ", "exefile")

def restore_reg_association():
    reg_delete("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.reg\UserChoice")
    return reg_add("HKCR", ".reg", "", "REG_SZ", "regfile")

def reset_all_policies():
    paths = [
        ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Policies"),
        ("HKCU", r"Software\Policies\Microsoft\Windows"),
        ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies"),
    ]
    results = []
    for hive, path in paths:
        ok, msg = reg_delete(hive, path)
        results.append(f"{hive}\\{path}: {'OK' if ok else msg.strip()[:40]}")
    return True, "\n".join(results)

def enable_defender():
    return reg_add("HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender",
                   "DisableAntiSpyware", "REG_DWORD", "0")

def enable_uac():
    ok1, _ = reg_add("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                     "EnableLUA", "REG_DWORD", "1")
    ok2, _ = reg_add("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                     "ConsentPromptBehaviorAdmin", "REG_DWORD", "5")
    return (ok1 and ok2), "UAC включён" if (ok1 and ok2) else "Требуются права администратора"


# ---------- macOS ----------
def mac_xattr_has_quarantine(path):
    ok, out = _run(["xattr", path])
    return ok and "com.apple.quarantine" in out

def mac_xattr_clear(path):
    return _run(["xattr", "-d", "com.apple.quarantine", path])

def mac_xattr_clear_dir(folder):
    ok_n = fail_n = 0
    for root, _, files in os.walk(folder):
        for f in files:
            p = os.path.join(root, f)
            if not mac_xattr_has_quarantine(p):
                continue
            ok, _ = mac_xattr_clear(p)
            ok_n += 1 if ok else 0
            fail_n += 0 if ok else 1
    return True, f"Очищено: {ok_n}, ошибок: {fail_n}"

def mac_gatekeeper_status():
    return _run(["spctl", "--status"])

def mac_gatekeeper_enable():
    return _mac_sudo("spctl --master-enable")

def mac_gatekeeper_disable():
    return _mac_sudo("spctl --master-disable")

def mac_sip_status():
    return _run(["csrutil", "status"])

def mac_firewall_status():
    return _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])

def mac_firewall_enable():
    return _mac_sudo("/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")

def mac_filevault_status():
    return _run(["fdesetup", "status"])

def mac_login_items_list():
    script = 'tell application "System Events" to get the name of every login item'
    ok, out = _run(["osascript", "-e", script], timeout=15)
    if not ok or not out.strip():
        return []
    return [x.strip() for x in out.split(", ") if x.strip()]

def mac_login_item_remove(name):
    script = f'tell application "System Events" to delete login item "{name}"'
    return _run(["osascript", "-e", script], timeout=15)

def mac_launch_items():
    dirs = [
        ("~/Library/LaunchAgents", os.path.expanduser("~/Library/LaunchAgents")),
        ("/Library/LaunchAgents",  "/Library/LaunchAgents"),
        ("/Library/LaunchDaemons", "/Library/LaunchDaemons"),
    ]
    result = []
    for label, base in dirs:
        if not os.path.isdir(base):
            continue
        try:
            for f in sorted(os.listdir(base)):
                if f.endswith(".plist"):
                    full = os.path.join(base, f)
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = -1
                    result.append((label, f, full, size))
        except PermissionError:
            continue
    return result

def mac_remove_launch_item(full_path):
    _run(["launchctl", "unload", full_path], timeout=10)
    try:
        os.remove(full_path)
        return True, full_path
    except PermissionError:
        return _mac_sudo(f'rm -f "{full_path}"')
    except Exception as e:
        return False, str(e)


# =============================================================
#  АНТИВИРУСНОЕ ЯДРО
# =============================================================
def file_sha256(path, chunk=65536):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(chunk), b""):
                h.update(block)
        return h.hexdigest()
    except Exception:
        return None


def scan_file(filepath, signatures=None):
    findings = []
    try:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            findings.append(f"Подозрительное расширение ({ext})")
        if os.path.getsize(filepath) > 100 * 1024 * 1024:
            return findings
        if signatures:
            digest = file_sha256(filepath)
            if digest and digest in signatures:
                findings.append(f"Сигнатура SHA-256: {digest[:16]}…")
        with open(filepath, "rb") as f:
            content = f.read()
        lower = content.lower()
        for pat in SUSPICIOUS_PATTERNS_CASE:
            if pat in lower:
                findings.append(f"Паттерн: {pat.decode(errors='ignore')}")
        for pat in SUSPICIOUS_PATTERNS_EXACT:
            if pat in content:
                findings.append(f"Паттерн: {pat.decode(errors='ignore')}")
    except Exception:
        pass
    return findings


def quarantine_file(filepath):
    try:
        base = os.path.basename(filepath)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(QUARANTINE_DIR, f"{ts}_{base}.quarantined")
        shutil.move(filepath, dest)
        return dest
    except Exception:
        return None


# =============================================================
#  ТЕМА
# =============================================================
def draw_gradient(canvas, w, h, c1, c2):
    r1, g1, b1 = canvas.winfo_rgb(c1)
    r2, g2, b2 = canvas.winfo_rgb(c2)
    r1, g1, b1 = r1 // 256, g1 // 256, b1 // 256
    r2, g2, b2 = r2 // 256, g2 // 256, b2 // 256
    steps = min(h, 64)
    for i in range(steps):
        t = i / max(steps - 1, 1)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        y0 = int(h * i / steps)
        y1 = int(h * (i + 1) / steps)
        canvas.create_rectangle(0, y0, w, y1,
                                fill=f"#{r:02x}{g:02x}{b:02x}", outline="")


def apply_theme(root, pal):
    root.configure(bg=pal["bg"])
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(".", background=pal["bg"], foreground=pal["text"],
                    fieldbackground=pal["surface"], font=("Segoe UI", 10))
    style.configure("TFrame", background=pal["bg"])
    style.configure("Card.TFrame", background=pal["surface"],
                    relief="flat", borderwidth=0)
    style.configure("TLabel", background=pal["bg"], foreground=pal["text"])
    style.configure("Dim.TLabel", background=pal["bg"], foreground=pal["text_dim"])
    style.configure("Header.TLabel", background=pal["surface"], foreground=pal["text"],
                    font=("Segoe UI", 16, "bold"))
    style.configure("SubHeader.TLabel", background=pal["surface"],
                    foreground=pal["text_dim"], font=("Segoe UI", 10))
    style.configure("CardLabel.TLabel", background=pal["surface"], foreground=pal["text"])
    style.configure("TLabelframe", background=pal["bg"],
                    bordercolor=pal["border"], lightcolor=pal["border"],
                    darkcolor=pal["border"], relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=pal["bg"],
                    foreground=pal["accent"], font=("Segoe UI", 10, "bold"))

    style.configure("TNotebook", background=pal["bg"], borderwidth=0)
    style.configure("TNotebook.Tab", background=pal["surface"],
                    foreground=pal["text_dim"], padding=[16, 9],
                    font=("Segoe UI", 10, "bold"), borderwidth=0)
    style.map("TNotebook.Tab",
              background=[("selected", pal["surface_alt"])],
              foreground=[("selected", pal["text"])],
              expand=[("selected", [0, 0, 0, 2])])

    for name, bg, fg, hov in [
        ("TButton", pal["surface_alt"], pal["text"], pal["surface_hi"]),
        ("Accent.TButton", pal["accent"], "#ffffff", pal["accent_hi"]),
        ("Danger.TButton", pal["danger"], "#ffffff", pal["danger_hi"]),
        ("Success.TButton", pal["success"], "#0b1a10", pal["success_hi"]),
    ]:
        style.configure(name, background=bg, foreground=fg,
                        borderwidth=0, focusthickness=0,
                        padding=[12, 8], font=("Segoe UI", 10, "bold"))
        style.map(name,
                  background=[("active", hov), ("pressed", hov)],
                  foreground=[("disabled", pal["text_dim"])])

    style.configure("TSeparator", background=pal["border"])
    style.configure("Treeview",
                    background=pal["surface"], fieldbackground=pal["surface"],
                    foreground=pal["text"], borderwidth=0, rowheight=26)
    style.map("Treeview",
              background=[("selected", pal["accent"])],
              foreground=[("selected", "#ffffff")])
    style.configure("Treeview.Heading",
                    background=pal["surface_alt"], foreground=pal["text_dim"],
                    font=("Segoe UI", 9, "bold"), borderwidth=0, padding=[8, 6])
    style.map("Treeview.Heading", background=[("active", pal["surface_hi"])])
    return style


# =============================================================
#  GUI
# =============================================================
class CounterUnlocker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.pal_name = self.settings.get("theme", "dark")
        self.pal = DARK if self.pal_name == "dark" else LIGHT

        self.title(f"{APP_NAME}  •  {APP_VERSION}")
        self.geometry(self.settings.get("geometry", "1100x780"))
        self.minsize(920, 620)

        self.signatures = load_signatures()
        self.log_lines = []
        self.monitoring = False
        self.monitor_folder = None
        self.monitor_state = {}
        self._system_scan_running = False

        self._build_menu()
        self._build_header()
        self.style = apply_theme(self, self.pal)

        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(8, 8))

        self._build_logs_tab()
        if IS_WINDOWS:
            self._build_windows_main_tab()
        else:
            self._build_mac_security_tab()
        self._build_scanner_tab()
        self._build_monitor_tab()
        self._build_quarantine_tab()
        self._build_debuggers_tab()
        if IS_WINDOWS:
            self._build_startup_tab_windows()
            self._build_services_tab_windows()
        else:
            self._build_startup_tab_mac()
            self._build_mac_quarantine_tab()

        self._flush_log_buffer()
        self._build_statusbar()

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.log(f"{APP_NAME} {APP_VERSION} запущен • {platform.system()}")

    # =========================================================
    #  МЕНЮ
    # =========================================================
    def _build_menu(self):
        menubar = tk.Menu(self)

        m_file = tk.Menu(menubar, tearoff=0)
        m_file.add_command(label="📂  Открыть папку данных",
                           command=lambda: self._open_folder(DATA_DIR))
        m_file.add_command(label="🗑️  Открыть карантин",
                           command=lambda: self._open_folder(QUARANTINE_DIR))
        m_file.add_command(label="📝  Открыть логи",
                           command=lambda: self._open_folder(LOG_DIR))
        m_file.add_command(label="📌  Открыть сигнатуры",
                           command=lambda: self._open_folder(SIGNATURES_DIR))
        m_file.add_separator()
        m_file.add_command(label="Выход", command=self.on_close)
        menubar.add_cascade(label="Файл", menu=m_file)

        # Windows
        m_win = tk.Menu(menubar, tearoff=0)
        win_state = "normal" if IS_WINDOWS else "disabled"
        if not IS_WINDOWS:
            m_win.add_command(label="⚠  Доступно только на Windows", state="disabled")
            m_win.add_separator()
        m_win.add_command(label="➡️  Вкладка «Главная»", state=win_state,
                          command=lambda: self._select_tab("Главная"))
        m_win.add_command(label="➡️  Вкладка «Автозагрузка»", state=win_state,
                          command=lambda: self._select_tab("Автозагрузка"))
        m_win.add_command(label="➡️  Вкладка «Службы»", state=win_state,
                          command=lambda: self._select_tab("Службы"))
        m_win.add_separator()
        unlock = tk.Menu(m_win, tearoff=0)
        for label, func in [
            ("🔓 Диспетчер задач",   unlock_task_manager),
            ("📝 Редактор реестра",   unlock_registry_editor),
            ("💻 Командная строка",   unlock_cmd),
            ("⚙️ Панель управления", unlock_control_panel),
            ("📁 Параметры папок",    unlock_folder_options),
            ("🏃 Диалог «Выполнить»", unlock_run_dialog),
            ("🔗 Ассоциация .exe",    restore_exe_association),
            ("📋 Ассоциация .reg",    restore_reg_association),
        ]:
            unlock.add_command(label=label, state=win_state,
                               command=self._make_action(func, label.strip()))
        m_win.add_cascade(label="🔓 Разблокировать", menu=unlock, state=win_state)
        danger = tk.Menu(m_win, tearoff=0)
        danger.add_command(label="🧹 Сбросить все политики", state=win_state,
                           command=self._confirm_reset)
        danger.add_command(label="🛡️ Включить Defender", state=win_state,
                           command=self._make_action(enable_defender, "Defender"))
        danger.add_command(label="👑 Включить UAC", state=win_state,
                           command=self._make_action(enable_uac, "UAC"))
        m_win.add_cascade(label="⚠ Опасные действия", menu=danger, state=win_state)
        m_win.add_separator()
        startup_dir = os.path.expandvars(
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        m_win.add_command(label="🗂️ Папка автозагрузки", state=win_state,
                          command=lambda: self._open_folder(startup_dir))
        m_win.add_command(label="📄 Открыть hosts", state=win_state,
                          command=lambda: self._open_folder(
                              os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                           "System32", "drivers", "etc")))
        m_win.add_command(label="🧾 Редактор реестра (regedit)", state=win_state,
                          command=lambda: self._run_external("regedit"))
        m_win.add_command(label="💻 Командная строка (cmd)", state=win_state,
                          command=lambda: self._run_external("cmd"))
        menubar.add_cascade(label="🪟 Windows", menu=m_win)

        # macOS
        m_mac = tk.Menu(menubar, tearoff=0)
        mac_state = "normal" if IS_MAC else "disabled"
        if not IS_MAC:
            m_mac.add_command(label="⚠  Доступно только на macOS", state="disabled")
            m_mac.add_separator()
        m_mac.add_command(label="➡️  Вкладка «Безопасность»", state=mac_state,
                          command=lambda: self._select_tab("Безопасность"))
        m_mac.add_command(label="➡️  Вкладка «Автозагрузка»", state=mac_state,
                          command=lambda: self._select_tab("Автозагрузка"))
        m_mac.add_command(label="➡️  Вкладка «Флаги карантина»", state=mac_state,
                          command=lambda: self._select_tab("Флаги"))
        m_mac.add_separator()
        gk = tk.Menu(m_mac, tearoff=0)
        gk.add_command(label="🛡️ Включить Gatekeeper", state=mac_state,
                       command=self._mac_enable_gatekeeper)
        gk.add_command(label="⚠ Отключить Gatekeeper", state=mac_state,
                       command=self._mac_disable_gatekeeper)
        gk.add_command(label="📊 Статус Gatekeeper", state=mac_state,
                       command=self._mac_show_gatekeeper_status)
        m_mac.add_cascade(label="Gatekeeper", menu=gk, state=mac_state)
        fw = tk.Menu(m_mac, tearoff=0)
        fw.add_command(label="🔥 Включить Firewall", state=mac_state,
                       command=self._mac_enable_firewall)
        fw.add_command(label="📊 Статус Firewall", state=mac_state,
                       command=self._mac_show_firewall_status)
        m_mac.add_cascade(label="Firewall", menu=fw, state=mac_state)
        m_mac.add_command(label="📊 Статус SIP", state=mac_state,
                          command=self._mac_show_sip)
        m_mac.add_command(label="📊 Статус FileVault", state=mac_state,
                          command=self._mac_show_filevault)
        m_mac.add_command(label="📋 Configuration Profiles", state=mac_state,
                          command=self._mac_show_profiles)
        m_mac.add_command(label="✍ Проверить подпись приложения…", state=mac_state,
                          command=self._mac_check_signature)
        m_mac.add_separator()
        q = tk.Menu(m_mac, tearoff=0)
        q.add_command(label="👁 Показать флаг у файла…", state=mac_state,
                      command=self._mac_show_xattr)
        q.add_command(label="🔓 Снять флаг с файла…", state=mac_state,
                      command=self._mac_clear_xattr_file)
        q.add_command(label="📂 Снять флаги с папки…", state=mac_state,
                      command=self._mac_clear_xattr_dir)
        m_mac.add_cascade(label="Флаги карантина", menu=q, state=mac_state)
        hosts = tk.Menu(m_mac, tearoff=0)
        hosts.add_command(label="👁 Просмотр /etc/hosts", state=mac_state,
                          command=self._mac_show_hosts)
        hosts.add_command(label="🔄 Восстановить стандартный", state=mac_state,
                          command=self._mac_restore_hosts)
        m_mac.add_cascade(label="hosts", menu=hosts, state=mac_state)
        m_mac.add_separator()
        m_mac.add_command(label="🗂️ ~/Library/LaunchAgents", state=mac_state,
                          command=lambda: self._open_folder(
                              os.path.expanduser("~/Library/LaunchAgents")))
        m_mac.add_command(label="🗂️ /Library/LaunchAgents", state=mac_state,
                          command=lambda: self._open_folder("/Library/LaunchAgents"))
        m_mac.add_command(label="🗂️ /Library/LaunchDaemons", state=mac_state,
                          command=lambda: self._open_folder("/Library/LaunchDaemons"))
        menubar.add_cascade(label="🍎 macOS", menu=m_mac)

        # Сканер
        m_scan = tk.Menu(menubar, tearoff=0)
        m_scan.add_command(label="📄 Сканировать файл…",
                           command=self._scan_file_dialog)
        m_scan.add_command(label="📂 Сканировать папку…",
                           command=self._scan_folder_dialog)
        m_scan.add_command(label="🖥️ Сканировать систему…",
                           command=self._scan_system_dialog)
        m_scan.add_separator()
        m_scan.add_command(label="👁 Включить / выключить мониторинг",
                           command=self._toggle_monitor)
        m_scan.add_command(label="➡️ Перейти к карантину",
                           command=lambda: self._select_tab("Карантин"))
        m_scan.add_separator()
        m_scan.add_command(label="🔄 Перезагрузить сигнатуры",
                           command=self._reload_signatures)
        menubar.add_cascade(label="Сканер", menu=m_scan)

        # Отладчики
        m_debug = tk.Menu(menubar, tearoff=0)
        m_debug.add_command(label="➡️ Вкладка «Отладчики»",
                            command=lambda: self._select_tab("Отладчики"))
        m_debug.add_separator()
        m_debug.add_command(label="🔬 Сканировать систему", command=self._scan_for_debuggers)
        m_debug.add_command(label="🗑️ Автоудаление всех отладчиков",
                            command=self._kill_all_debuggers)
        m_debug.add_separator()
        m_debug.add_command(label="🛡️ Проверить сам процесс", command=self._check_self_debug)
        m_debug.add_command(label="⚡ Включить anti-debug", command=self._enable_anti_debug)
        menubar.add_cascade(label="🔬 Отладчики", menu=m_debug)

        # Вид
        m_view = tk.Menu(menubar, tearoff=0)
        m_view.add_command(label="🌙 Тёмная тема",
                           command=lambda: self._set_theme("dark"))
        m_view.add_command(label="☀️ Светлая тема",
                           command=lambda: self._set_theme("light"))
        menubar.add_cascade(label="Вид", menu=m_view)

        # Справка
        m_help = tk.Menu(menubar, tearoff=0)
        m_help.add_command(label="О программе", command=self._about)
        m_help.add_command(label="Где хранятся файлы?", command=self._show_paths)
        menubar.add_cascade(label="Справка", menu=m_help)

        self.config(menu=menubar)
        self.menubar = menubar

    # ---------- шапка ----------
    def _build_header(self):
        menu_bar = tk.Frame(self, bg=self.pal["header_top"], height=36)
        menu_bar.pack(fill="x", side="top")
        menu_bar.pack_propagate(False)

        self.menu_btn = tk.Menubutton(
            menu_bar, text="☰  Меню  ▾",
            bg=self.pal["accent"], fg="#ffffff",
            activebackground=self.pal["accent_hi"], activeforeground="#ffffff",
            relief="flat", borderwidth=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2", padx=14, pady=2)
        self.menu_btn.pack(side="left", padx=8, pady=4)
        self.menu_btn["menu"] = self.menubar

        tk.Label(menu_bar,
                 text=f"{APP_NAME}  •  {platform.system()} {platform.release()}",
                 bg=self.pal["header_top"], fg="#cfcfd8",
                 font=("Segoe UI", 9)).pack(side="left", padx=10)

        self.header_canvas = tk.Canvas(self, height=76, highlightthickness=0,
                                       bg=self.pal["header_top"])
        self.header_canvas.pack(fill="x", side="top")

        def redraw(event=None):
            w = self.header_canvas.winfo_width() or 1000
            self.header_canvas.delete("all")
            draw_gradient(self.header_canvas, w, 76,
                          self.pal["header_top"], self.pal["header_bot"])
            self.header_canvas.create_text(
                22, 26, text="🔓  Counter Unlocker", anchor="w",
                fill="#ffffff", font=("Segoe UI", 18, "bold"))
            self.header_canvas.create_text(
                22, 52,
                text=f"Разблокировка системных ограничений + сканер  •  "
                     f"{platform.system()} {platform.release()}",
                anchor="w", fill="#ffffff", font=("Segoe UI", 9))
            admin = "👑 админ" if self._is_admin() else "👤 пользователь"
            self.header_canvas.create_text(
                w - 22, 26, text=f"v{APP_VERSION}", anchor="e",
                fill="#ffffff", font=("Segoe UI", 11, "bold"))
            self.header_canvas.create_text(
                w - 22, 52, text=f"{admin}  •  сигнатур: {len(self.signatures)}",
                anchor="e", fill="#ffffff", font=("Segoe UI", 9))

        self.header_canvas.bind("<Configure>", redraw)
        self.after(50, redraw)
        self._redraw_header = redraw

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=self.pal["surface_alt"], height=28)
        bar.pack(fill="x", side="bottom")
        self.status_label = tk.Label(
            bar, text=f"  Данные: {DATA_DIR}",
            bg=self.pal["surface_alt"], fg=self.pal["text_dim"],
            font=("Segoe UI", 9), anchor="w")
        self.status_label.pack(side="left", fill="y", padx=4)
        self.status_right = tk.Label(
            bar, text="готов  ",
            bg=self.pal["surface_alt"], fg=self.pal["text_dim"],
            font=("Segoe UI", 9), anchor="e")
        self.status_right.pack(side="right", fill="y", padx=4)

    def _set_theme(self, name):
        self.pal_name = name
        self.pal = DARK if name == "dark" else LIGHT
        self.settings["theme"] = name
        save_settings(self.settings)
        for w in self.winfo_children():
            w.destroy()
        self._build_menu()
        self._build_header()
        self.style = apply_theme(self, self.pal)
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(8, 8))
        self._build_logs_tab()
        if IS_WINDOWS:
            self._build_windows_main_tab()
        else:
            self._build_mac_security_tab()
        self._build_scanner_tab()
        self._build_monitor_tab()
        self._build_quarantine_tab()
        self._build_debuggers_tab()
        if IS_WINDOWS:
            self._build_startup_tab_windows()
            self._build_services_tab_windows()
        else:
            self._build_startup_tab_mac()
            self._build_mac_quarantine_tab()
        self._flush_log_buffer()
        self._build_statusbar()
        self.log(f"Тема переключена: {name}")

    # ---------- утилиты ----------
    def _select_tab(self, keyword):
        try:
            for tid in self.nb.tabs():
                if keyword in self.nb.tab(tid, "text"):
                    self.nb.select(tid)
                    return
        except Exception:
            pass

    def _run_external(self, cmd):
        try:
            if IS_WINDOWS:
                subprocess.Popen(cmd, shell=True)
            else:
                subprocess.Popen(["open", "-a", cmd])
            self.log(f"Запущено: {cmd}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _is_admin(self):
        if IS_WINDOWS:
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except Exception:
                return False
        try:
            return os.geteuid() == 0
        except Exception:
            return False

    def _open_folder(self, path):
        try:
            if IS_WINDOWS:
                os.startfile(path)
            else:
                subprocess.Popen(["open", path])
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _about(self):
        messagebox.showinfo(
            APP_NAME,
            f"{APP_NAME} v{APP_VERSION}\n\n"
            "Гибрид: разблокировка системных ограничений\n"
            "и лёгкий антивирусный сканер.\n\n"
            f"ОС: {platform.system()} {platform.release()}\n"
            f"Данные: {DATA_DIR}\n"
            f"Настройки: {CONFIG_DIR}")

    def _show_paths(self):
        messagebox.showinfo(
            "Где хранятся файлы",
            f"Данные:\n  {DATA_DIR}\n\n"
            f"Карантин:\n  {QUARANTINE_DIR}\n\n"
            f"Логи:\n  {LOG_DIR}\n\n"
            f"Сигнатуры:\n  {SIGNATURES_DIR}\n\n"
            f"Настройки:\n  {CONFIG_DIR}")

    def log(self, message):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}"
        self.log_lines.append(line)
        if hasattr(self, "log_text"):
            try:
                self.log_text.config(state="normal")
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
                self.log_text.config(state="disabled")
            except Exception:
                pass
        try:
            with open(os.path.join(LOG_DIR, "counter_unlocker.log"),
                      "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def _flush_log_buffer(self):
        self.log_text.config(state="normal")
        for line in self.log_lines:
            self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def on_close(self):
        try:
            self.settings["geometry"] = self.geometry()
            save_settings(self.settings)
        except Exception:
            pass
        self.monitoring = False
        self._system_scan_running = False
        self.log("Завершение работы")
        self.destroy()

    # =========================================================
    # Windows: Главная
    # =========================================================
    def _build_windows_main_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔓 Главная  ")

        head = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        head.pack(fill="x", pady=(6, 10))
        ttk.Label(head, text="Разблокировка системных компонентов Windows",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(head,
                  text="Действия применяются к HKCU. Для HKLM/UAC запустите от админа.",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 0))

        grid_frame = ttk.Frame(tab)
        grid_frame.pack(fill="x", pady=(0, 6))

        actions = [
            ("🔓", "Диспетчер задач",    unlock_task_manager),
            ("📝", "Редактор реестра",   unlock_registry_editor),
            ("💻", "Командная строка",   unlock_cmd),
            ("⚙️", "Панель управления", unlock_control_panel),
            ("📁", "Параметры папок",    unlock_folder_options),
            ("🏃", "Диалог «Выполнить»", unlock_run_dialog),
            ("🔗", "Ассоциация .exe",    restore_exe_association),
            ("📋", "Ассоциация .reg",    restore_reg_association),
        ]
        for i, (icon, label, func) in enumerate(actions):
            card = ttk.Frame(grid_frame, style="Card.TFrame", padding=(12, 10))
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=4, pady=4)
            ttk.Label(card, text=icon, font=("Segoe UI", 20),
                      style="CardLabel.TLabel").pack(side="left", padx=(0, 10))
            ttk.Label(card, text=label, style="CardLabel.TLabel",
                      font=("Segoe UI", 11, "bold")).pack(side="left")
            ttk.Button(card, text="Разблокировать", style="Accent.TButton",
                       command=self._make_action(func, label)).pack(side="right")
        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

        ttk.Separator(tab, orient="horizontal").pack(fill="x", pady=14)

        danger_frame = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        danger_frame.pack(fill="x")
        ttk.Label(danger_frame, text="⚠ Осторожно — системные изменения",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(danger_frame,
                  text="Сброс политик удаляет ключи целиком.",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 10))
        btns = ttk.Frame(danger_frame, style="Card.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="🧹 Сбросить все политики", style="Danger.TButton",
                   command=self._confirm_reset).pack(side="left", padx=(0, 6))
        ttk.Button(btns, text="🛡️ Включить Defender", style="Success.TButton",
                   command=self._make_action(enable_defender, "Defender")).pack(side="left", padx=6)
        ttk.Button(btns, text="👑 Включить UAC", style="Success.TButton",
                   command=self._make_action(enable_uac, "UAC")).pack(side="left", padx=6)

    def _make_action(self, func, label):
        def cmd():
            ok, msg = func()
            if ok:
                self.log(f"Успешно: {label}")
                messagebox.showinfo("Готово", f"✔ {label}\n\n{msg}")
            else:
                self.log(f"Ошибка: {label} — {msg.strip()[:120]}")
                messagebox.showerror("Ошибка", f"✖ {label}\n\n{msg.strip()[:300]}")
        return cmd

    def _confirm_reset(self):
        if not messagebox.askyesno(
                "Подтверждение",
                "Удалить все ключи политик Windows (HKCU и HKLM)?\n\nПродолжить?"):
            return
        self._make_action(reset_all_policies, "Сброс политик")()

    # =========================================================
    # macOS: Безопасность
    # =========================================================
    def _build_mac_security_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🛡️ Безопасность  ")

        head = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        head.pack(fill="x", pady=(6, 10))
        ttk.Label(head, text="Проверка безопасности macOS",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(head,
                  text="SIP · Gatekeeper · Firewall · FileVault · Profiles",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 0))

        checks_frame = ttk.LabelFrame(tab, text=" Статусы системы ", padding=10)
        checks_frame.pack(fill="x", pady=(0, 8))

        checks = [
            ("System Integrity Protection (SIP)", mac_sip_status),
            ("Gatekeeper",                        mac_gatekeeper_status),
            ("Application Firewall",              mac_firewall_status),
            ("FileVault",                         mac_filevault_status),
        ]
        for i, (label, func) in enumerate(checks):
            ttk.Label(checks_frame, text=label + ":").grid(row=i, column=0,
                                                          sticky="w", padx=6, pady=4)
            ok, out = func()
            status = (out.strip().splitlines() or ["?"])[0][:90]
            ttk.Label(checks_frame, text=status,
                      foreground="#7ec699" if ("enabled" in status.lower() or "on" in status.lower())
                      else "#ff6b6b").grid(row=i, column=1, sticky="w", padx=6, pady=4)

        actions_frame = ttk.LabelFrame(tab, text=" Действия (нужен пароль администратора) ", padding=10)
        actions_frame.pack(fill="x", pady=8)

        mac_actions = [
            ("🛡️ Включить Gatekeeper",         self._mac_enable_gatekeeper),
            ("⚠ Отключить Gatekeeper",         self._mac_disable_gatekeeper),
            ("🔥 Включить Firewall",            self._mac_enable_firewall),
            ("📋 Показать Profiles",            self._mac_show_profiles),
            ("✍ Проверить подпись приложения", self._mac_check_signature),
        ]
        for i, (text, func) in enumerate(mac_actions):
            ttk.Button(actions_frame, text=text, command=func,
                       style="Danger.TButton" if "Отключ" in text else "TButton"
                       ).grid(row=i // 2, column=i % 2, sticky="ew",
                              padx=4, pady=4, ipady=2)
        actions_frame.columnconfigure(0, weight=1)
        actions_frame.columnconfigure(1, weight=1)

    def _mac_enable_gatekeeper(self):
        if not messagebox.askyesno("Gatekeeper", "Включить Gatekeeper?"):
            return
        ok, out = mac_gatekeeper_enable()
        self.log(f"Включение Gatekeeper: {'OK' if ok else out[:120]}")
        (messagebox.showinfo("Готово", "Gatekeeper включён") if ok
         else messagebox.showerror("Ошибка", out[:400]))

    def _mac_disable_gatekeeper(self):
        if not messagebox.askyesno("Gatekeeper",
                                   "Отключить Gatekeeper? Это снижает безопасность!"):
            return
        ok, out = mac_gatekeeper_disable()
        self.log(f"Отключение Gatekeeper: {'OK' if ok else out[:120]}")
        (messagebox.showinfo("Готово", "Gatekeeper отключён") if ok
         else messagebox.showerror("Ошибка", out[:400]))

    def _mac_enable_firewall(self):
        ok, out = mac_firewall_enable()
        self.log(f"Включение Firewall: {'OK' if ok else out[:120]}")
        (messagebox.showinfo("Готово", "Firewall включён") if ok
         else messagebox.showerror("Ошибка", out[:400]))

    def _mac_show_gatekeeper_status(self):
        ok, out = mac_gatekeeper_status()
        messagebox.showinfo("Gatekeeper", out.strip() or "нет вывода")

    def _mac_show_firewall_status(self):
        ok, out = mac_firewall_status()
        messagebox.showinfo("Firewall", out.strip() or "нет вывода")

    def _mac_show_sip(self):
        ok, out = mac_sip_status()
        messagebox.showinfo("SIP", out.strip() or "нет вывода")

    def _mac_show_filevault(self):
        ok, out = mac_filevault_status()
        messagebox.showinfo("FileVault", out.strip() or "нет вывода")

    def _mac_show_profiles(self):
        ok, out = _run(["profiles", "-P"], timeout=20)
        win = tk.Toplevel(self)
        win.title("Configuration Profiles")
        win.geometry("760x520")
        win.configure(bg=self.pal["console_bg"])
        t = tk.Text(win, wrap="word", font=("Menlo", 10),
                    bg=self.pal["console_bg"], fg=self.pal["console_fg"])
        t.pack(fill="both", expand=True)
        t.insert("1.0", out or "Нет профилей или нужны права.")
        t.config(state="disabled")
        self.log("Показаны Configuration Profiles")

    def _mac_check_signature(self):
        path = filedialog.askopenfilename(
            title="Выберите .app или бинарник",
            filetypes=[("Applications", "*.app"), ("All", "*")])
        if not path:
            return
        target = path
        if path.endswith(".app"):
            mdir = os.path.join(path, "Contents", "MacOS")
            if os.path.isdir(mdir):
                files = os.listdir(mdir)
                if files:
                    target = os.path.join(mdir, files[0])
        ok, out = _run(["codesign", "-dv", "--verbose=4", target], timeout=30)
        messagebox.showinfo("Подпись", f"{target}\n\n{out or '(нет вывода)'}")

    # =========================================================
    # macOS: Автозагрузка
    # =========================================================
    def _build_startup_tab_mac(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🚀 Автозагрузка  ")

        li_frame = ttk.LabelFrame(tab, text=" Login Items ", padding=8)
        li_frame.pack(fill="x", pady=(6, 8))
        self.mac_login_list = tk.Listbox(li_frame, height=5,
                                         bg=self.pal["surface"], fg=self.pal["text"],
                                         selectbackground=self.pal["accent"],
                                         selectforeground="#ffffff",
                                         borderwidth=0, highlightthickness=0,
                                         font=("Segoe UI", 10))
        self.mac_login_list.pack(fill="x", pady=(0, 6))
        li_btns = ttk.Frame(li_frame)
        li_btns.pack(fill="x")
        ttk.Button(li_btns, text="🔄 Обновить", style="TButton",
                   command=self._refresh_mac_login_items).pack(side="left", padx=(0, 4))
        ttk.Button(li_btns, text="🗑️ Удалить выбранный", style="Danger.TButton",
                   command=self._delete_mac_login_item).pack(side="left")
        self._refresh_mac_login_items()

        la_frame = ttk.LabelFrame(tab, text=" LaunchAgents / LaunchDaemons ", padding=8)
        la_frame.pack(fill="both", expand=True)

        cols = ("dir", "name", "path", "size")
        self.mac_launch_tree = ttk.Treeview(la_frame, columns=cols,
                                            show="headings", height=12)
        for c, t, w in [("dir", "Каталог", 200), ("name", "Файл", 220),
                        ("path", "Путь", 460), ("size", "Размер, Б", 90)]:
            self.mac_launch_tree.heading(c, text=t)
            self.mac_launch_tree.column(c, width=w,
                                        anchor="e" if c == "size" else "w")
        self.mac_launch_tree.pack(fill="both", expand=True, pady=(0, 6))

        btns = ttk.Frame(la_frame)
        btns.pack(fill="x")
        ttk.Button(btns, text="🔄 Обновить", style="TButton",
                   command=self._refresh_mac_launch_items).pack(side="left", padx=(0, 4))
        ttk.Button(btns, text="🗑️ Удалить выбранный", style="Danger.TButton",
                   command=self._delete_mac_launch_item).pack(side="left", padx=4)
        ttk.Button(btns, text="🔍 Сканировать plist'ы", style="Accent.TButton",
                   command=self._scan_mac_launch_items).pack(side="left")

        self._mac_launch_entries = {}
        self._refresh_mac_launch_items()

    def _refresh_mac_login_items(self):
        self.mac_login_list.delete(0, "end")
        for item in mac_login_items_list():
            self.mac_login_list.insert("end", item)
        self.log(f"Login Items: {self.mac_login_list.size()}")

    def _delete_mac_login_item(self):
        sel = self.mac_login_list.curselection()
        if not sel:
            return
        name = self.mac_login_list.get(sel[0])
        if not messagebox.askyesno("Удалить", f"Удалить login item «{name}»?"):
            return
        ok, out = mac_login_item_remove(name)
        if ok:
            self.log(f"Login item удалён: {name}")
            self._refresh_mac_login_items()
        else:
            messagebox.showerror("Ошибка", out[:300])

    def _refresh_mac_launch_items(self):
        for row in self.mac_launch_tree.get_children():
            self.mac_launch_tree.delete(row)
        self._mac_launch_entries.clear()
        for label, name, full, size in mac_launch_items():
            iid = self.mac_launch_tree.insert("", "end",
                                              values=(label, name, full, size))
            self._mac_launch_entries[iid] = full
        self.log(f"Launch items: {len(self._mac_launch_entries)}")

    def _delete_mac_launch_item(self):
        sel = self.mac_launch_tree.selection()
        if not sel:
            return
        full = self._mac_launch_entries[sel[0]]
        if not messagebox.askyesno("Удалить",
                                   f"Удалить «{os.path.basename(full)}»?"):
            return
        ok, out = mac_remove_launch_item(full)
        if ok:
            self.log(f"Удалён: {full}")
            self._refresh_mac_launch_items()
        else:
            messagebox.showerror("Ошибка", str(out)[:300])

    def _scan_mac_launch_items(self):
        found = 0
        for _, _, full, _ in mac_launch_items():
            findings = scan_file(full, self.signatures)
            if findings:
                found += 1
                self.log(f"plist: {full} — {'; '.join(findings)}")
                q = quarantine_file(full)
                if q:
                    self.log(f"→ карантин: {q}")
        messagebox.showinfo("Готово", f"Найдено подозрительных plist'ов: {found}")
        self._refresh_mac_launch_items()

    # =========================================================
    # macOS: Quarantine-флаги
    # =========================================================
    def _build_mac_quarantine_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🏷️ Флаги карантина  ")

        head = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        head.pack(fill="x", pady=(6, 10))
        ttk.Label(head, text="Атрибут com.apple.quarantine на macOS",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(head, text="Главный «замок» приложений.",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 0))

        btns = ttk.Frame(tab)
        btns.pack(fill="x", pady=(0, 8))
        ttk.Button(btns, text="👁 Показать флаг", style="TButton",
                   command=self._mac_show_xattr).pack(side="left", padx=(0, 4))
        ttk.Button(btns, text="🔓 Снять флаг с файла", style="Accent.TButton",
                   command=self._mac_clear_xattr_file).pack(side="left", padx=4)
        ttk.Button(btns, text="📂 Снять с папки", style="Accent.TButton",
                   command=self._mac_clear_xattr_dir).pack(side="left", padx=4)

        hosts_frame = ttk.LabelFrame(tab, text=" /etc/hosts ", padding=8)
        hosts_frame.pack(fill="x", pady=8)
        ttk.Button(hosts_frame, text="👁 Просмотр", style="TButton",
                   command=self._mac_show_hosts).pack(side="left", padx=(0, 4))
        ttk.Button(hosts_frame, text="🔄 Восстановить стандартный", style="Danger.TButton",
                   command=self._mac_restore_hosts).pack(side="left")

        self.mac_xattr_output = tk.Text(tab, height=12, wrap="word",
                                        bg=self.pal["console_bg"], fg=self.pal["console_fg"],
                                        insertbackground="#fff",
                                        font=("Menlo", 9), borderwidth=0)
        self.mac_xattr_output.pack(fill="both", expand=True, pady=(8, 0))

    def _mac_show_xattr(self):
        path = filedialog.askopenfilename(title="Выберите файл")
        if not path:
            return
        ok, out = _run(["xattr", "-l", path])
        self.mac_xattr_output.delete("1.0", "end")
        self.mac_xattr_output.insert("1.0", f"{path}\n\n{out or '(нет атрибутов)'}")
        self.log(f"xattr -l: {path}")

    def _mac_clear_xattr_file(self):
        path = filedialog.askopenfilename(title="Выберите файл / приложение")
        if not path:
            return
        if path.endswith(".app"):
            ok, msg = mac_xattr_clear_dir(path)
        else:
            ok, msg = mac_xattr_clear(path)
        self.mac_xattr_output.delete("1.0", "end")
        self.mac_xattr_output.insert("1.0", f"{path}\n{msg or 'OK'}")
        self.log(f"xattr -d: {path} — {'OK' if ok else msg[:100]}")
        (messagebox.showinfo("Готово", msg or "OK") if ok
         else messagebox.showerror("Ошибка", str(msg)[:300]))

    def _mac_clear_xattr_dir(self):
        folder = filedialog.askdirectory(title="Выберите папку")
        if not folder:
            return
        ok, msg = mac_xattr_clear_dir(folder)
        self.mac_xattr_output.delete("1.0", "end")
        self.mac_xattr_output.insert("1.0", f"{folder}\n{msg}")
        self.log(f"xattr dir: {msg}")
        messagebox.showinfo("Готово", msg)

    def _mac_show_hosts(self):
        try:
            with open("/etc/hosts", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as e:
            content = f"Ошибка: {e}"
        self.mac_xattr_output.delete("1.0", "end")
        self.mac_xattr_output.insert("1.0", f"/etc/hosts\n\n{content}")

    def _mac_restore_hosts(self):
        if not messagebox.askyesno("hosts",
                                   "Заменить /etc/hosts стандартным содержимым?"):
            return
        content = (
            "##\n# Host Database\n##\n"
            "127.0.0.1\tlocalhost\n"
            "255.255.255.255\tbroadcasthost\n"
            "::1\tlocalhost\n"
        )
        script = (
            'do shell script "cp /etc/hosts /etc/hosts.bak.$(date +%s) && '
            f"printf '%s' '{content}' > /etc/hosts\" with administrator privileges"
        )
        ok, out = _run(["osascript", "-e", script], timeout=60)
        self.log(f"hosts восстановлен: {'OK' if ok else out[:120]}")
        (messagebox.showinfo("Готово", "hosts восстановлен") if ok
         else messagebox.showerror("Ошибка", out[:400]))

    # =========================================================
    # Windows: Автозагрузка
    # =========================================================
    def _build_startup_tab_windows(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🚀 Автозагрузка  ")

        top = ttk.Frame(tab)
        top.pack(fill="x", pady=6)
        ttk.Button(top, text="🔄 Обновить", style="TButton",
                   command=self._refresh_startup_win).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="🗑️ Удалить выбранное", style="Danger.TButton",
                   command=self._delete_startup_win).pack(side="left")

        columns = ("hive", "name", "value")
        self.startup_tree = ttk.Treeview(tab, columns=columns,
                                         show="headings", height=18)
        for c, t, w in [("hive", "Источник", 200),
                        ("name", "Имя", 220),
                        ("value", "Команда", 560)]:
            self.startup_tree.heading(c, text=t)
            self.startup_tree.column(c, width=w)
        self.startup_tree.pack(fill="both", expand=True, pady=(6, 0))
        self._startup_entries = {}
        self._refresh_startup_win()

    def _refresh_startup_win(self):
        for row in self.startup_tree.get_children():
            self.startup_tree.delete(row)
        self._startup_entries.clear()
        if not IS_WINDOWS:
            return
        for hive, path in [("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                           ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run")]:
            ok, out = reg_query(hive, path)
            if not ok:
                continue
            for line in out.splitlines()[1:]:
                line = line.strip()
                if not line or "REG_" not in line:
                    continue
                parts = [p.strip() for p in line.split("    ") if p.strip()]
                if len(parts) < 3:
                    continue
                name, _rt, value = parts[0], parts[1], "    ".join(parts[2:])
                iid = self.startup_tree.insert("", "end",
                                               values=(f"{hive}\\Run", name, value))
                self._startup_entries[iid] = (hive, path, name)
        self.log(f"Автозагрузка: {len(self._startup_entries)}")

    def _delete_startup_win(self):
        sel = self.startup_tree.selection()
        if not sel:
            return
        hive, path, name = self._startup_entries[sel[0]]
        if not messagebox.askyesno("Удалить", f"Удалить «{name}»?"):
            return
        ok, msg = reg_delete(hive, path, name)
        if ok:
            self.log(f"Удалена автозагрузка: {name}")
            self._refresh_startup_win()
        else:
            messagebox.showerror("Ошибка", msg)

    # =========================================================
    # Windows: Службы
    # =========================================================
    def _build_services_tab_windows(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ⚙️ Службы  ")

        top = ttk.Frame(tab)
        top.pack(fill="x", pady=6)
        ttk.Button(top, text="🔄 Обновить", style="TButton",
                   command=self._refresh_services_win).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="▶ Запустить", style="Success.TButton",
                   command=lambda: self._service_action_win("start")).pack(side="left", padx=4)
        ttk.Button(top, text="⏹ Остановить", style="Danger.TButton",
                   command=lambda: self._service_action_win("stop")).pack(side="left", padx=4)
        ttk.Button(top, text="🤖 Авто", style="TButton",
                   command=lambda: self._service_action_win("config", "start= auto")).pack(side="left", padx=4)
        ttk.Button(top, text="🚫 Отключить", style="Danger.TButton",
                   command=lambda: self._service_action_win("config", "start= disabled")).pack(side="left", padx=4)

        self.services_list = tk.Listbox(tab, activestyle="dotbox",
                                        bg=self.pal["surface"], fg=self.pal["text"],
                                        selectbackground=self.pal["accent"],
                                        selectforeground="#ffffff",
                                        borderwidth=0, highlightthickness=0,
                                        font=("Consolas", 10))
        self.services_list.pack(fill="both", expand=True, pady=(6, 0))
        self._refresh_services_win()

    def _refresh_services_win(self):
        self.services_list.delete(0, "end")
        if not IS_WINDOWS:
            return
        ok, out = sc_run("query", "type=", "service", "state=", "all")
        if not ok:
            return
        for line in out.splitlines():
            if "SERVICE_NAME" in line:
                try:
                    name = line.split(":", 1)[1].strip()
                    self.services_list.insert("end", name)
                except Exception:
                    pass
        self.log(f"Службы: {self.services_list.size()}")

    def _service_action_win(self, action, *extra):
        sel = self.services_list.curselection()
        if not sel:
            return
        name = self.services_list.get(sel[0])
        args = [action, name]
        if extra:
            args.extend(extra[0].split())
        ok, msg = sc_run(*args)
        if ok:
            self.log(f"Служба {name}: {action} — OK")
            messagebox.showinfo("Готово", f"{name}: {action}")
        else:
            self.log(f"Служба {name}: {action} — ошибка")
            messagebox.showerror("Ошибка", msg)
        self._refresh_services_win()

    # =========================================================
    # Сканер
    # =========================================================
    def _build_scanner_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔍 Сканер  ")

        top = ttk.Frame(tab)
        top.pack(fill="x", pady=6)
        ttk.Button(top, text="📄 Сканировать файл", style="Accent.TButton",
                   command=self._scan_file_dialog).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="📂 Сканировать папку", style="Accent.TButton",
                   command=self._scan_folder_dialog).pack(side="left", padx=4)
        ttk.Button(top, text="🖥️ Сканировать систему", style="Danger.TButton",
                   command=self._scan_system_dialog).pack(side="left", padx=4)
        ttk.Button(top, text="🔄 Обновить сигнатуры", style="TButton",
                   command=self._reload_signatures).pack(side="right")

        self.scan_text = tk.Text(tab, height=20, wrap="word",
                                 bg=self.pal["console_bg"], fg=self.pal["console_fg"],
                                 insertbackground="#fff", borderwidth=0,
                                 font=("Consolas", 9))
        self.scan_text.pack(fill="both", expand=True, pady=(6, 0))
        self.scan_text.tag_config("hit", foreground="#ff6b6b")
        self.scan_text.tag_config("clean", foreground="#7ec699")
        self.scan_text.tag_config("info", foreground="#fbbf24")

    def _reload_signatures(self):
        self.signatures = load_signatures()
        messagebox.showinfo("Сигнатуры", f"Загружено: {len(self.signatures)}")
        self.log(f"Сигнатуры перезагружены: {len(self.signatures)}")
        if hasattr(self, "_redraw_header"):
            self._redraw_header()

    def _scan_file_dialog(self):
        path = filedialog.askopenfilename(title="Выберите файл")
        if path:
            self._process_file(path, show=True)

    def _scan_folder_dialog(self):
        path = filedialog.askdirectory(title="Выберите папку")
        if not path:
            return
        count = hits = 0
        for root, _, files in os.walk(path):
            for f in files:
                p = os.path.join(root, f)
                if self._process_file(p, show=False):
                    hits += 1
                count += 1
        self._scan_write(f"\n--- Сканирование папки завершено: {count} файлов, "
                         f"обнаружено {hits} ---\n", "hit" if hits else "clean")

    # ---------- Сканирование системы ----------
    def _system_paths(self):
        paths = []
        if IS_WINDOWS:
            for env in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)",
                        "APPDATA", "LOCALAPPDATA", "TEMP", "USERPROFILE"):
                p = os.environ.get(env)
                if p and os.path.isdir(p) and p not in paths:
                    paths.append(p)
        else:
            for p in ["/Applications", "/Library", "/usr/local", "/opt",
                      os.path.expanduser("~/Library"),
                      os.path.expanduser("~/Downloads"),
                      os.path.expanduser("~/Desktop")]:
                if os.path.isdir(p) and p not in paths:
                    paths.append(p)
        return paths

    def _scan_system_dialog(self):
        if self._system_scan_running:
            messagebox.showwarning("Сканирование", "Сканирование уже идёт.")
            return
        paths = self._system_paths()
        if not paths:
            messagebox.showerror("Сканирование", "Не найдено системных папок.")
            return
        if not messagebox.askyesno(
                "Сканирование системы",
                f"Будут просканированы {len(paths)} папок:\n\n"
                + "\n".join("• " + p for p in paths) +
                "\n\nЭто может занять несколько минут. Продолжить?"):
            return
        self.scan_text.delete("1.0", "end")
        self._scan_write(f"🖥️ Сканирование системы — {len(paths)} папок\n", "info")
        self._system_scan_running = True
        threading.Thread(target=self._scan_system_worker,
                         args=(paths,), daemon=True).start()

    def _scan_system_worker(self, paths):
        skip_dirs = {"node_modules", ".git", "__pycache__",
                     "Cache", "cache", "Caches", "Temp", "temp"}
        total = hits = 0
        try:
            for base in paths:
                self.after(0, lambda b=base: self._scan_write(f"\n>>> {b}\n", "info"))
                for root, dirs, files in os.walk(base):
                    dirs[:] = [d for d in dirs if d not in skip_dirs]
                    for f in files:
                        if not self._system_scan_running:
                            return
                        p = os.path.join(root, f)
                        total += 1
                        found, findings = self._process_file_silent(p)
                        if found:
                            hits += 1
                            msg = (f"[ОБНАРУЖЕНО] {p}\n    "
                                   + "\n    ".join(findings) + "\n")
                            self.after(0, lambda m=msg: self._scan_write(m, "hit"))
                        if total % 250 == 0:
                            summary = f"  … обработано {total}, обнаружений {hits}\n"
                            self.after(0, lambda s=summary: self._scan_write(s, "info"))
        except Exception as e:
            self.log(f"Сканирование системы — ошибка: {e}")
        finally:
            final = (f"\n--- Готово: {total} файлов, {hits} обнаружений ---\n")
            self.after(0, lambda f=final, h=hits: self._scan_write(
                f, "hit" if h else "clean"))
            self.after(0, lambda: setattr(self, "_system_scan_running", False))

    def _process_file_silent(self, filepath):
        findings = scan_file(filepath, self.signatures)
        if findings:
            self.log(f"ОБНАРУЖЕНО: {filepath}")
            quarantine_file(filepath)
            return True, findings
        return False, findings

    def _process_file(self, filepath, show=True):
        findings = scan_file(filepath, self.signatures)
        if findings:
            msg = f"[ОБНАРУЖЕНО] {filepath}\n    " + "\n    ".join(findings)
            self._scan_write(msg + "\n", "hit")
            self.log(f"ОБНАРУЖЕНО: {filepath}")
            dest = quarantine_file(filepath)
            if dest:
                self._scan_write(f"    → карантин: {dest}\n", "hit")
                self.log(f"Карантин: {dest}")
            return True
        if show:
            self._scan_write(f"[чисто] {filepath}\n", "clean")
            self.log(f"Чисто: {filepath}")
        return False

    def _scan_write(self, text, tag=None):
        self.scan_text.insert("end", text, tag)
        self.scan_text.see("end")

    # =========================================================
    # Мониторинг
    # =========================================================
    def _build_monitor_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  👁 Мониторинг  ")

        card = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        card.pack(fill="x", pady=6)
        ttk.Label(card, text="Слежение за папкой в реальном времени",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(card, text="Опрос раз в 2 секунды.",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 0))

        self.monitor_status = ttk.Label(tab, text="Мониторинг выключен",
                                        font=("Segoe UI", 11, "bold"))
        self.monitor_status.pack(pady=12)
        self.monitor_btn = ttk.Button(tab, text="📂 Выбрать папку и включить",
                                      style="Accent.TButton",
                                      command=self._toggle_monitor)
        self.monitor_btn.pack(pady=6, ipady=4)
        self.monitor_info = ttk.Label(tab, text="", style="Dim.TLabel")
        self.monitor_info.pack(pady=4)

    def _toggle_monitor(self):
        if self.monitoring:
            self.monitoring = False
            self.monitor_btn.config(text="📂 Выбрать папку и включить")
            self.monitor_status.config(text="Мониторинг выключен")
            self.monitor_info.config(text="")
            self.log("Мониторинг остановлен")
            return
        folder = filedialog.askdirectory(title="Выберите папку")
        if not folder:
            return
        self.monitor_folder = folder
        self.monitor_state = {}
        self.monitoring = True
        self.monitor_btn.config(text="⏹ Остановить мониторинг")
        self.monitor_status.config(text=f"Мониторинг ВКЛЮЧЁН:\n{folder}")
        self.log(f"Мониторинг: {folder}")
        self._poll_folder()

    def _poll_folder(self):
        if not self.monitoring or not self.monitor_folder:
            return
        scanned = hits = 0
        try:
            for root, _, files in os.walk(self.monitor_folder):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        m = os.path.getmtime(p)
                    except OSError:
                        continue
                    if self.monitor_state.get(p) != m:
                        self.monitor_state[p] = m
                        scanned += 1
                        if self._process_file(p, show=False):
                            hits += 1
        except Exception as e:
            self.log(f"Мониторинг — ошибка: {e}")
        self.monitor_info.config(
            text=f"Последний проход: {datetime.datetime.now():%H:%M:%S} — "
                 f"проверено {scanned}, обнаружено {hits}")
        self.after(2000, self._poll_folder)

    # =========================================================
    # Карантин
    # =========================================================
    def _build_quarantine_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🗑️ Карантин  ")

        top = ttk.Frame(tab)
        top.pack(fill="x", pady=6)
        ttk.Button(top, text="🔄 Обновить", style="TButton",
                   command=self._refresh_quarantine).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="↩ Восстановить", style="Success.TButton",
                   command=self._restore_quarantine).pack(side="left", padx=4)
        ttk.Button(top, text="🗑️ Удалить", style="Danger.TButton",
                   command=self._delete_quarantine).pack(side="left", padx=4)
        ttk.Button(top, text="📂 Открыть папку", style="TButton",
                   command=lambda: self._open_folder(QUARANTINE_DIR)).pack(side="right")

        self.quarantine_list = tk.Listbox(tab, activestyle="dotbox",
                                          bg=self.pal["surface"], fg=self.pal["text"],
                                          selectbackground=self.pal["accent"],
                                          selectforeground="#ffffff",
                                          borderwidth=0, highlightthickness=0,
                                          font=("Consolas", 10))
        self.quarantine_list.pack(fill="both", expand=True, pady=(6, 0))
        self._refresh_quarantine()

    def _refresh_quarantine(self):
        self.quarantine_list.delete(0, "end")
        try:
            for f in sorted(os.listdir(QUARANTINE_DIR)):
                self.quarantine_list.insert("end", f)
        except Exception:
            pass

    def _restore_quarantine(self):
        sel = self.quarantine_list.curselection()
        if not sel:
            return
        fname = self.quarantine_list.get(sel[0])
        src = os.path.join(QUARANTINE_DIR, fname)
        target = filedialog.asksaveasfilename(
            title="Восстановить как…",
            initialfile=fname.replace(".quarantined", ""))
        if not target:
            return
        try:
            shutil.move(src, target)
            self.log(f"Восстановлен: {target}")
            self._refresh_quarantine()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _delete_quarantine(self):
        sel = self.quarantine_list.curselection()
        if not sel:
            return
        fname = self.quarantine_list.get(sel[0])
        if not messagebox.askyesno("Удалить", f"Удалить «{fname}» окончательно?"):
            return
        try:
            os.remove(os.path.join(QUARANTINE_DIR, fname))
            self.log(f"Удалён из карантина: {fname}")
            self._refresh_quarantine()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    # =========================================================
    # Отладчики
    # =========================================================
    def _build_debuggers_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  🔬 Отладчики  ")

        head = ttk.Frame(tab, style="Card.TFrame", padding=(18, 14))
        head.pack(fill="x", pady=(6, 10))
        ttk.Label(head, text="Обнаружение отладчиков и RE-инструментов",
                  style="Header.TLabel").pack(anchor="w")
        ttk.Label(head,
                  text="Проверка запущенных процессов + защита от отладки самой утилиты",
                  style="SubHeader.TLabel").pack(anchor="w", pady=(4, 0))

        self_frame = ttk.LabelFrame(tab, text=" Самопроверка процесса ", padding=10)
        self_frame.pack(fill="x", pady=(0, 8))
        self.debug_self_label = ttk.Label(self_frame, text="—",
                                           font=("Segoe UI", 11, "bold"))
        self.debug_self_label.pack(side="left", padx=(0, 12))
        ttk.Button(self_frame, text="🔄 Проверить", style="TButton",
                   command=self._check_self_debug).pack(side="left", padx=4)
        ttk.Button(self_frame, text="🛡️ Включить anti-debug", style="Success.TButton",
                   command=self._enable_anti_debug).pack(side="left", padx=4)

        sys_frame = ttk.LabelFrame(tab, text=" Запущенные отладчики в системе ", padding=10)
        sys_frame.pack(fill="both", expand=True, pady=(0, 8))

        top = ttk.Frame(sys_frame)
        top.pack(fill="x", pady=(0, 6))
        ttk.Button(top, text="🔄 Сканировать", style="Accent.TButton",
                   command=self._scan_for_debuggers).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="🛑 Завершить выбранный", style="Danger.TButton",
                   command=self._kill_debugger).pack(side="left", padx=4)
        ttk.Button(top, text="🗑️ Автоудаление всех", style="Danger.TButton",
                   command=self._kill_all_debuggers).pack(side="left", padx=4)

        self.debug_status = ttk.Label(top, text="", style="Dim.TLabel")
        self.debug_status.pack(side="right", padx=6)

        cols = ("process", "matched")
        self.debugger_tree = ttk.Treeview(sys_frame, columns=cols,
                                           show="headings", height=14)
        self.debugger_tree.heading("process", text="Процесс")
        self.debugger_tree.heading("matched", text="Совпадение с базой")
        self.debugger_tree.column("process", width=320)
        self.debugger_tree.column("matched", width=320)
        self.debugger_tree.pack(fill="both", expand=True)

        info = ttk.Frame(tab, style="Card.TFrame", padding=(18, 10))
        info.pack(fill="x")
        ttk.Label(info,
                  text="ℹ  База: x64dbg · OllyDbg · WinDbg · IDA · Cheat Engine · "
                       "Process Hacker · Frida · LLDB · radare2 · Hopper · gdb",
                  style="SubHeader.TLabel").pack(anchor="w")

        self._check_self_debug()

    def _check_self_debug(self):
        debugged, signals = is_self_debugged()
        if debugged:
            self.debug_self_label.config(text="⚠  ПРОЦЕСС ОТЛАЖИВАЕТСЯ",
                                         foreground="#ff6b6b")
            for s in signals:
                self.log(f"Anti-debug: {s}")
        else:
            self.debug_self_label.config(text="✔  Отладчик не обнаружен",
                                         foreground="#7ec699")
            self.log("Anti-debug: чисто")

    def _enable_anti_debug(self):
        if not IS_WINDOWS:
            messagebox.showinfo("Anti-debug",
                                "Активная защита реализована для Windows.\n"
                                "На macOS — только пассивная проверка.")
            return
        try:
            k32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll
            current_thread = k32.GetCurrentThread()
            ntdll.NtSetInformationThread(current_thread, 17, None, 0)
            self.log("Anti-debug: THREAD_HIDE_FROM_DEBUGGER включён")
            messagebox.showinfo("Anti-debug", "✔ Активная защита включена")
        except Exception as e:
            messagebox.showerror("Anti-debug", f"Не удалось: {e}")

    def _scan_for_debuggers(self):
        for row in self.debugger_tree.get_children():
            self.debugger_tree.delete(row)
        hits = detect_debuggers()
        if not hits:
            self.debug_status.config(text="чисто")
            self.log("Отладчики: не обнаружено")
            messagebox.showinfo("Скан отладчиков",
                                "✔ Известных отладчиков не найдено.")
            return
        for proc, pattern in hits:
            self.debugger_tree.insert("", "end", values=(proc, pattern))
            self.log(f"Отладчик: {proc} (совпадение: {pattern})")
        self.debug_status.config(text=f"найдено: {len(hits)}")
        messagebox.showwarning("Скан отладчиков",
                               f"⚠ Обнаружено отладчиков: {len(hits)}")

    def _kill_debugger(self):
        sel = self.debugger_tree.selection()
        if not sel:
            return
        proc_name = self.debugger_tree.item(sel[0], "values")[0]
        if not messagebox.askyesno("Завершить процесс",
                                    f"Завершить процесс «{proc_name}»?"):
            return
        try:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/F", "/IM", proc_name],
                               capture_output=True, timeout=10)
            else:
                subprocess.run(["killall", "-9", proc_name],
                               capture_output=True, timeout=10)
            self.log(f"Процесс завершён: {proc_name}")
            self._scan_for_debuggers()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _kill_all_debuggers(self):
        hits = detect_debuggers()
        if not hits:
            messagebox.showinfo("Автоудаление", "Нечего удалять — отладчиков нет.")
            return
        names = sorted({h[0] for h in hits})
        if not messagebox.askyesno(
                "Автоудаление",
                f"Завершить все обнаруженные процессы ({len(names)})?\n\n"
                + "\n".join("• " + n for n in names) +
                "\n\nЭто действие необратимо. Продолжить?"):
            return
        killed = failed = 0
        for name in names:
            try:
                if IS_WINDOWS:
                    r = subprocess.run(["taskkill", "/F", "/IM", name],
                                       capture_output=True, timeout=10)
                else:
                    r = subprocess.run(["killall", "-9", name],
                                       capture_output=True, timeout=10)
                if r.returncode == 0:
                    killed += 1
                    self.log(f"Автоудаление: завершён {name}")
                else:
                    failed += 1
                    self.log(f"Автоудаление: не удалось {name}")
            except Exception as e:
                failed += 1
                self.log(f"Автоудаление: ошибка {name}: {e}")
        messagebox.showinfo("Автоудаление",
                            f"✔ Завершено: {killed}\n✖ Ошибок: {failed}")
        self._scan_for_debuggers()

    # =========================================================
    # Логи
    # =========================================================
    def _build_logs_tab(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  📝 Логи  ")

        top = ttk.Frame(tab)
        top.pack(fill="x", pady=6)
        ttk.Button(top, text="🧹 Очистить вид", style="TButton",
                   command=self._clear_log_view).pack(side="left", padx=(0, 4))
        ttk.Button(top, text="📂 Открыть папку логов", style="TButton",
                   command=lambda: self._open_folder(LOG_DIR)).pack(side="left")

        self.log_text = tk.Text(tab, wrap="word", state="disabled",
                                bg=self.pal["console_bg"], fg=self.pal["console_fg"],
                                insertbackground="#fff", borderwidth=0,
                                font=("Consolas", 9))
        self.log_text.pack(fill="both", expand=True, pady=(6, 0))

    def _clear_log_view(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self.log_lines.clear()


# =============================================================
#  Запуск
# =============================================================
def _shutdown(sig=None, frame=None):
    try:
        app.on_close()
    except Exception:
        pass

try:
    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)
except Exception:
    pass

if __name__ == "__main__":
    app = CounterUnlocker()
    app.mainloop()
