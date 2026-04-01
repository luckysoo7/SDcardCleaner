"""
SD 카드 안전 삭제 + 포맷 도구
- 이동식 드라이브(SD 카드, USB)를 감지하여 무작위 데이터로 덮어씌운 후 포맷
- Windows 전용 (ctypes + Kernel32 API 사용)
- 반드시 관리자 권한으로 실행 (자동으로 UAC 요청)
"""

import os
import sys
import ctypes
import ctypes.wintypes as wintypes
import subprocess
import threading
import queue
import tempfile
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from typing import Callable, Optional

# ──────────────────────────────────────────────
# 상수 정의
# ──────────────────────────────────────────────

CHUNK_SIZE = 4 * 1024 * 1024          # 4MB 청크 (512바이트 배수이므로 정렬 OK)
MIN_DRIVE_SIZE_BYTES = 100 * 1024 * 1024  # 100MB 미만 드라이브 제외
SYSTEM_DRIVES = {'C'}                  # 절대 삭제 불가 드라이브

# Windows Kernel32 상수
GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
# 64비트 안전 INVALID_HANDLE_VALUE: c_void_p 기준으로 정의
# (ctypes 기본 반환형 c_int는 32비트라 64비트 핸들 비교 오류 발생)
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# IOCTL 코드
IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
FSCTL_LOCK_VOLUME     = 0x00090018  # 볼륨 잠금 (직접 쓰기 전 필수)
FSCTL_DISMOUNT_VOLUME = 0x00090020  # 볼륨 마운트 해제

# CreateFileW 플래그
# FILE_FLAG_NO_BUFFERING 미사용: bytes 버퍼가 512바이트 정렬 보장 안 됨 → ERROR 87
FILE_FLAG_WRITE_THROUGH = 0x80000000


# ──────────────────────────────────────────────
# 데이터 클래스
# ──────────────────────────────────────────────

@dataclass
class DriveInfo:
    letter: str        # 드라이브 문자 (예: 'E')
    label: str         # 볼륨 레이블 (예: 'SD카드')
    size_bytes: int    # 총 용량 (바이트)
    fstype: str        # 파일시스템 (예: 'FAT32')

    @property
    def size_gb(self) -> float:
        return self.size_bytes / (1024 ** 3)

    @property
    def display_name(self) -> str:
        label = self.label or "레이블 없음"
        return f"{self.letter}:  [{label}]  {self.size_gb:.1f} GB  {self.fstype}  (이동식)"


# ──────────────────────────────────────────────
# 1. AdminChecker — 관리자 권한 확인 및 UAC 재실행
# ──────────────────────────────────────────────

class AdminChecker:
    @staticmethod
    def is_admin() -> bool:
        """현재 프로세스가 관리자 권한인지 확인"""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def relaunch_as_admin() -> None:
        """
        UAC 프롬프트를 띄워 현재 스크립트를 관리자 권한으로 재실행.
        성공하면 현재 프로세스 종료.
        이 시점에 tkinter 루트가 없으므로 messagebox 대신 print 사용.
        """
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,           # hwnd
            "runas",        # verb: 관리자 권한 요청
            sys.executable, # 실행 파일 (python.exe)
            f'"{script}" {params}',
            None,
            1               # SW_NORMAL
        )
        # ret > 32 이면 성공적으로 새 프로세스 시작됨
        if ret <= 32:
            print(
                "[오류] 관리자 권한을 획득하지 못했습니다.\n"
                "프로그램을 마우스 우클릭 → '관리자로 실행' 해주세요."
            )
        sys.exit(0)  # 현재 (비권한) 프로세스 종료


# ──────────────────────────────────────────────
# 2. DriveDetector — 이동식 드라이브 감지
# ──────────────────────────────────────────────

class DriveDetector:
    def get_removable_drives(self) -> list:
        """
        이동식 드라이브(SD 카드, USB 등)만 감지해서 DriveInfo 리스트 반환.
        시스템 드라이브(C:) 및 100MB 미만 드라이브는 제외.
        """
        drives = []

        # wmic으로 이동식 드라이브 목록 조회 (DriveType=2)
        removable_letters = self._get_removable_letters_via_wmic()

        for letter in removable_letters:
            if letter.upper() in SYSTEM_DRIVES:
                continue  # C: 등 시스템 드라이브 절대 제외

            mountpoint = f"{letter}:\\"
            try:
                # 드라이브 용량 조회
                free_bytes  = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    mountpoint,
                    ctypes.byref(free_bytes),
                    ctypes.byref(total_bytes),
                    None
                )
                size = total_bytes.value
                if size < MIN_DRIVE_SIZE_BYTES:
                    continue

                label = self._get_volume_label(letter)
                fstype = self._get_fstype(letter)

                drives.append(DriveInfo(
                    letter=letter.upper(),
                    label=label,
                    size_bytes=size,
                    fstype=fstype,
                ))
            except Exception:
                continue

        return drives

    def _get_removable_letters_via_wmic(self) -> list:
        """
        GetDriveTypeW로 이동식 드라이브(DRIVE_REMOVABLE=2) 문자 목록 반환.
        wmic 대신 ctypes 직접 호출 → 인코딩 문제 없음, Windows 11 호환.
        """
        import string
        DRIVE_REMOVABLE = 2
        letters = []
        for letter in string.ascii_uppercase:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(f"{letter}:\\")
            if drive_type == DRIVE_REMOVABLE:
                letters.append(letter)
        return letters

    def _get_volume_label(self, letter: str) -> str:
        """볼륨 레이블 조회"""
        buf = ctypes.create_unicode_buffer(256)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            f"{letter}:\\", buf, 256,
            None, None, None, None, 0
        )
        return buf.value if ok else ""

    def _get_fstype(self, letter: str) -> str:
        """파일시스템 유형 조회 (FAT32, exFAT, NTFS 등)"""
        buf_label = ctypes.create_unicode_buffer(256)
        buf_fs    = ctypes.create_unicode_buffer(256)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            f"{letter}:\\",
            buf_label, 256,
            None, None, None,
            buf_fs, 256
        )
        return buf_fs.value if ok else "알 수 없음"


# ──────────────────────────────────────────────
# 3. SecureWiper — 원시 볼륨 덮어쓰기 엔진
# ──────────────────────────────────────────────

class SecureWiper:
    """
    Windows Kernel32 API로 볼륨을 직접 열어 무작위 데이터로 덮어씀.
    모드: '1pass' = 1-pass 랜덤, 'dod3' = DoD 3-pass
    """

    def __init__(
        self,
        drive_info: DriveInfo,
        mode: str,
        progress_cb: Callable,   # (done_bytes, total_bytes, pass_label) → None
        status_cb: Callable,     # (message: str) → None
    ):
        self.drive = drive_info
        self.mode = mode
        self.progress_cb = progress_cb
        self.status_cb = status_cb
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    def wipe(self) -> bool:
        """
        덮어쓰기 실행. 성공이면 True, 취소/오류면 False 반환.
        예외 발생 시 그대로 raise (WipeWorker에서 처리).
        """
        handle = self._open_volume()
        try:
            # 볼륨 잠금 + 마운트 해제: 직접 쓰기 전 반드시 필요 (없으면 오류 코드 5)
            self._lock_volume(handle)
            self._dismount_volume(handle)
            total = self._get_volume_size(handle)

            if self.mode == 'dod3':
                passes = [
                    ("1/3  랜덤 데이터",   lambda n: os.urandom(n)),
                    ("2/3  0xFF 채우기",   lambda n: b'\xff' * n),
                    ("3/3  랜덤 데이터",   lambda n: os.urandom(n)),
                ]
            else:
                passes = [
                    ("1/1  랜덤 데이터",   lambda n: os.urandom(n)),
                ]

            for label, fill_fn in passes:
                if self._cancelled:
                    return False
                self._run_pass(handle, total, label, fill_fn)

            return not self._cancelled

        finally:
            ctypes.windll.kernel32.CloseHandle(handle)

    # ── 내부 메서드 ──────────────────────────────

    def _open_volume(self):
        """
        볼륨을 쓰기 전용으로 열기.
        경로 형식: "\\\\.\\{드라이브문자}:"  (예: \\\\.\\E:)
        """
        path = f"\\\\.\\{self.drive.letter}:"

        # restype 명시: HANDLE은 포인터 크기이므로 c_void_p로 설정해야
        # 64비트에서 반환값이 c_int(32비트)로 잘려 INVALID_HANDLE_VALUE 비교가 깨지는 것을 방지
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateFileW.restype = ctypes.c_void_p

        handle = kernel32.CreateFileW(
            path,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_WRITE_THROUGH,  # NO_BUFFERING 제거: 버퍼 정렬 강제 → bytes 객체 전달 시 오류 87
            None
        )
        if handle is None or handle == INVALID_HANDLE_VALUE:
            err = ctypes.GetLastError()
            raise PermissionError(
                f"볼륨 {self.drive.letter}: 열기 실패 (오류 코드: {err})\n"
                "관리자 권한으로 실행했는지 확인하세요."
            )
        return handle

    def _lock_volume(self, handle) -> None:
        """
        FSCTL_LOCK_VOLUME: 볼륨을 독점 잠금.
        Windows는 이 호출 없이 볼륨에 직접 쓰면 ERROR_ACCESS_DENIED(5)를 반환.
        """
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle, FSCTL_LOCK_VOLUME,
            None, 0, None, 0,
            ctypes.byref(returned), None
        )
        if not ok:
            err = ctypes.GetLastError()
            raise PermissionError(
                f"볼륨 잠금 실패 (오류 코드: {err})\n"
                "탐색기나 다른 프로그램이 이 드라이브를 사용 중일 수 있습니다.\n"
                "해당 드라이브의 창을 모두 닫고 다시 시도하세요."
            )

    def _dismount_volume(self, handle) -> None:
        """
        FSCTL_DISMOUNT_VOLUME: 볼륨 파일시스템을 언마운트.
        쓰기 중 파일시스템 캐시와 충돌을 방지.
        실패해도 치명적이지 않으므로 오류를 무시.
        """
        returned = wintypes.DWORD(0)
        ctypes.windll.kernel32.DeviceIoControl(
            handle, FSCTL_DISMOUNT_VOLUME,
            None, 0, None, 0,
            ctypes.byref(returned), None
        )

    def _get_volume_size(self, handle) -> int:
        """
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX로 볼륨 전체 크기(바이트) 조회.
        DISK_GEOMETRY_EX 구조체: Geometry(24바이트) + DiskSize(8바이트 LARGE_INTEGER)
        """
        buf = ctypes.create_string_buffer(64)
        returned = wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.DeviceIoControl(
            handle,
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            None, 0,
            buf, len(buf),
            ctypes.byref(returned),
            None
        )
        if not ok:
            # IOCTL 실패 시 DriveInfo에 저장된 크기로 폴백
            return self.drive.size_bytes

        # DISK_GEOMETRY_EX.DiskSize는 오프셋 24에 위치
        disk_size = ctypes.c_int64.from_buffer_copy(buf, 24).value
        return disk_size if disk_size > 0 else self.drive.size_bytes

    def _run_pass(self, handle, total_bytes: int, label: str, fill_fn: Callable):
        """단일 패스 실행: 파일 포인터를 처음으로 되돌린 뒤 청크 단위로 씀"""
        # SetFilePointerEx: LARGE_INTEGER는 구조체로 전달해야 함
        # c_longlong을 직접 넘기면 일부 플랫폼에서 인자 해석이 틀릴 수 있음
        class LARGE_INTEGER(ctypes.Structure):
            _fields_ = [("QuadPart", ctypes.c_longlong)]

        li = LARGE_INTEGER(QuadPart=0)
        ctypes.windll.kernel32.SetFilePointerEx(
            handle,
            li,
            None,
            0  # FILE_BEGIN
        )

        written_total = 0
        while written_total < total_bytes:
            if self._cancelled:
                return

            remaining = total_bytes - written_total
            chunk = min(CHUNK_SIZE, remaining)

            # 512바이트(섹터 크기) 배수로 정렬 — WriteFile 요구사항
            aligned = (chunk // 512) * 512
            if aligned == 0:
                break

            data = fill_fn(aligned)

            # WriteFile 호출
            bytes_written = wintypes.DWORD(0)
            ok = ctypes.windll.kernel32.WriteFile(
                handle,
                data,
                aligned,
                ctypes.byref(bytes_written),
                None
            )
            if not ok:
                err = ctypes.GetLastError()
                # 1167 = ERROR_DEVICE_NOT_CONNECTED (USB 뽑힘 등)
                if err == 1167:
                    raise IOError("드라이브 연결이 끊어졌습니다. SD 카드를 확인하세요.")
                raise IOError(f"WriteFile 실패 (오류 코드: {err})")

            written_total += bytes_written.value
            self.progress_cb(written_total, total_bytes, label)


# ──────────────────────────────────────────────
# 4. DiskFormatter — diskpart 스크립트로 포맷
# ──────────────────────────────────────────────

class DiskFormatter:
    """
    diskpart를 이용해 드라이브를 포맷.
    FAT32 / exFAT 선택 가능 (32GB 초과는 exFAT 권장).
    """

    def __init__(self, drive_info: DriveInfo):
        self.drive = drive_info

    def format_drive(self, fs_type: str = 'fat32') -> bool:
        """
        포맷 실행. diskpart 방식 시도 후 실패 시 format 명령어 폴백.
        fs_type: 'fat32' 또는 'exfat'
        """
        try:
            return self._format_via_diskpart(fs_type)
        except Exception:
            return self._format_via_cmd(fs_type)

    def _format_via_diskpart(self, fs_type: str) -> bool:
        """
        diskpart 스크립트로 포맷.
        select volume → format fs=... quick → assign letter 순서.
        """
        script = (
            f"select volume {self.drive.letter}\n"
            f"format fs={fs_type} quick label=SDCARD\n"
            f"assign letter={self.drive.letter}\n"
            "exit\n"
        )
        # 임시 파일에 스크립트 저장 (ASCII만 사용)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.txt')
        try:
            with os.fdopen(tmp_fd, 'w', encoding='ascii') as f:
                f.write(script)

            result = subprocess.run(
                ['diskpart', '/s', tmp_path],
                capture_output=True, text=True,
                timeout=180,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.returncode == 0
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def _format_via_cmd(self, fs_type: str) -> bool:
        """diskpart 실패 시 format 명령어로 폴백 (32GB 초과 FAT32는 실패 가능)"""
        result = subprocess.run(
            ['format', f'{self.drive.letter}:', f'/FS:{fs_type.upper()}',
             '/Q', '/Y', '/V:SDCARD'],
            capture_output=True, text=True,
            timeout=120,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0


# ──────────────────────────────────────────────
# 5. WipeWorker — 백그라운드 스레드 (wipe → format)
# ──────────────────────────────────────────────

class WipeWorker(threading.Thread):
    """
    덮어쓰기와 포맷을 백그라운드 스레드에서 실행.
    진행 상황은 queue를 통해 메인 스레드(GUI)로 전달.

    Queue 메시지 형식:
      ('progress', done_bytes, total_bytes, pass_label)
      ('status',  message_str)
      ('done',    success_bool)
      ('error',   error_message_str)
      ('cancelled',)
    """

    def __init__(
        self,
        drive_info: DriveInfo,
        wipe_mode: str,
        fs_type: str,
        msg_queue: queue.Queue
    ):
        super().__init__(daemon=True)
        self.drive = drive_info
        self.wipe_mode = wipe_mode
        self.fs_type = fs_type
        self.q = msg_queue
        self._wiper: Optional[SecureWiper] = None

    def cancel(self) -> None:
        if self._wiper:
            self._wiper.cancel()

    def run(self) -> None:
        try:
            def on_progress(done, total, label):
                self.q.put(('progress', done, total, label))

            def on_status(msg):
                self.q.put(('status', msg))

            self._wiper = SecureWiper(
                self.drive, self.wipe_mode,
                on_progress, on_status
            )

            on_status(f"{self.drive.letter}: 덮어쓰기 시작...")
            success = self._wiper.wipe()

            if not success:
                self.q.put(('cancelled',))
                return

            on_status("포맷 중... (잠시 기다려 주세요)")
            fmt_ok = DiskFormatter(self.drive).format_drive(self.fs_type)
            self.q.put(('done', fmt_ok))

        except Exception as e:
            self.q.put(('error', str(e)))


# ──────────────────────────────────────────────
# 6. SDCleanerApp — tkinter GUI
# ──────────────────────────────────────────────

class SDCleanerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SD 카드 안전 삭제 도구")
        self.resizable(False, False)

        self._detector = DriveDetector()
        self._drives: list = []
        self._worker: Optional[WipeWorker] = None
        self._queue: queue.Queue = queue.Queue()

        # 옵션 변수
        self._wipe_mode = tk.StringVar(value='1pass')
        self._fs_type   = tk.StringVar(value='fat32')

        self._build_ui()
        self._refresh_drives()
        self._center_window()

    # ── UI 구성 ──────────────────────────────

    def _build_ui(self):
        """전체 레이아웃 구성"""
        PAD = 12

        # ① 경고 배너
        banner = tk.Frame(self, bg='#c0392b', pady=10)
        banner.pack(fill='x')
        tk.Label(
            banner,
            text="⚠  경고: 선택한 드라이브의 모든 데이터가 영구 삭제됩니다  ⚠",
            bg='#c0392b', fg='white',
            font=('맑은 고딕', 11, 'bold')
        ).pack()

        main = tk.Frame(self, padx=PAD, pady=PAD)
        main.pack(fill='both', expand=True)

        # ② 드라이브 목록
        list_frame = tk.LabelFrame(main, text="이동식 드라이브 목록", padx=8, pady=8)
        list_frame.pack(fill='x', pady=(0, 8))

        list_inner = tk.Frame(list_frame)
        list_inner.pack(fill='x')

        self._listbox = tk.Listbox(
            list_inner, height=4, width=55,
            font=('맑은 고딕', 10),
            selectbackground='#2980b9', selectforeground='white',
            activestyle='none'
        )
        self._listbox.pack(side='left', fill='x', expand=True)

        scrollbar = tk.Scrollbar(list_inner, orient='vertical',
                                 command=self._listbox.yview)
        scrollbar.pack(side='right', fill='y')
        self._listbox.config(yscrollcommand=scrollbar.set)

        self._refresh_btn = tk.Button(
            list_frame, text="새로고침",
            command=self._refresh_drives,
            font=('맑은 고딕', 9)
        )
        self._refresh_btn.pack(anchor='e', pady=(6, 0))

        # ③ 옵션 영역
        opt_frame = tk.LabelFrame(main, text="삭제 옵션", padx=8, pady=8)
        opt_frame.pack(fill='x', pady=(0, 8))

        # 덮어쓰기 모드
        mode_row = tk.Frame(opt_frame)
        mode_row.pack(fill='x', pady=2)
        tk.Label(mode_row, text="덮어쓰기 모드:", width=14, anchor='w',
                 font=('맑은 고딕', 10)).pack(side='left')
        tk.Radiobutton(
            mode_row, text="1-pass 랜덤 (빠름)", variable=self._wipe_mode,
            value='1pass', font=('맑은 고딕', 10)
        ).pack(side='left', padx=(0, 12))
        tk.Radiobutton(
            mode_row, text="DoD 3-pass (철저, 3배 시간)", variable=self._wipe_mode,
            value='dod3', font=('맑은 고딕', 10)
        ).pack(side='left')

        # 포맷 형식
        fs_row = tk.Frame(opt_frame)
        fs_row.pack(fill='x', pady=2)
        tk.Label(fs_row, text="포맷 형식:", width=14, anchor='w',
                 font=('맑은 고딕', 10)).pack(side='left')
        fs_menu = ttk.Combobox(
            fs_row, textvariable=self._fs_type,
            values=['fat32', 'exfat'], state='readonly', width=10,
            font=('맑은 고딕', 10)
        )
        fs_menu.pack(side='left')
        tk.Label(
            fs_row, text="  ※ 32GB 초과 SD 카드는 exFAT 권장",
            fg='gray', font=('맑은 고딕', 9)
        ).pack(side='left')

        # ④ 진행률
        prog_frame = tk.LabelFrame(main, text="진행 상황", padx=8, pady=8)
        prog_frame.pack(fill='x', pady=(0, 8))

        self._progress_var = tk.DoubleVar(value=0.0)
        self._progressbar = ttk.Progressbar(
            prog_frame, variable=self._progress_var,
            maximum=100, length=440, mode='determinate'
        )
        self._progressbar.pack(fill='x', pady=(0, 4))

        self._status_label = tk.Label(
            prog_frame, text="드라이브를 선택하고 시작 버튼을 누르세요.",
            font=('맑은 고딕', 9), anchor='w'
        )
        self._status_label.pack(fill='x')

        # ⑤ 버튼
        btn_frame = tk.Frame(main)
        btn_frame.pack()

        self._start_btn = tk.Button(
            btn_frame, text="  시작  ",
            command=self._on_start_clicked,
            bg='#c0392b', fg='white',
            font=('맑은 고딕', 11, 'bold'),
            padx=20, pady=6,
            relief='flat', cursor='hand2'
        )
        self._start_btn.pack(side='left', padx=(0, 16))

        self._cancel_btn = tk.Button(
            btn_frame, text="  취소  ",
            command=self._on_cancel_clicked,
            state='disabled',
            font=('맑은 고딕', 11),
            padx=20, pady=6,
            relief='flat', cursor='hand2'
        )
        self._cancel_btn.pack(side='left')

    # ── 이벤트 핸들러 ──────────────────────────

    def _refresh_drives(self):
        """드라이브 목록 새로고침"""
        self._drives = self._detector.get_removable_drives()
        self._listbox.delete(0, tk.END)
        if self._drives:
            for d in self._drives:
                self._listbox.insert(tk.END, f"  {d.display_name}")
            self._listbox.selection_set(0)
        else:
            self._listbox.insert(tk.END, "  이동식 드라이브를 찾을 수 없습니다. SD 카드를 연결하세요.")

    def _on_start_clicked(self):
        """시작 버튼 클릭 → 드라이브 선택 확인 → 이중 확인 → 작업 시작"""
        sel = self._listbox.curselection()
        if not sel or not self._drives:
            messagebox.showwarning("선택 오류", "삭제할 드라이브를 선택해 주세요.")
            return

        drive = self._drives[sel[0]]

        # 1차 확인 다이얼로그
        answer = messagebox.askyesno(
            "⚠ 경고 — 데이터 영구 삭제",
            f"드라이브 {drive.letter}: ({drive.size_gb:.1f} GB) 의\n"
            f"모든 데이터를 영구 삭제합니다.\n\n"
            f"복구가 불가능합니다. 계속하시겠습니까?",
            icon='warning'
        )
        if not answer:
            return

        # 2차 확인: 드라이브 문자 직접 입력
        if not self._confirm_drive_letter(drive.letter):
            return

        # 작업 시작
        self._start_wipe(drive)

    def _confirm_drive_letter(self, letter: str) -> bool:
        """
        드라이브 문자를 직접 입력하게 하는 이중 확인 다이얼로그.
        정확히 입력해야만 True 반환.
        """
        dialog = tk.Toplevel(self)
        dialog.title("최종 확인")
        dialog.resizable(False, False)
        dialog.grab_set()  # 모달 창

        tk.Label(
            dialog,
            text=f"정말로 {letter}: 드라이브를 삭제하려면\n"
                 f"드라이브 문자 '{letter}' 를 아래에 입력하세요:",
            font=('맑은 고딕', 10), pady=16, padx=20
        ).pack()

        entry_var = tk.StringVar()
        entry = tk.Entry(dialog, textvariable=entry_var, width=8,
                         font=('맑은 고딕', 14), justify='center')
        entry.pack(pady=(0, 12))
        entry.focus_set()

        result = [False]

        def on_confirm():
            if entry_var.get().strip().upper() == letter.upper():
                result[0] = True
                dialog.destroy()
            else:
                messagebox.showwarning("입력 오류",
                    "드라이브 문자가 일치하지 않습니다.", parent=dialog)

        def on_cancel():
            dialog.destroy()

        btn_frame = tk.Frame(dialog, pady=8)
        btn_frame.pack()
        tk.Button(btn_frame, text="확인", command=on_confirm,
                  bg='#c0392b', fg='white', font=('맑은 고딕', 10),
                  padx=12, relief='flat').pack(side='left', padx=6)
        tk.Button(btn_frame, text="취소", command=on_cancel,
                  font=('맑은 고딕', 10), padx=12, relief='flat').pack(side='left', padx=6)

        entry.bind('<Return>', lambda _: on_confirm())
        dialog.bind('<Escape>', lambda _: on_cancel())

        self.wait_window(dialog)
        return result[0]

    def _start_wipe(self, drive: DriveInfo):
        """WipeWorker 스레드 시작 및 UI 상태 전환"""
        self._start_btn.config(state='disabled')
        self._cancel_btn.config(state='normal')
        self._refresh_btn.config(state='disabled')  # 작업 중 드라이브 목록 교체 방지
        self._progress_var.set(0)
        self._status_label.config(text="작업 준비 중...")

        self._worker = WipeWorker(
            drive,
            self._wipe_mode.get(),
            self._fs_type.get(),
            self._queue
        )
        self._worker.start()
        self.after(100, self._poll_queue)

    def _poll_queue(self):
        """Queue에서 Worker 메시지를 읽어 UI 업데이트 (100ms마다 폴링)"""
        finished = False
        try:
            while True:
                msg = self._queue.get_nowait()
                kind = msg[0]

                if kind == 'progress':
                    _, done, total, label = msg
                    pct = (done / total * 100) if total > 0 else 0
                    self._progress_var.set(pct)
                    done_gb  = done  / (1024 ** 3)
                    total_gb = total / (1024 ** 3)
                    self._status_label.config(
                        text=f"{label}  —  {done_gb:.2f} GB / {total_gb:.2f} GB  ({pct:.1f}%)"
                    )

                elif kind == 'status':
                    self._status_label.config(text=msg[1])

                elif kind == 'done':
                    success = msg[1]
                    self._on_complete(success)
                    finished = True

                elif kind == 'error':
                    messagebox.showerror("오류 발생", msg[1])
                    self._reset_ui("오류가 발생했습니다.")
                    finished = True

                elif kind == 'cancelled':
                    self._reset_ui("작업이 취소됐습니다.")
                    finished = True

        except queue.Empty:
            pass

        if not finished:
            self.after(100, self._poll_queue)

    def _on_complete(self, success: bool):
        """작업 완료 처리"""
        self._progress_var.set(100)
        if success:
            self._status_label.config(
                text="완료! 덮어쓰기 및 포맷이 성공적으로 끝났습니다."
            )
            messagebox.showinfo(
                "완료",
                "SD 카드 안전 삭제 및 포맷이 완료됐습니다.\n"
                "데이터를 복구할 수 없는 상태입니다."
            )
        else:
            messagebox.showwarning("포맷 실패",
                "덮어쓰기는 완료됐지만 포맷에 실패했습니다.\n"
                "Windows 탐색기에서 수동으로 포맷해 주세요.")
            self._status_label.config(text="덮어쓰기 완료 (포맷 실패 — 수동 포맷 필요)")

        self._reset_ui(None)
        self._refresh_drives()

    def _on_cancel_clicked(self):
        """취소 버튼 클릭"""
        if self._worker:
            self._worker.cancel()
        self._cancel_btn.config(state='disabled')
        self._status_label.config(text="취소 중... (현재 청크 완료 후 중단됩니다)")

    def _reset_ui(self, status_msg: Optional[str]):
        """버튼 상태 초기화"""
        self._start_btn.config(state='normal')
        self._cancel_btn.config(state='disabled')
        self._refresh_btn.config(state='normal')
        if status_msg:
            self._status_label.config(text=status_msg)

    # ── 유틸리티 ──────────────────────────────

    def _center_window(self):
        """창을 화면 중앙에 배치"""
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"+{x}+{y}")


# ──────────────────────────────────────────────
# 진입점
# ──────────────────────────────────────────────

if __name__ == '__main__':
    # 관리자 권한 확인 — 없으면 UAC 프롬프트 띄우고 재실행
    if not AdminChecker.is_admin():
        AdminChecker.relaunch_as_admin()

    app = SDCleanerApp()
    app.mainloop()
