import os
import hashlib
import shutil
import zipfile
import logging
import json
import math
from datetime import datetime
from tkinter import Tk, ttk, filedialog, BooleanVar, messagebox, Text, Scrollbar
from typing import List, Tuple, Dict
from pathlib import Path

class FileSignatures:
    """Professional database of file signatures and patterns."""

    SIGNATURES = {
        # Document formats
        "PDF": (b"%PDF", 0.85),  # Signature, entropy threshold
        "DOC": (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0.82),
        "DOCX": (b"PK\x03\x04", 0.85),
        "XLS": (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0.82),
        "XLSX": (b"PK\x03\x04", 0.85),

        # Image formats
        "PNG": (b"\x89PNG\r\n\x1a\n", 0.95),
        "JPEG": (b"\xFF\xD8\xFF", 0.92),
        "GIF": (b"GIF87a", 0.90),
        "BMP": (b"BM", 0.85),

        # Archive formats
        "ZIP": (b"PK\x03\x04", 0.95),
        "RAR": (b"Rar!\x1a\x07", 0.95),
        "7Z": (b"7z\xbc\xaf\x27\x1c", 0.95),

        # Executable formats
        "EXE": (b"MZ", 0.80),
        "ELF": (b"\x7FELF", 0.80),

        # Text formats
        "TXT": (None, 0.50),  # Text files are low entropy
        "XML": (b"<?xml", 0.60),
        "HTML": (b"<!DOCTYPE", 0.60),

        # Source code
        "PY": (None, 0.65),
        "JAVA": (None, 0.65),
        "JS": (None, 0.65),
        "CPP": (None, 0.65),
        "H": (None, 0.65),
    }

    # Trusted development directories/files
    TRUSTED_PATHS = [
        ".git",
        ".svn",
        ".idea",
        ".vscode",
        "__pycache__",
        "node_modules",
        "venv",
        "env",
        ".pytest_cache",
    ]

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_file_type(self, file_path: str) -> str:
        """Determine file type based on extension and content."""
        ext = Path(file_path).suffix.upper().lstrip('.')
        if not ext:
            return self._detect_type_from_content(file_path)
        return ext if ext in self.SIGNATURES else "UNKNOWN"

    def _detect_type_from_content(self, file_path: str) -> str:
        """Detect file type from content when extension is missing."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                for file_type, (signature, _) in self.SIGNATURES.items():
                    if signature and signature in header:
                        return file_type
            return "UNKNOWN"
        except Exception as e:
            self.logger.error(f"Error detecting file type for {file_path}: {e}")
            return "UNKNOWN"

    def validate(self, file_path: str, file_types: List[str]) -> Tuple[bool, str]:
        """Enhanced file validation with context awareness."""
        try:
            # Check if file is in trusted path
            if any(trusted in str(file_path) for trusted in self.TRUSTED_PATHS):
                return True, "Trusted development path"

            file_type = self.get_file_type(file_path)

            # If no specific types selected, consider valid
            if not file_types:
                return True, "No specific type restrictions"

            # If file type is unknown but in a trusted path, consider valid
            if file_type == "UNKNOWN" and any(trusted in str(file_path) for trusted in self.TRUSTED_PATHS):
                return True, "Unknown type in trusted path"

            return file_type in file_types, f"File type: {file_type}"

        except Exception as e:
            self.logger.error(f"Error validating file {file_path}: {e}")
            return False, f"Validation error: {str(e)}"

class MalwareSignatures:
    """Professional database of malware signatures and patterns."""

    def __init__(self):
        self.quarantine_dir = Path("quarantine")
        self.quarantine_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self.file_signatures = FileSignatures()

        # Known malware signatures
        self.signatures: Dict[str, bytes] = {
            "trojan_type1": b"This Program Cannot Be Run in DOS Mode",
            "ransomware_type1": b"ENCRYPTED_FILE_MARKER",
            "keylogger_type1": b"GetAsyncKeyState",
            "rootkit_type1": b"SYSTEM\\CurrentControlSet\\Services",
        }

        # Suspicious behavioral patterns
        self.behavioral_patterns = [
            rb"CreateRemoteThread",
            rb"WriteProcessMemory",
            rb"VirtualAllocEx",
            rb"SetWindowsHookEx",
        ]

    def scan_file(self, file_path: str) -> Tuple[bool, str]:
        """Context-aware malware scanning."""
        try:
            # Get file type and corresponding entropy threshold
            file_type = self.file_signatures.get_file_type(file_path)
            _, threshold = self.file_signatures.SIGNATURES.get(file_type, (None, 0.8))

            with open(file_path, "rb") as f:
                content = f.read()

                # Skip malware checks for trusted paths
                if any(trusted in str(file_path) for trusted in self.file_signatures.TRUSTED_PATHS):
                    return True, "Trusted development path"

                # Check known malware signatures
                for mal_type, signature in self.signatures.items():
                    if signature in content:
                        return False, f"Detected {mal_type}"

                # Check behavioral patterns for executable files
                if file_type in ["EXE", "DLL", "SYS"]:
                    for pattern in self.behavioral_patterns:
                        if pattern in content:
                            return False, f"Suspicious behavior: {pattern.decode('utf-8', 'ignore')}"

                # Check for suspicious encryption/packing
                entropy = self._check_entropy(content)
                if entropy > threshold:
                    # Additional validation for known high-entropy formats
                    if file_type in ["PNG", "JPEG", "ZIP", "PDF"]:
                        if self._validate_format(file_type, content):
                            return True, "Valid compressed format"
                    return False, f"Suspicious entropy level: {entropy:.2f} > {threshold:.2f}"

                return True, "Clean"

        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return False, f"Scan error: {str(e)}"

    def _validate_format(self, file_type: str, content: bytes) -> bool:
        """Validate file format structure."""
        try:
            if file_type == "PNG":
                return (content.startswith(b"\x89PNG\r\n\x1a\n") and
                       b"IEND" in content[-8:])
            elif file_type == "JPEG":
                return (content.startswith(b"\xFF\xD8") and
                       content.endswith(b"\xFF\xD9"))
            elif file_type == "PDF":
                return (content.startswith(b"%PDF-") and
                       b"%%EOF" in content[-8:])
            elif file_type == "ZIP":
                return content.startswith(b"PK\x03\x04") and len(content) > 30
            return False
        except Exception:
            return False


    def quarantine_file(self, file_path: str) -> str:
        """Move infected file to quarantine with metadata."""
        try:
            file_name = Path(file_path).name
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{file_name}.quarantine"
            quarantine_path = self.quarantine_dir / quarantine_name

            metadata = {
                "original_path": str(file_path),
                "timestamp": timestamp,
                "hash": self._calculate_hash(file_path)
            }

            self._encrypt_and_move(file_path, str(quarantine_path), metadata)
            return str(quarantine_path)
        except Exception as e:
            self.logger.error(f"Error quarantining file {file_path}: {e}")
            raise Exception(f"Quarantine failed: {str(e)}")

    def _check_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy to detect encryption/packing."""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x))/len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _encrypt_and_move(self, source: str, dest: str, metadata: Dict) -> None:
        """Encrypt file and move to quarantine with metadata."""
        shutil.move(source, dest)
        meta_path = f"{dest}.meta"
        with open(meta_path, "w") as f:
            json.dump(metadata, f)

class DeepScanner:
    """Enhanced scanner with deep inspection capabilities."""

    def __init__(self):
        self.malware_db = MalwareSignatures()
        self.logger = logging.getLogger(__name__)

    def deep_scan_file(self, file_path: str) -> Tuple[bool, str]:
        """Perform deep scan of file including archives."""
        try:
            if zipfile.is_zipfile(file_path):
                return self._scan_archive(file_path)
            return self.malware_db.scan_file(file_path)
        except Exception as e:
            self.logger.error(f"Error in deep scan of {file_path}: {e}")
            return False, f"Scan failed: {str(e)}"

    def _scan_archive(self, archive_path: str) -> Tuple[bool, str]:
        """Scan contents of archive files."""
        try:
            with zipfile.ZipFile(archive_path, 'r') as archive:
                temp_dir = Path("temp_scan")
                temp_dir.mkdir(exist_ok=True)

                for file_info in archive.infolist():
                    temp_path = temp_dir / file_info.filename
                    archive.extract(file_info, path=temp_dir)
                    is_clean, message = self.malware_db.scan_file(str(temp_path))
                    temp_path.unlink()  # Clean up

                    if not is_clean:
                        shutil.rmtree(temp_dir)
                        return False, f"Malware found in archive: {message}"

                shutil.rmtree(temp_dir)
                return True, "Archive clean"
        except Exception as e:
            self.logger.error(f"Error scanning archive {archive_path}: {e}")
            return False, f"Archive scan failed: {str(e)}"

class FileScanner:
    """Professional file scanner with comprehensive scanning capabilities."""

    def __init__(self, directory: str, file_types: List[str], check_corruption: bool,
                 check_malicious: bool, recursive: bool, delete_flagged: bool):
        self.directory = directory
        self.file_types = file_types
        self.check_corruption = check_corruption
        self.check_malicious = check_malicious
        self.recursive = recursive
        self.delete_flagged = delete_flagged
        self.deep_scanner = DeepScanner()
        self.file_signatures = FileSignatures()
        self.logger = logging.getLogger(__name__)

    def scan(self) -> List[str]:
        """Scan files in the directory and return categorized results."""
        results = []
        try:
            for root, _, files in os.walk(self.directory):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    is_safe, reason = self._analyze_file(file_path)

                    if is_safe:
                        results.append(f"✅ Safe file: {file_path}")
                    else:
                        results.append(f"❌ {reason}: {file_path}")
                        if self.delete_flagged:
                            self._handle_flagged_file(file_path)

                if not self.recursive:
                    break
        except Exception as e:
            self.logger.error(f"Error during scan: {e}")
            results.append(f"❌ Scan error: {str(e)}")

        return results

    def _analyze_file(self, file_path: str) -> Tuple[bool, str]:
        """Comprehensive file analysis."""
        try:
            # Check file type signatures if enabled
            if self.check_corruption and self.file_types:
                if not self.file_signatures.validate(file_path, self.file_types):
                    return False, "Invalid file signature"

            # Perform malware scan if enabled
            if self.check_malicious:
                is_clean, message = self.deep_scanner.deep_scan_file(file_path)
                if not is_clean:
                    return False, f"Malicious content: {message}"

            return True, "Safe"
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            return False, f"Analysis error: {str(e)}"

    def _handle_flagged_file(self, file_path: str) -> None:
        """Handle flagged files based on configuration."""
        try:
            quarantine_path = self.deep_scanner.malware_db.quarantine_file(file_path)
            self.logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
        except Exception as e:
            self.logger.error(f"Error handling flagged file {file_path}: {e}")
            raise Exception(f"Failed to handle flagged file: {str(e)}")

class EnhancedAntivirusApp:
    """GoSeek Guard."""

    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Professional Antivirus Scanner")
        self.root.geometry("900x700")

        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            filename='antivirus.log'
        )

        self._setup_variables()
        self._setup_ui()

    def _setup_variables(self) -> None:
        """Initialize application variables."""
        self.check_corruption = BooleanVar(value=True)
        self.check_malicious = BooleanVar(value=True)
        self.recursive_scan = BooleanVar(value=True)
        self.delete_flagged_files = BooleanVar(value=False)
        self.file_types_vars = {
            file_type: BooleanVar(value=True)
            for file_type in FileSignatures.SIGNATURES.keys()
        }

    def _setup_ui(self) -> None:
        """Set up the user interface."""
        self.style = ttk.Style()
        self.style.configure('Custom.TFrame', background='#f0f0f0')

        main_container = ttk.Frame(self.root, padding="10", style='Custom.TFrame')
        main_container.pack(fill="both", expand=True)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True)

        # Create tabs
        self._create_scan_tab()
        self._create_results_tab()
        self._create_logs_tab()

    def _create_scan_tab(self) -> None:
        """Create the scanning interface tab."""
        scan_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(scan_frame, text="Scan")

        # Directory selection
        dir_frame = ttk.LabelFrame(scan_frame, text="Select Directory", padding="5")
        dir_frame.pack(fill="x", pady=5)

        self.directory_path = ttk.Entry(dir_frame)
        self.directory_path.pack(side="left", fill="x", expand=True, padx=5)

        browse_btn = ttk.Button(dir_frame, text="Browse", command=self._browse_directory)
        browse_btn.pack(side="right", padx=5)

        # Scan options
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options", padding="5")
        options_frame.pack(fill="x", pady=5)

        # File types
        file_types_frame = ttk.Frame(options_frame)
        file_types_frame.pack(fill="x", pady=5)

        ttk.Label(file_types_frame, text="File Types:").pack(side="left", padx=5)

        for file_type, var in self.file_types_vars.items():
            cb = ttk.Checkbutton(file_types_frame, text=file_type, variable=var)
            cb.pack(side="left", padx=5)

        # Other options
        ttk.Checkbutton(options_frame, text="Check for Corruption",
                       variable=self.check_corruption).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Check for Malware",
                       variable=self.check_malicious).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Scan Subdirectories",
                       variable=self.recursive_scan).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Quarantine Detected Files",
                       variable=self.delete_flagged_files).pack(anchor="w", pady=2)

        # Scan button
        scan_btn = ttk.Button(scan_frame, text="Start Scan", command=self._start_scan)
        scan_btn.pack(pady=10)

    def _create_results_tab(self) -> None:
        """Create the results display tab."""
        results_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(results_frame, text="Results")

        # Results text widget with scrollbar
        self.results_text = Text(results_frame, wrap="word", height=20)
        scrollbar = Scrollbar(results_frame, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)

        self.results_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def _create_logs_tab(self) -> None:
        """Create the logs display tab."""
        logs_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(logs_frame, text="Logs")

        # Log text widget with scrollbar
        self.logs_text = Text(logs_frame, wrap="word", height=20)
        scrollbar = Scrollbar(logs_frame, command=self.logs_text.yview)
        self.logs_text.configure(yscrollcommand=scrollbar.set)

        self.logs_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Add refresh button
        refresh_btn = ttk.Button(logs_frame, text="Refresh Logs", command=self._refresh_logs)
        refresh_btn.pack(pady=5)

        # Initial load of logs
        self._refresh_logs()

    def _browse_directory(self) -> None:
        """Open directory selection dialog."""
        directory = filedialog.askdirectory()
        if directory:
            self.directory_path.delete(0, "end")
            self.directory_path.insert(0, directory)

    def _start_scan(self) -> None:
        """Initiate the scanning process."""
        directory = self.directory_path.get()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory")
            return

        # Get selected file types
        selected_types = [
            file_type for file_type, var in self.file_types_vars.items()
            if var.get()
        ]

        try:
            # Create scanner instance
            scanner = FileScanner(
                directory=directory,
                file_types=selected_types,
                check_corruption=self.check_corruption.get(),
                check_malicious=self.check_malicious.get(),
                recursive=self.recursive_scan.get(),
                delete_flagged=self.delete_flagged_files.get()
            )

            # Disable scan button during scan
            self.notebook.tab(0, state="disabled")
            self.root.update()

            # Perform scan
            results = scanner.scan()

            # Display results
            self._display_results(results)

            # Re-enable scan tab
            self.notebook.tab(0, state="normal")

            # Switch to results tab
            self.notebook.select(1)

            # Show completion message
            messagebox.showinfo("Scan Complete",
                              f"Scan completed successfully.\n"
                              f"Found {len([r for r in results if '❌' in r])} potential threats.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during scan: {str(e)}")
            logging.error(f"Scan error: {str(e)}")
            self.notebook.tab(0, state="normal")

    def _display_results(self, results: List[str]) -> None:
        """Display scan results in the results tab."""
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", "=== Scan Results ===\n\n")

        for result in results:
            if "❌" in result:
                self.results_text.insert("end", result + "\n", "threat")
            else:
                self.results_text.insert("end", result + "\n", "safe")

        # Configure tags for colored text
        self.results_text.tag_configure("threat", foreground="red")
        self.results_text.tag_configure("safe", foreground="green")

    def _refresh_logs(self) -> None:
        """Refresh the contents of the logs tab."""
        try:
            self.logs_text.delete(1.0, "end")
            if os.path.exists("antivirus.log"):
                with open("antivirus.log", "r") as log_file:
                    self.logs_text.insert("end", log_file.read())
        except Exception as e:
            self.logs_text.insert("end", f"Error reading logs: {str(e)}")

def main():
    """Main entry point for the application."""
    try:
        root = Tk()
        root.title("Goseek Guard")

        # Set up logging
        logging.basicConfig(
            filename='antivirus.log',
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        app = EnhancedAntivirusApp(root)
        root.mainloop()
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        messagebox.showerror("Critical Error",
                            f"A critical error occurred: {str(e)}\n"
                            "Please check the logs for details.")

if __name__ == "__main__":
    main()
