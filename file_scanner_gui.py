import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

class FileScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Scanner & Analyzer")
        self.root.geometry("800x600")

        # Known file signatures
        self.signatures = {
           "PNG": b"\x89PNG\r\n\x1a\n",
           "JPEG": b"\xFF\xD8\xFF",
           "GIF": b"GIF89a",
           "PDF": b"%PDF-1.",
           "ZIP": b"PK\x03\x04",
           "EICAR": b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        }

        self.create_gui()

    def create_gui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Directory selection
        ttk.Label(main_frame, text="Select Directory:").grid(row=0, column=0, sticky=tk.W)
        self.dir_path = tk.StringVar()
        dir_entry = ttk.Entry(main_frame, textvariable=self.dir_path, width=60)
        dir_entry.grid(row=0, column=1, padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2)

        # Scan options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="5")
        options_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))

        self.check_corruption = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Check for file corruption",
                       variable=self.check_corruption).grid(row=0, column=0, sticky=tk.W)

        self.check_malicious = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Check for malicious content",
                       variable=self.check_malicious).grid(row=1, column=0, sticky=tk.W)

        # Results area
        ttk.Label(main_frame, text="Scan Results:").grid(row=2, column=0, sticky=tk.W)

        self.results_text = tk.Text(main_frame, height=20, width=80)
        self.results_text.grid(row=3, column=0, columnspan=3, pady=5)

        # Scrollbar for results
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        scrollbar.grid(row=3, column=3, sticky=(tk.N, tk.S))
        self.results_text.configure(yscrollcommand=scrollbar.set)

        # Action buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)

        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.dir_path.set(directory)

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)

    def log_result(self, message):
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.root.update_idletasks()

    def is_file_corrupted(self, file_path, expected_signature):
        try:
            with open(file_path, 'rb') as file:
                actual_signature = file.read(len(expected_signature))
                return actual_signature != expected_signature
        except Exception as e:
            return True

    def is_malicious_file(self, file_path):
        try:
            with open(file_path, "rb") as file:
                file_content = file.read()
                return self.signatures["EICAR"] in file_content
        except Exception:
            return False

    def start_scan(self):
        directory = self.dir_path.get()
        if not directory:
            messagebox.showerror("Error", "Please select a directory first!")
            return

        self.clear_results()
        self.log_result(f"Starting scan of: {directory}\n")

        try:
            for root, _, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.log_result(f"Scanning: {file_path}")

                    if self.check_corruption.get() and file.lower().endswith('.png'):
                        if self.is_file_corrupted(file_path, self.signatures["PNG"]):
                            self.log_result("⚠️ WARNING: Possible corruption detected!")

                    if self.check_malicious.get():
                        if self.is_malicious_file(file_path):
                            self.log_result("🚨 ALERT: Malicious content detected!")
                            if messagebox.askyesno("Malicious File Detected",
                                                 f"Delete malicious file?\n{file_path}"):
                                os.remove(file_path)
                                self.log_result("File deleted.")

                    self.log_result("")  # Empty line for readability

            self.log_result("\nScan completed!")

        except Exception as e:
            self.log_result(f"\nError during scan: {str(e)}")
            messagebox.showerror("Error", f"An error occurred during the scan: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileScannerApp(root)
    root.mainloop()
