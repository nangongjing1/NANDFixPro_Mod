# pyinstaller --onefile --windowed --icon=icon.ico nandfixpro.py

import sys
import traceback
import datetime
import tkinter as tk
import stat
import psutil
import os
import ctypes
from ctypes import wintypes
import hashlib
import struct
from tkinter import colorchooser


# --- ROBUST ERROR LOGGING AND EXIT ---
def log_uncaught_exceptions(ex_cls, ex, tb):
    # Log the error to a file
    with open("error_log.txt", "a") as f:
        f.write(f"--- {datetime.datetime.now()} ---\n")
        f.write(''.join(traceback.format_exception(ex_cls, ex, tb)))
        f.write("\n")
    
    # Also show a user-friendly error message box
    error_message = f"A critical error occurred:\n\n{ex}\n\nPlease check error_log.txt for more details."
    try:
        from tkinter import messagebox
        # Create a temporary root to show the message box if the main app failed
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("未处理的异常", error_message)
        root.destroy()
    except Exception as e:
        print(f"Could not show messagebox: {e}")
        
    # IMPORTANT: Ensure the process exits cleanly after a crash
    sys.exit(1)

def force_remove_readonly(func, path, exc_info):
    """Error handler for shutil.rmtree to handle read-only files."""
    if os.path.exists(path):
        os.chmod(path, stat.S_IWRITE)
        func(path)

def safe_remove_directory(directory_path):
    """Safely remove a directory, handling read-only files and permission issues."""
    if not directory_path.exists():
        return True
        
    try:
        # First try normal removal
        shutil.rmtree(directory_path)
        return True
    except PermissionError:
        try:
            # If that fails, try with the error handler for read-only files
            shutil.rmtree(directory_path, onerror=force_remove_readonly)
            return True
        except Exception as e:
            print(f"WARNING: Could not remove directory {directory_path}: {e}")
            return False



def find_emmc_backup_folder(sd_drive):
    """Find the backup/[emmcID]/restore folder structure."""
    backup_path = sd_drive / "backup"
    if backup_path.exists():
        for folder in backup_path.iterdir():
            if folder.is_dir() and folder.name.isalnum() and len(folder.name) >= 6:  # emmcID is alphanumeric
                restore_path = folder / "restore"
                if restore_path.exists():
                    return restore_path
    return None


sys.excepthook = log_uncaught_exceptions
# --- END OF LOGGING CODE ---

# --- PRODINFO CONSTANTS ---
CRC_16_TABLE = [
    0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
    0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400
]

REGION_CODE_MAP = {
    "America": b"\x52\x32\x00\x00",
    "Asia (Singapore)": b"\x55\x31\x00\x00", 
    "Asia (Malaysia)": b"\x55\x34\x00\x00",
    "Australia": b"\x55\x32\x00\x00",
    "Europe": b"\x52\x31\x00\x00",
    "Japan": b"\x54\x31\x00\x00",
}

REGION_MAP = {v.hex().upper(): k for k, v in REGION_CODE_MAP.items()}

# --- PRODINFO ENGINE CLASSES ---
class ProdinfoEngine:
    """Backend engine for handling PRODINFO data and logic."""
    
    def __init__(self):
        self.data = None
        self.filepath = None
        
        # Block definitions for PRODINFO structure
        self.blocks = {
            'ConfigurationId1': (0x40, 0x20), 
            'WlanCountryCodes': (0x80, 0x190),
            'WlanMacAddress': (0x210, 0x08), 
            'BtMacAddress': (0x220, 0x08),
            'SerialNumber': (0x250, 0x20), 
            'ProductModel': (0x3740, 0x10),
            'ColorVariation': (0x3750, 0x10), 
            'HousingBezelColor': (0x4230, 0x10),
            'HousingMainColor1': (0x4240, 0x10),
        }
        
        # Define which blocks need CRC16 checks
        self.crc_blocks = [
            'ConfigurationId1', 'WlanCountryCodes', 'WlanMacAddress', 'BtMacAddress',
            'SerialNumber', 'ProductModel', 'ColorVariation', 'HousingBezelColor', 'HousingMainColor1'
        ]

    def calculate_crc16(self, data):
        """Calculate CRC16 using lookup table"""
        crc = 0x55AA
        for byte in data:
            r = CRC_16_TABLE[crc & 0x0F]
            crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[byte & 0x0F]
            r = CRC_16_TABLE[crc & 0x0F]
            crc = ((crc >> 4) & 0x0FFF) ^ r ^ CRC_16_TABLE[(byte >> 4) & 0x0F]
        return crc & 0xFFFF

    def compute_sha256(self, offset=0x40):
        """Compute SHA256 hash of PRODINFO body using EXACT body size from header"""
        if not self.data:
            return None
        
        try:
            # Read body size from header (offset 0x8, 4 bytes, little endian)
            body_size = struct.unpack('<I', self.data[0x8:0xC])[0]
            
            # Validate body size to prevent reading beyond file
            max_possible_size = len(self.data) - offset
            if body_size > max_possible_size:
                # Use fallback size if header value seems invalid
                body_size = max_possible_size
            
            # Hash EXACTLY body_size bytes starting from offset, not to end of file
            body_data = self.data[offset:offset + body_size]
            computed_hash = hashlib.sha256(body_data).digest()
            
            return computed_hash
        except Exception as e:
            # If header parsing fails, fall back to a reasonable default
            # but log the issue so user knows there's a problem
            return None

    def load_file(self, filepath):
        """Load PRODINFO file"""
        try:
            if not os.path.exists(filepath):
                return False, "File not found."
            
            with open(filepath, 'rb') as f:
                magic = f.read(4)
                if magic != b'CAL0':
                    return False, "Invalid PRODINFO file. Must be decrypted with 'CAL0' magic."
                f.seek(0)
                self.data = bytearray(f.read())
            
            self.filepath = filepath
            # Create backup
            shutil.copy(self.filepath, self.filepath + ".bak")
            return True, "File loaded successfully."
            
        except Exception as e:
            return False, f"Failed to load PRODINFO: {e}"

    def save_file(self, output_path=None):
        """Save PRODINFO file with recalculated checksums"""
        if not self.data:
            return False, "No PRODINFO data loaded."
        
        try:
            # Recalculate all checksums before saving
            self.recalculate_all_checksums()
            
            save_path = output_path or self.filepath
            with open(save_path, 'wb') as f:
                f.write(self.data)
            return True, "File saved successfully."
            
        except Exception as e:
            return False, f"Failed to save file: {e}"

    def get_serial(self):
        """Get serial number from PRODINFO"""
        if not self.data:
            return ""
        try:
            serial_bytes = self.data[0x250:0x250 + 14]
            return serial_bytes.decode('ascii', errors='replace').strip('\x00')
        except:
            return "Error Reading Serial"

    def set_serial(self, serial):
        """Set serial number in PRODINFO"""
        if not self.data or len(serial) != 14:
            return False
        try:
            # Clear the entire serial block first
            self.data[0x250:0x250 + 30] = b'\x00' * 30
            # Write the new serial
            self.data[0x250:0x250 + 14] = serial.encode('ascii')
            return True
        except:
            return False

    def get_wifi_region(self):
        """Get WiFi region from PRODINFO"""
        if not self.data:
            return "Unknown"
        try:
            region_bytes = self.data[0x88:0x88 + 4]
            return REGION_MAP.get(region_bytes.hex().upper(), "Unknown")
        except:
            return "Error Reading Region"

    def set_wifi_region(self, region_name):
        """Set WiFi region in PRODINFO"""
        if not self.data or region_name not in REGION_CODE_MAP:
            return False
        try:
            region_bytes = REGION_CODE_MAP[region_name]
            self.data[0x88:0x88 + 4] = region_bytes
            return True
        except:
            return False

    def get_color(self, color_name):
        """Get color value from PRODINFO"""
        if not self.data or color_name not in self.blocks:
            return "000000"
        try:
            offset, _ = self.blocks[color_name]
            color_bytes = self.data[offset:offset + 3]
            return color_bytes.hex().upper()
        except:
            return "000000"

    def set_color(self, color_name, hex_string):
        """Set color value in PRODINFO"""
        if not self.data or color_name not in self.blocks or len(hex_string) != 6:
            return False
        try:
            offset, _ = self.blocks[color_name]
            color_bytes = bytes.fromhex(hex_string)
            self.data[offset:offset + 3] = color_bytes
            # Set alpha to FF
            self.data[offset + 3] = 0xFF
            return True
        except:
            return False

    def write_crc16(self, block_name):
        """Write CRC16 for a specific block"""
        if block_name not in self.blocks:
            return
        
        offset, size = self.blocks[block_name]
        if offset + size <= len(self.data):
            block_data = self.data[offset:offset + size - 2]
            crc = self.calculate_crc16(block_data)
            struct.pack_into('<H', self.data, offset + size - 2, crc)

    def recalculate_all_checksums(self):
        """Recalculate all checksums and hashes"""
        # Update header update count
        try:
            update_count = struct.unpack('<H', self.data[0x10:0x12])[0]
            update_count += 1
            struct.pack_into('<H', self.data, 0x10, update_count)
        except:
            pass
        
        # Update header CRC
        try:
            header_data = self.data[0:0x1E]
            header_crc = self.calculate_crc16(header_data)
            struct.pack_into('<H', self.data, 0x1E, header_crc)
        except:
            pass
        
        # Update block CRCs
        for block_name in self.crc_blocks:
            self.write_crc16(block_name)
        
        # Update body SHA256
        try:
            body_hash = self.compute_sha256(0x40)
            if body_hash:
                self.data[0x20:0x40] = body_hash
        except:
            pass
        
        # Update full block CRC (if file is large enough)
        try:
            if len(self.data) >= 0x8004:
                full_block_data = self.data[0x0:0x8000]
                full_block_crc = self.calculate_crc16(full_block_data)
                struct.pack_into('<H', self.data, 0x8000, full_block_crc)
        except:
            pass

    def verify_file_integrity(self):
        """Verify the integrity of the loaded PRODINFO file"""
        if not self.data:
            return False, "No PRODINFO data loaded"
        
        verification_results = []
        
        try:
            # Read critical header values first
            body_size = struct.unpack('<I', self.data[0x8:0xC])[0]
            verification_results.append(f"Header body_size: {body_size} bytes (0x{body_size:X})")
            verification_results.append(f"File size: {len(self.data)} bytes (0x{len(self.data):X})")
            
            # 1. Verify header CRC16
            header_data = self.data[0:0x1E]
            stored_header_crc = struct.unpack('<H', self.data[0x1E:0x20])[0]
            computed_header_crc = self.calculate_crc16(header_data)
            
            if stored_header_crc == computed_header_crc:
                verification_results.append("✓ Header CRC16: VALID")
            else:
                verification_results.append(f"✗ Header CRC16: INVALID (stored: {stored_header_crc:04X}, computed: {computed_header_crc:04X})")
            
            # 2. Verify body SHA256 with EXACT size calculation
            stored_body_hash = self.data[0x20:0x40]
            computed_body_hash = self.compute_sha256(0x40)
            
            if computed_body_hash is None:
                verification_results.append("✗ Body SHA256: FAILED to compute (invalid header?)")
            elif stored_body_hash == computed_body_hash:
                verification_results.append("✓ Body SHA256: VALID")
                verification_results.append(f"  Hashed range: 0x40 to 0x{0x40 + body_size:X} ({body_size} bytes)")
            else:
                verification_results.append(f"✗ Body SHA256: INVALID")
                verification_results.append(f"  Hashed range: 0x40 to 0x{0x40 + body_size:X} ({body_size} bytes)")
                verification_results.append(f"  Stored:   {stored_body_hash.hex().upper()}")
                verification_results.append(f"  Computed: {computed_body_hash.hex().upper()}")
                verification_results.append("  This will cause Atmosphère to flag as INVALID_PRODINFO!")
            
            # 3. Verify individual block CRC16s
            for block_name in self.crc_blocks:
                if block_name in self.blocks:
                    offset, size = self.blocks[block_name]
                    if offset + size <= len(self.data):
                        block_data = self.data[offset:offset + size - 2]
                        stored_crc = struct.unpack('<H', self.data[offset + size - 2:offset + size])[0]
                        computed_crc = self.calculate_crc16(block_data)
                        
                        # Special handling for color blocks that might be uninitialized
                        if block_name in ['HousingBezelColor', 'HousingMainColor1']:
                            # Check if the color data is all zeros (uninitialized)
                            color_data = self.data[offset:offset + 3]
                            if color_data == b'\x00\x00\x00' and stored_crc == 0x0000:
                                verification_results.append(f"⚠  {block_name} CRC16: UNINITIALIZED (color data is 000000)")
                                verification_results.append(f"  This is normal for some NAND dumps - colors not set by manufacturer")
                                continue
                        
                        if stored_crc == computed_crc:
                            verification_results.append(f"✓ {block_name} CRC16: VALID")
                        else:
                            verification_results.append(f"✗ {block_name} CRC16: INVALID (stored: {stored_crc:04X}, computed: {computed_crc:04X})")
                            # For color blocks, show the actual color data for debugging
                            if block_name in ['HousingBezelColor', 'HousingMainColor1']:
                                color_data = self.data[offset:offset + 3]
                                verification_results.append(f"  Color data: {color_data.hex().upper()}")
                                full_block = self.data[offset:offset + size - 2]
                                verification_results.append(f"  Full block: {full_block.hex().upper()}")
            
            # Count only critical errors (not warnings)
            error_count = sum(1 for result in verification_results if result.startswith("✗"))
            warning_count = sum(1 for result in verification_results if result.startswith("⚠ "))
            
            if error_count == 0:
                if warning_count > 0:
                    return True, f"Verification passed with {warning_count} warnings:\n" + "\n".join(verification_results)
                else:
                    return True, "\n".join(verification_results)
            else:
                return False, f"Found {error_count} critical errors:\n" + "\n".join(verification_results)
                
        except Exception as e:
            return False, f"Verification failed: {e}"

class PRODINFOEditorDialog(tk.Toplevel):
    """Modal dialog for editing PRODINFO data"""
    
    def __init__(self, parent, prodinfo_path):
        super().__init__(parent)
        self.transient(parent)
        self.title("PRODINFO Editor")
        self.parent = parent
        self.result = False
        self.resizable(False, False)
        
        # Initialize engine with existing PRODINFO
        self.engine = ProdinfoEngine()
        success, message = self.engine.load_file(prodinfo_path)
        
        if not success:
            CustomDialog(parent, title="PRODINFO Error", message=f"Failed to load PRODINFO:\n{message}")
            self.destroy()
            return
        
        # Apply parent's theme
        self.configure(bg=parent.style.lookup('TFrame', 'background'))
        
        # GUI variables
        self.serial_var = tk.StringVar()
        self.region_var = tk.StringVar()
        self.color_vars = {
            'HousingBezelColor': tk.StringVar(),
            'HousingMainColor1': tk.StringVar()
        }
        
        self._setup_ui()
        self._populate_from_engine()
        self.center_window()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
    def _setup_ui(self):
        main_frame = ttk.Frame(self, padding="20", style="Dark.TFrame")
        main_frame.pack(expand=True, fill=tk.BOTH)
        
        # Serial section
        serial_frame = ttk.LabelFrame(main_frame, text="Serial Number", padding="10")
        serial_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(serial_frame, text="Current:", style="Dark.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.current_serial_label = ttk.Label(serial_frame, text="", style="Dark.TLabel", font=("Consolas", 9))
        self.current_serial_label.grid(row=0, column=1, sticky="w")
        
        ttk.Label(serial_frame, text="New:", style="Dark.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
        serial_entry = ttk.Entry(serial_frame, textvariable=self.serial_var, width=16, font=("Consolas", 9))
        serial_entry.grid(row=1, column=1, sticky="w", pady=(5, 0))

        # Limit serial number to 14 characters
        self.serial_var.trace_add("write", lambda *_: self._validate_serial_length())
        
        # Region section
        region_frame = ttk.LabelFrame(main_frame, text="WiFi Region", padding="10")
        region_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(region_frame, text="Current:", style="Dark.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.current_region_label = ttk.Label(region_frame, text="", style="Dark.TLabel", font=("Consolas", 9))
        self.current_region_label.grid(row=0, column=1, sticky="w")
        
        ttk.Label(region_frame, text="New:", style="Dark.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 5), pady=(5, 0))
        region_combo = ttk.Combobox(region_frame, textvariable=self.region_var, 
                                   values=list(REGION_CODE_MAP.keys()), state="readonly", width=18)
        region_combo.grid(row=1, column=1, sticky="w", pady=(5, 0))
        
        # Colors section
        colors_frame = ttk.LabelFrame(main_frame, text="Frame Colors", padding="10")
        colors_frame.pack(fill="x", pady=(0, 15))
        
        color_names = {
            'HousingBezelColor': 'Bezel Color',
            'HousingMainColor1': 'Main Color'
        }
        
        for idx, (color_key, display_name) in enumerate(color_names.items()):
            ttk.Label(colors_frame, text=f"{display_name}:", style="Dark.TLabel").grid(
                row=idx, column=0, sticky="w", padx=(0, 8), pady=3)
            
            color_entry = ttk.Entry(colors_frame, textvariable=self.color_vars[color_key], 
                                  width=8, font=("Consolas", 9))
            color_entry.grid(row=idx, column=1, padx=(0, 8), pady=3)
            
            color_preview = tk.Label(colors_frame, width=3, height=1, bg="white", relief="solid", borderwidth=1)
            color_preview.grid(row=idx, column=2, padx=(0, 8), pady=3)
            setattr(self, f"{color_key}_preview", color_preview)
            
            pick_btn = ttk.Button(colors_frame, text="Pick", 
                                command=lambda key=color_key: self._pick_color(key))
            pick_btn.grid(row=idx, column=3, pady=3)
            
            # Bind color entry changes
            self.color_vars[color_key].trace("w", lambda *args, key=color_key: self._update_color_preview(key))

        # Verification section
        verify_frame = ttk.LabelFrame(main_frame, text="File Integrity", padding="10")
        verify_frame.pack(fill="x", pady=(0, 10))

        verify_button = ttk.Button(verify_frame, text="Verify PRODINFO Integrity", 
                                command=self._verify_integrity, style="TButton")
        verify_button.pack(pady=5)    
        
        # Buttons
        button_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        button_frame.pack(pady=(10, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self.on_cancel, style="TButton").pack(
            side=tk.LEFT, padx=(0, 10), ipadx=10, ipady=2)
        ttk.Button(button_frame, text="Apply Changes", command=self.on_apply, style="Accent.TButton").pack(
            side=tk.LEFT, ipadx=10, ipady=2)
    
    def _populate_from_engine(self):
        """Populate dialog with current PRODINFO data"""
        # Serial
        current_serial = self.engine.get_serial()
        self.current_serial_label.config(text=current_serial)
        self.serial_var.set(current_serial)
        
        # Region
        current_region = self.engine.get_wifi_region()
        self.current_region_label.config(text=current_region)
        self.region_var.set(current_region)
        
        # Colors
        for color_key in self.color_vars:
            color_hex = self.engine.get_color(color_key)
            self.color_vars[color_key].set(color_hex)
            self._update_color_preview(color_key)

    def _validate_serial_length(self):
        """Limit serial number to 14 characters"""
        current = self.serial_var.get()
        if len(current) > 14:
            self.serial_var.set(current[:14])

    def _update_color_preview(self, color_key):
        """Update color preview square"""
        try:
            color_hex = self.color_vars[color_key].get().strip()
            if len(color_hex) == 6 and all(c in "0123456789ABCDEF" for c in color_hex.upper()):
                preview = getattr(self, f"{color_key}_preview")
                preview.config(bg=f"#{color_hex}")
        except:
            pass
    
    def _pick_color(self, color_key):
        """Open color picker dialog"""
        try:
            current_color = self.color_vars[color_key].get()
            initial_color = f"#{current_color}" if len(current_color) == 6 else "#000000"
            
            color_code = colorchooser.askcolor(
                title=f"Choose {color_key.replace('Housing', '').replace('Color', '').replace('1', '')} Color",
                initialcolor=initial_color
            )
            
            if color_code and color_code[1]:
                hex_color = color_code[1][1:].upper()
                self.color_vars[color_key].set(hex_color)
                
        except Exception as e:
            print(f"Error opening color chooser: {e}")
    
    def center_window(self):
        self.update_idletasks()
        parent_x, parent_y = self.parent.winfo_x(), self.parent.winfo_y()
        parent_w, parent_h = self.parent.winfo_width(), self.parent.winfo_height()
        dialog_w, dialog_h = self.winfo_width(), self.winfo_height()
        x = parent_x + (parent_w // 2) - (dialog_w // 2)
        y = parent_y + (parent_h // 2) - (dialog_h // 2)
        self.geometry(f"+{x}+{y}")
    
    def on_apply(self):
        """Apply changes and save PRODINFO"""
        try:
            # Apply serial
            serial = self.serial_var.get().strip()
            if len(serial) == 14:
                self.engine.set_serial(serial)
            
            # Apply region
            region = self.region_var.get()
            if region in REGION_CODE_MAP:
                self.engine.set_wifi_region(region)
            
            # Apply colors
            for color_key in self.color_vars:
                color_hex = self.color_vars[color_key].get().strip()
                if len(color_hex) == 6 and all(c in "0123456789ABCDEF" for c in color_hex.upper()):
                    self.engine.set_color(color_key, color_hex)
            
            # Save file
            success, message = self.engine.save_file()
            
            if success:
                self.result = True
                CustomDialog(self.parent, title="Success", message="PRODINFO updated successfully!")
                self.destroy()
            else:
                CustomDialog(self.parent, title="Save Error", message=f"Failed to save PRODINFO:\n{message}")
                
        except Exception as e:
            CustomDialog(self.parent, title="Error", message=f"Failed to apply changes:\n{e}")
    
    def on_cancel(self):
        """Cancel and close dialog"""
        self.result = False
        self.destroy()

    def _verify_integrity(self):
        """Verify the integrity of the currently loaded PRODINFO"""
        try:
            is_valid, results = self.engine.verify_file_integrity()
            
            # Create a new dialog to show results
            verify_dialog = tk.Toplevel(self)
            verify_dialog.title("PRODINFO Integrity Verification")
            verify_dialog.geometry("600x500")
            verify_dialog.configure(bg=self.parent.style.lookup('TFrame', 'background'))
            verify_dialog.transient(self)
            verify_dialog.grab_set()
            
            # Center the dialog
            parent_x, parent_y = self.winfo_x(), self.winfo_y()
            parent_w, parent_h = self.winfo_width(), self.winfo_height()
            dialog_w, dialog_h = 600, 500
            x = parent_x + (parent_w // 2) - (dialog_w // 2)
            y = parent_y + (parent_h // 2) - (dialog_h // 2)
            verify_dialog.geometry(f"+{x}+{y}")
            
            main_frame = ttk.Frame(verify_dialog, padding="15", style="Dark.TFrame")
            main_frame.pack(expand=True, fill=tk.BOTH)
            
            # Status label
            status_text = "✓ VERIFICATION PASSED" if is_valid else "✗ VERIFICATION FAILED"
            status_color = "#107c10" if is_valid else "#d13438"
            
            status_label = ttk.Label(main_frame, text=status_text, 
                                font=(self.parent.style.lookup('TLabel', 'font')[0], 12, 'bold'),
                                foreground=status_color, style="Dark.TLabel")
            status_label.pack(pady=(0, 10))
            
            # Results text widget
            text_widget = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD,
                bg="#1e1e1e", fg="#d4d4d4", relief="flat", borderwidth=1,
                font=("Consolas", 9), insertbackground="#d4d4d4"
            )
            text_widget.pack(expand=True, fill="both", pady=(0, 10))
            
            # Insert results
            text_widget.insert(tk.END, results)
            text_widget.config(state="disabled")
            
            # Close button
            close_button = ttk.Button(main_frame, text="Close", 
                                    command=verify_dialog.destroy, style="Accent.TButton")
            close_button.pack(pady=5)
            
        except Exception as e:
            CustomDialog(self.parent, title="Verification Error", 
                        message=f"Failed to verify PRODINFO integrity:\n{e}")    



# --- YOUR ORIGINAL SCRIPT CONTINUES HERE ---
from tkinter import ttk, filedialog, scrolledtext
import os
import tempfile
import shutil
from pathlib import Path
import threading
import subprocess
import re
import ctypes
import configparser
import pythoncom

# --- CUSTOM DIALOG CLASS (Modernized) ---
class CustomDialog(tk.Toplevel):
    def __init__(self, parent, title=None, message="", buttons="ok"):
        super().__init__(parent)
        self.transient(parent)
        self.title(title)
        self.parent = parent
        self.result = False
        self.resizable(False, False)
        self.last_output_dir = None
        
        # Apply modern theme from parent
        self.configure(bg=parent.style.lookup('TFrame', 'background'))

        main_frame = ttk.Frame(self, padding="20 20 20 20", style="Dark.TFrame")
        main_frame.pack(expand=True, fill=tk.BOTH)

        message_label = ttk.Label(main_frame, text=message, wraplength=400, justify=tk.LEFT, style="Dark.TLabel")
        message_label.pack(padx=10, pady=10)
        
        button_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        button_frame.pack(pady=(20, 0))

        if buttons == "yesno":
            yes_button = ttk.Button(button_frame, text="是", command=self.on_yes, style="Accent.TButton")
            yes_button.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=2)
            no_button = ttk.Button(button_frame, text="否", command=self.on_no, style="TButton")
            no_button.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=2)
            self.bind("<Return>", lambda e: self.on_yes())
            self.bind("<Escape>", lambda e: self.on_no())
        else: # Default is "ok"
            ok_button = ttk.Button(button_frame, text="确定", command=self.on_no, style="Accent.TButton")
            ok_button.pack(side=tk.LEFT, padx=10, ipadx=10, ipady=2)
            self.bind("<Return>", lambda e: self.on_no())
            self.bind("<Escape>", lambda e: self.on_no())

        self.center_window()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_no)
        self.wait_window(self)

    def center_window(self):
        self.update_idletasks()
        parent_x, parent_y = self.parent.winfo_x(), self.parent.winfo_y()
        parent_w, parent_h = self.parent.winfo_width(), self.parent.winfo_height()
        dialog_w, dialog_h = self.winfo_width(), self.winfo_height()
        x = parent_x + (parent_w // 2) - (dialog_w // 2)
        y = parent_y + (parent_h // 2) - (dialog_h // 2)
        self.geometry(f"+{x}+{y}")

    def on_yes(self):
        self.result = True
        self.destroy()

    def on_no(self):
        self.result = False
        self.destroy()

class ConsoleTypeDialog(tk.Toplevel):
    """Dialog for selecting console type override"""
    def __init__(self, parent, current_selection=""):
        super().__init__(parent)
        self.transient(parent)
        self.title("Switch型号")
        self.parent = parent
        self.result = None  # Will store selected console type or None if cancelled
        self.resizable(False, False)

        # Apply modern theme from parent
        self.configure(bg=parent.style.lookup('TFrame', 'background'))

        main_frame = ttk.Frame(self, padding="20 20 20 20", style="Dark.TFrame")
        main_frame.pack(expand=True, fill=tk.BOTH)

        # Warning message
        warning_text = (
            "⚠️ 此功能仅应在修复具有不匹配固件文件的Switch时使用\n"
            "(例如，为不同Switch变体生成的启动文件)\n\n"
            "例子:\n"
            "• Switch有Erista启动文件但实际上是Mariko\n"
            "• Switch有Mariko启动文件但实际上是Erista\n"
            "• 错误: \"Erista pkg1 on Mariko\" 或 \"Wrong pkg1 flashed\"\n\n"
            "如果不确定，请取消并使用自动检测。\n"
        )
        warning_label = ttk.Label(main_frame, text=warning_text,
                                 wraplength=450, justify=tk.LEFT, style="Dark.TLabel")
        warning_label.pack(padx=10, pady=(10, 20))

        # Dropdown frame
        dropdown_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        dropdown_frame.pack(pady=(0, 20))

        ttk.Label(dropdown_frame, text="选择您的Switch型号:",
                 style="Dark.TLabel").pack(side=tk.LEFT, padx=(0, 10))

        self.console_type_var = tk.StringVar(value=current_selection if current_selection else "Erista (V1 已修补/未修补)")
        console_dropdown = ttk.Combobox(
            dropdown_frame,
            textvariable=self.console_type_var,
            values=["Erista (V1 已修补/未修补)", "Mariko (V2, Lite, OLED)"],
            state="readonly",
            width=30
        )
        console_dropdown.pack(side=tk.LEFT)

        # Buttons
        button_frame = ttk.Frame(main_frame, style="Dark.TFrame")
        button_frame.pack(pady=(10, 0))

        ok_button = ttk.Button(button_frame, text="确定", command=self.on_ok,
                              style="Accent.TButton")
        ok_button.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=2)

        cancel_button = ttk.Button(button_frame, text="取消", command=self.on_cancel,
                                   style="TButton")
        cancel_button.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=2)

        self.bind("<Return>", lambda _: self.on_ok())
        self.bind("<Escape>", lambda _: self.on_cancel())

        self.center_window()
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def center_window(self):
        self.update_idletasks()
        parent_x, parent_y = self.parent.winfo_x(), self.parent.winfo_y()
        parent_w, parent_h = self.parent.winfo_width(), self.parent.winfo_height()
        dialog_w, dialog_h = self.winfo_width(), self.winfo_height()
        x = parent_x + (parent_w // 2) - (dialog_w // 2)
        y = parent_y + (parent_h // 2) - (dialog_h // 2)
        self.geometry(f"+{x}+{y}")

    def on_ok(self):
        self.result = self.console_type_var.get()
        self.destroy()

    def on_cancel(self):
        self.result = None
        self.destroy()

# --- MAIN APPLICATION CLASS ---
class SwitchGuiApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.version = "2.0.3"
        self.title(f"NAND Fix Pro v{self.version} 中文版")
        self.geometry("650x700") # Changed height for a better fit
        self.resizable(False, False)
        
        # --- PATHS & STATE VARIABLES ---
        self.config_file = "config.ini"
        self.paths = {
            "7z": tk.StringVar(), "osfmount": tk.StringVar(),
            "nxnandmanager": tk.StringVar(), "keys": tk.StringVar(), "firmware": tk.StringVar(),
            "prodinfo": tk.StringVar(), "partitions_folder": tk.StringVar(),
            "output_folder": tk.StringVar(), "emmchaccgen": tk.StringVar(),
            "temp_directory": tk.StringVar(),
        }
        self.level_requirements = {
            1: ["firmware", "7z", "emmchaccgen", "nxnandmanager", "osfmount"],
            2: ["firmware", "7z", "emmchaccgen", "nxnandmanager", "osfmount", "partitions_folder"],
            3: ["firmware", "prodinfo", "7z", "emmchaccgen", "nxnandmanager", "osfmount", "partitions_folder"]
        }
        self.start_level1_button, self.start_level2_button, self.start_level3_button = None, None, None

        self.prodinfo_browse_button = None

        self.button_states = {
            "get_keys": "active",
            "level1": "disabled", 
            "level2": "disabled", 
            "level3": "disabled",
            "copy_boot": "disabled",
            "advanced_user": "disabled"
        }
        self.get_keys_buttons = []
        self.copy_boot_buttons = []
        self.advanced_user_button = None
        self.donor_prodinfo_from_sd = False

        # Console type override variables
        self.override_console_type = tk.BooleanVar(value=False)
        self.manual_console_type = tk.StringVar(value="")

        # --- INITIALIZATION ---
        self._setup_styles()
        self._load_config()
        self._setup_widgets()
        self._validate_paths_and_update_buttons()
        self.center_window()

        # Set up cleanup on exit
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        
    def _create_main_button_row(self, parent_frame, process_name, command, button_ref):
        """Creates the consistent row of three main buttons for each tab."""
        button_frame = ttk.Frame(parent_frame)

        # Get Keys button (left)
        get_keys_button = ttk.Button(button_frame, text="从SD卡获取密钥",
                                     command=self._get_keys_from_sd, style="Active.TButton")
        get_keys_button.pack(side=tk.LEFT, padx=10, ipady=5, ipadx=15)
        self.get_keys_buttons.append(get_keys_button)

        # Main process button (center)
        button = ttk.Button(button_frame, text=f"开始{process_name}处理",
                            command=command, style="Disabled.TButton", state="disabled")
        button.pack(side=tk.LEFT, padx=10, ipady=5, ipadx=15)
        setattr(self, button_ref, button)

        # Copy BOOT files button (right)
        copy_boot_button = ttk.Button(button_frame, text="复制BOOT到SD卡",
                                      command=self._copy_boot_files_to_sd, style="Disabled.TButton", state="disabled")
        copy_boot_button.pack(side=tk.LEFT, padx=10, ipady=5, ipadx=15)
        
        # 确保按钮被添加到列表中，以便后续更新
        if copy_boot_button not in self.copy_boot_buttons:
            self.copy_boot_buttons.append(copy_boot_button)
            self._log(f"DEBUG: Added copy BOOT button to tracking list")
        
        return button_frame
        
    # In class SwitchGuiApp:

    def _update_progress(self, progress_text):
        """Displays and updates a progress bar on a single line in the log."""
        if hasattr(self, 'log_widget') and self.log_widget:
            self.log_widget.config(state="normal")

            # Check if we have a progress line marker
            if not hasattr(self, '_progress_line_index'):
                # First time - insert a new line and use a mark to track it
                self.log_widget.insert(tk.END, f"--- Progress: {progress_text}\n")
                # Create a mark at the start of this line (gravity=left keeps it stable)
                self.log_widget.mark_set("progress_mark", "end-2l linestart")
                self.log_widget.mark_gravity("progress_mark", "left")
                self._progress_line_index = True  # Flag to indicate we have a progress line
            else:
                # Update the existing progress line in place using the mark
                line_start = "progress_mark"
                line_end = f"{line_start} lineend"
                self.log_widget.delete(line_start, line_end)
                self.log_widget.insert(line_start, f"--- Progress: {progress_text}")

            self.log_widget.see(tk.END)
            self.log_widget.config(state="disabled")
            self.update_idletasks()

    def _run_command_with_progress(self, command, task_name="Processing"):
        """Runs a command (like 7z) and shows a progress bar by parsing its output."""
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                                        bufsize=1, universal_newlines=True)
            output = []
            progress_regex = re.compile(r"(\d+)\s*%\s*\d*") # Regex to find percentage

            for line in iter(process.stdout.readline, ''):
                clean_line = line.strip()
                if not clean_line: continue

                match = progress_regex.search(clean_line)
                if match:
                    percent = int(match.group(1))
                    bar_length = 25
                    filled_length = int(bar_length * percent / 100)
                    bar = '█' * filled_length + '-' * (bar_length - filled_length)
                    self._update_progress(f"{task_name}: [{bar}] {percent}%")
                else:
                    output.append(clean_line)
                    self._log(clean_line)

            process.stdout.close()
            return_code = process.wait()

            # Clear progress tracker for next operation
            if hasattr(self, '_progress_line_index'):
                delattr(self, '_progress_line_index')

            self._log(f"--- {task_name} finished.")
            return return_code, "\n".join(output)
        except Exception as e:
            # Clear progress tracker on error
            if hasattr(self, '_progress_line_index'):
                delattr(self, '_progress_line_index')
            self._log(f"FATAL ERROR: Failed to execute command. {e}")
            return -1, str(e)

    def _copy_with_progress(self, src_path, dest_path, task_name="Copying file"):
        """Copies a large file while displaying a progress bar."""
        try:
            src_path, dest_path = Path(src_path), Path(dest_path)
            total_size = src_path.stat().st_size
            copied_size = 0
            chunk_size = 1024 * 1024 # 1MB chunks

            with open(src_path, 'rb') as src, open(dest_path, 'wb') as dest:
                while True:
                    chunk = src.read(chunk_size)
                    if not chunk:
                        break
                    dest.write(chunk)
                    copied_size += len(chunk)

                    percent = int((copied_size / total_size) * 100)
                    bar_length = 25
                    filled_length = int(bar_length * percent / 100)
                    bar = '█' * filled_length + '-' * (bar_length - filled_length)
                    self._update_progress(f"{task_name}: [{bar}] {percent}%")

            # Clear progress tracker for next operation
            if hasattr(self, '_progress_line_index'):
                delattr(self, '_progress_line_index')

            self._log(f"--- {task_name} finished.")
            return True
        except Exception as e:
            # Clear progress tracker on error
            if hasattr(self, '_progress_line_index'):
                delattr(self, '_progress_line_index')
            self._log(f"ERROR: File copy failed. {e}")
            return False    

    def center_window(self):
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        window_w = self.winfo_width()
        window_h = self.winfo_height()
        x = (screen_w // 2) - (window_w // 2)
        y = (screen_h // 2) - (window_h // 2)
        self.geometry(f'+{x}+{y}')

    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        self.BG_COLOR = "#2e2e2e"
        self.FG_COLOR = "#fafafa"
        self.BG_LIGHT = "#3c3c3c"
        self.BG_DARK = "#252525"
        self.ACCENT_COLOR = "#0078d4"
        self.ACCENT_ACTIVE = "#005a9e"
        self.DISABLED_FG = "#888888"
        self.FONT_FAMILY = "Segoe UI"

        self.configure(background=self.BG_COLOR)

        self.style.configure('.', background=self.BG_COLOR, foreground=self.FG_COLOR, font=(self.FONT_FAMILY, 10))
        self.style.configure("TFrame", background=self.BG_COLOR)
        self.style.configure("Dark.TFrame", background=self.BG_DARK)
        self.style.configure("TLabel", background=self.BG_COLOR, foreground=self.FG_COLOR, font=(self.FONT_FAMILY, 10))
        self.style.configure("Dark.TLabel", background=self.BG_DARK, foreground=self.FG_COLOR, font=(self.FONT_FAMILY, 10))
        self.style.configure("TCheckbutton", font=(self.FONT_FAMILY, 10))
        self.style.map("TCheckbutton",
                       background=[('active', self.BG_COLOR)],
                       indicatorbackground=[('selected', self.ACCENT_COLOR), ('!selected', self.BG_LIGHT)],
                       indicatorcolor=[('!selected', self.BG_LIGHT)])

        self.style.configure("TButton", font=(self.FONT_FAMILY, 10, 'bold'), borderwidth=0, padding=(10, 5))
        self.style.map("TButton",
                       background=[('!disabled', self.BG_LIGHT), ('active', self.ACCENT_ACTIVE), ('disabled', self.BG_DARK)],
                       foreground=[('!disabled', self.FG_COLOR), ('disabled', self.DISABLED_FG)])
        self.style.configure("Accent.TButton", background=self.ACCENT_COLOR)
        self.style.map("Accent.TButton",
                       background=[('!disabled', self.ACCENT_COLOR), ('active', self.ACCENT_ACTIVE), ('disabled', self.BG_DARK)],
                       foreground=[('!disabled', '#ffffff'), ('disabled', self.DISABLED_FG)])

        self.style.configure("TLabelFrame", background=self.BG_COLOR, borderwidth=1, relief="solid")
        self.style.configure("TLabelFrame.Label", background=self.BG_COLOR, foreground=self.FG_COLOR,
                             font=(self.FONT_FAMILY, 11, 'bold'))
        
        # --- THIS IS THE CORRECTED PART FOR LEFT-ALIGNED TABS ---
        self.style.configure("TNotebook", background=self.BG_COLOR, borderwidth=0)
        self.style.configure("TNotebook.Tab",
                             background=self.BG_LIGHT,
                             foreground=self.FG_COLOR,
                             font=(self.FONT_FAMILY, 10, 'bold'),
                             padding=[15, 8],
                             borderwidth=0,
                             anchor='w') # Anchor text to the left
        self.style.map("TNotebook.Tab",
                       background=[("selected", self.BG_COLOR), ("active", self.ACCENT_COLOR)])
                       # 'expand' property is REMOVED to stop stretching

        self.style.configure("Active.TButton", background="#0078d4", foreground="#ffffff")
        self.style.map("Active.TButton",
                       background=[('!disabled', '#0078d4'), ('active', '#005a9e'), ('disabled', self.BG_DARK)],
                       foreground=[('!disabled', '#ffffff'), ('disabled', self.DISABLED_FG)])

        self.style.configure("Completed.TButton", background="#107c10", foreground="#ffffff")
        self.style.map("Completed.TButton",
                       background=[('!disabled', '#107c10'), ('active', '#0e6e0e'), ('disabled', self.BG_DARK)],
                       foreground=[('!disabled', '#ffffff'), ('disabled', self.DISABLED_FG)])

        self.style.configure("Disabled.TButton", background=self.BG_DARK, foreground=self.DISABLED_FG)

        # Entry styles - FIXED for visibility
        self.style.configure("TEntry", 
                           background="#ffffff",        # White background
                           foreground="#000000",        # Black text
                           fieldbackground="#ffffff",   # White field
                           borderwidth=1,
                           insertcolor="#000000")       # Black cursor

        # Combobox styles - FIXED for visibility  
        self.style.configure("TCombobox",
                           background="#ffffff",        # White background
                           foreground="#000000",        # Black text
                           fieldbackground="#ffffff",   # White field
                           borderwidth=1)
        self.style.map("TCombobox",
                      foreground=[('readonly', '#000000'),    # Black text in readonly
                                 ('active', '#000000')])      # Black text when active

    # THIS IS THE NEW, MORE RELIABLE FUNCTION
    def _detect_switch_sd_card_wmi(self):
        """Detect Switch SD card by iterating logical drives and checking their parent hardware ID."""
        self._log("--- Detecting Switch SD card using specific hardware IDs...")
        try:
            import wmi
            c = wmi.WMI()

            # Iterate through all logical disks (e.g., "C:", "D:")
            for logical_disk in c.Win32_LogicalDisk():
                try:
                    # Go backwards from the logical disk to find its partition
                    partitions = c.query(f"ASSOCIATORS OF {{Win32_LogicalDisk.DeviceID='{logical_disk.DeviceID}'}} WHERE AssocClass=Win32_LogicalDiskToPartition")
                    if not partitions:
                        continue

                    # Go backwards from the partition to find the physical disk drive it belongs to
                    physical_disks = c.query(f"ASSOCIATORS OF {{Win32_DiskPartition.DeviceID='{partitions[0].DeviceID}'}} WHERE AssocClass=Win32_DiskDriveToDiskPartition")
                    if not physical_disks:
                        continue

                    # Now we have the parent physical disk, check its hardware ID
                    disk = physical_disks[0]
                    pnp_id = disk.PNPDeviceID or ""

                    # Check if the physical disk has the unique Hekate SD card signature
                    if "VEN_HEKATE" in pnp_id and "PROD_SD_RAW" in pnp_id:
                        mountpoint = logical_disk.DeviceID
                        self._log(f"--- SUCCESS: Found Hekate SD Card ({pnp_id}) at drive: {mountpoint}")
                        return Path(mountpoint)
                except Exception:
                    # Ignore any errors for specific drives and just continue checking others
                    continue

        except ImportError:
            self._log("ERROR: The 'wmi' library is required for SD card detection.")
            CustomDialog(self, title="Dependency Error", message="The 'wmi' library is not installed.")
            return None
        except Exception as e:
            self._log(f"ERROR: A critical exception occurred during WMI SD card detection: {e}")
            return None

        self._log("--- No Switch SD card with Hekate hardware ID was found.")
        return None

    def _manual_select_sd_card(self):
        """Prompt user to manually select the SD card drive when automatic detection fails."""
        self._log("--- Prompting user for manual SD card selection...")

        dialog = CustomDialog(
            self,
            title="SD Card Not Found",
            message="Could not automatically detect Switch SD card.\n\nPlease ensure:\n• SD card is mounted via Hekate USB tools\n• SD card contains /bootloader/ folder\n\nWould you like to manually select the SD card?",
            buttons="yesno"
        )

        if not dialog.result:
            self._log("--- User declined manual SD card selection.")
            return None

        # Open folder selection dialog
        sd_path = filedialog.askdirectory(
            title="Select Switch SD Card Drive/Folder",
            mustexist=True
        )

        if not sd_path:
            self._log("--- User canceled SD card selection.")
            return None

        sd_path = Path(sd_path)
        self._log(f"--- User selected path: {sd_path}")

        # Validate the selected path has the bootloader folder
        bootloader_path = sd_path / "bootloader"
        if not bootloader_path.exists():
            self._log(f"ERROR: Selected path does not contain /bootloader/ folder.")
            CustomDialog(
                self,
                title="Invalid SD Card",
                message=f"The selected folder does not contain a /bootloader/ folder.\n\nPlease select the root of your Switch SD card."
            )
            return None

        self._log(f"--- SUCCESS: Manually selected SD card validated at: {sd_path}")
        return sd_path

    def _detect_switch_drives_wmi(self):
            self._log("--- Detecting Switch eMMC using specific hardware IDs...")
            try:
                import wmi
            except ImportError:
                self._log("ERROR: The 'wmi' library is required. Please run 'pip install wmi' from a command prompt.")
                CustomDialog(self, title="Dependency Error", message="The 'wmi' library is not installed.\nPlease run 'pip install wmi' in a command prompt.")
                return []
            
            c = wmi.WMI()
            potential_drives = []
            for disk in c.Win32_DiskDrive():
                pnp_id = disk.PNPDeviceID or ""
                # The PNPDeviceID is the most reliable identifier. We look for the unique strings
                # from Hekate's UMS implementation for the eMMC.
                # e.g., "USBSTOR\\DISK&VEN_HEKATE&PROD_EMMC_GPP&REV_1.00\\..."
                if "VEN_HEKATE" in pnp_id and "PROD_EMMC_GPP" in pnp_id:
                    try:
                        size_gb = int(disk.Size) / (1024**3)
                        drive_info = {
                            "path": disk.DeviceID,
                            "size": f"{size_gb:.2f} GB",
                            "size_gb": size_gb,
                            "model": disk.Model
                        }
                        potential_drives.append(drive_info)
                        self._log(f"--- Found Switch eMMC GPP drive: {drive_info['path']} ({drive_info['size']})")
                    except Exception as e:
                        self._log(f"WARNING: Found Hekate eMMC device but could not get its size. Error: {e}")
                        continue # Skip if size calculation fails

            if not potential_drives:
                self._log("--- No Switch eMMC GPP drive with Hekate hardware ID was found.")
            return potential_drives    

    def _setup_widgets(self):
        menubar = tk.Menu(self, background=self.BG_LIGHT, foreground=self.FG_COLOR,
                            activebackground=self.ACCENT_COLOR, activeforeground=self.FG_COLOR, 
                            relief="flat", borderwidth=0)
        self.config(menu=menubar)

        # --- Setup Settings, PRODINFO, and Help Menus ---
        self._setup_settings_menu(menubar)
        self._setup_prodinfo_menu(menubar)  # THIS LINE WAS MISSING!

        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0,
            background=self.BG_LIGHT, foreground=self.FG_COLOR,
            activebackground=self.ACCENT_COLOR, activeforeground=self.FG_COLOR,
            relief="flat", borderwidth=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="使用指南", command=self._show_usage_guide_window)
        help_menu.add_separator()
        help_menu.add_command(label="关于 NAND Fix Pro", command=self._show_about_window)

        # --- STANDARD TTK.NOTEBOOK IMPLEMENTATION ---
        self.tab_control = ttk.Notebook(self, style="TNotebook")
        
        # Create tab frames
        self.tab_level1 = ttk.Frame(self.tab_control, padding="15")
        self.tab_level2 = ttk.Frame(self.tab_control, padding="15")
        self.tab_level3 = ttk.Frame(self.tab_control, padding="15")
        
        # Add tabs to notebook
        self.tab_control.add(self.tab_level1, text='第1级: 系统恢复')
        self.tab_control.add(self.tab_level2, text='第2级: 完全重建')
        self.tab_control.add(self.tab_level3, text='第3级: 完整恢复')
        
        # Pack the notebook
        self.tab_control.pack(expand=1, fill="both", padx=15, pady=10)
        
        # --- POPULATE TABS ---
        self._setup_level1_tab(self.tab_level1)
        self._setup_level2_tab(self.tab_level2)
        self._setup_level3_tab(self.tab_level3)
        
        # --- LOG WIDGET SETUP ---
        log_frame = ttk.LabelFrame(self, text="日志输出", padding="10")
        log_frame.pack(padx=15, pady=(5, 15), fill="both", expand=True)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_widget = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, state="disabled",
            bg="#1e1e1e", fg="#d4d4d4", relief="flat", borderwidth=2,
            font=("Consolas", 10), insertbackground="#d4d4d4"
        )
        self.log_widget.grid(row=0, column=0, sticky="nsew")

        # Add button frame for Save and Clear buttons
        button_frame = ttk.Frame(log_frame)
        button_frame.grid(row=1, column=0, pady=(10, 0), sticky="e")

        # Reset App button
        reset_button = ttk.Button(button_frame, text="重置应用", command=self._reset_application_state, style="TButton")
        reset_button.pack(side=tk.LEFT, padx=(0, 10))

        clear_log_button = ttk.Button(button_frame, text="清除日志", command=self._clear_log, style="TButton")
        clear_log_button.pack(side=tk.LEFT, padx=(0, 10))

        save_log_button = ttk.Button(button_frame, text="保存日志", command=self._save_log, style="TButton")
        save_log_button.pack(side=tk.LEFT)

      

    def _load_config(self):
        """Loads paths from config.ini, running auto-detect if it doesn't exist."""
        config = configparser.ConfigParser()
        # Paths that should be reset on each app launch
        transient_paths = ["keys", "prodinfo", "firmware"]

        if Path(self.config_file).exists():
            config.read(self.config_file)
            for key in self.paths:
                # Don't load transient paths from config - they should always start empty
                if key in transient_paths:
                    self.paths[key].set('')
                else:
                    self.paths[key].set(config.get('Paths', key, fallback=''))
            # Save config to clear transient paths from config.ini
            self._save_config()
        else:
            self._auto_detect_paths()
            self._save_config()

    def _save_config(self):
        """Saves current paths to config.ini."""
        config = configparser.ConfigParser()
        config['Paths'] = {key: var.get() for key, var in self.paths.items()}
        with open(self.config_file, 'w') as configfile:
            config.write(configfile)
        self._log(f"INFO: Configuration saved to {self.config_file}")

    def _is_path_valid(self, key):
        """Helper to check if a path from the dict is non-empty and exists."""
        path_str = self.paths[key].get()
        if not path_str:
            return False
        return Path(path_str).exists()
    
    def _check_disk_space(self, required_gb=60):
        try:
            import shutil
            # Use custom temp directory if set, otherwise use system default
            if self.paths['temp_directory'].get():
                temp_dir = self.paths['temp_directory'].get()
            else:
                temp_dir = tempfile.gettempdir()
                
            free_bytes = shutil.disk_usage(temp_dir).free
            free_gb = free_bytes / (1024**3)
            
            if free_gb < required_gb:
                self._log(f"ERROR: Insufficient disk space on {temp_dir}. Need {required_gb}GB, have {free_gb:.1f}GB available")
                CustomDialog(self, title="磁盘空间不足", 
                            message=f"所选驱动器上的可用空间不足。\n\n" +
                                    f"驱动器: {temp_dir}\n" +
                                    f"所需: {required_gb}GB\n" +
                                    f"可用: {free_gb:.1f}GB\n\n" +
                                    f"请释放空间或在设置中选择其它目录。")
                return False
            
            self._log(f"--- Disk space check: {free_gb:.1f}GB available on {temp_dir}")
            return True
            
        except Exception as e:
            self._log(f"WARNING: Could not check disk space. {e}")
            return True

    def _validate_paths_and_update_buttons(self):
        """Checks required paths for each level and enables/disables buttons."""
        keys_ready = self.button_states["get_keys"] == "completed"
        
        # Level 1 Validation
        level1_ok = all(self._is_path_valid(key) for key in self.level_requirements[1])
        if self.start_level1_button:
            if keys_ready and level1_ok:
                self.start_level1_button.config(state="normal")
                # DON'T override completed state
                if self.button_states["level1"] == "disabled":
                    self.button_states["level1"] = "active"
            else:
                self.start_level1_button.config(state="disabled")
                # Only set to disabled if not completed
                if self.button_states["level1"] not in ["completed", "active"]:
                    self.button_states["level1"] = "disabled"

        # Level 2 Validation
        level2_ok = all(self._is_path_valid(key) for key in self.level_requirements[2])
        if self.start_level2_button:
            if keys_ready and level2_ok:
                self.start_level2_button.config(state="normal")
                # DON'T override completed state
                if self.button_states["level2"] == "disabled":
                    self.button_states["level2"] = "active"
            else:
                self.start_level2_button.config(state="disabled")
                # Only set to disabled if not completed
                if self.button_states["level2"] not in ["completed", "active"]:
                    self.button_states["level2"] = "disabled"

        # Advanced USER Fix button (same requirements as Level 2)
        if self.advanced_user_button:
            if keys_ready and level2_ok:
                self.advanced_user_button.config(state="normal")
                # DON'T override completed state
                if self.button_states["advanced_user"] == "disabled":
                    self.button_states["advanced_user"] = "available"
            else:
                self.advanced_user_button.config(state="disabled")
                # Only set to disabled if not completed
                if self.button_states["advanced_user"] not in ["completed", "available"]:
                    self.button_states["advanced_user"] = "disabled"

        # Level 3 Validation
        level3_ok = all(self._is_path_valid(key) for key in self.level_requirements[3])
        if self.start_level3_button:
            if keys_ready and level3_ok:
                self.start_level3_button.config(state="normal")
                # DON'T override completed state
                if self.button_states["level3"] == "disabled":
                    self.button_states["level3"] = "active"
            else:
                self.start_level3_button.config(state="disabled")
                # Only set to disabled if not completed
                if self.button_states["level3"] not in ["completed", "active"]:
                    self.button_states["level3"] = "disabled"
        
        # DON'T RESET GET_KEYS BUTTON STATE HERE - it should stay completed once done
        
        self._update_button_colors()
        self.update_idletasks()

        # Enable PRODINFO menu whenever a valid PRODINFO file is loaded (from any source)
        if self._is_path_valid("prodinfo"):
            self._enable_prodinfo_menu()
        else:
            self._disable_prodinfo_menu()

    def _update_button_colors(self):
        """Update button colors and states based on workflow progression."""
        try:
            # Get Keys Buttons
            for button in self.get_keys_buttons:
                if self.button_states["get_keys"] == "completed":
                    button.config(style="Completed.TButton", state="disabled") # Green and disabled
                else:
                    button.config(style="Active.TButton", state="normal") # Blue and clickable

            # Level Process Buttons
            for level_num, button_attr in [(1, "start_level1_button"), (2, "start_level2_button"), (3, "start_level3_button")]:
                button = getattr(self, button_attr, None)
                if button:
                    state_key = f"level{level_num}"
                    if self.button_states[state_key] == "active":
                        button.config(style="Active.TButton", state="normal")     # Blue and clickable
                    elif self.button_states[state_key] == "completed":
                        button.config(style="Completed.TButton", state="disabled") # Green and disabled
                    else:
                        button.config(style="Disabled.TButton", state="disabled")  # Grey and disabled

            # Advanced User Button (grey but clickable when available)
            if self.advanced_user_button:
                if self.button_states["advanced_user"] in ["available", "completed"]:
                    self.advanced_user_button.config(style="Disabled.TButton", state="normal")
                else:
                    self.advanced_user_button.config(style="Disabled.TButton", state="disabled")

            # Copy BOOT Buttons - 增强更新逻辑，确保所有按钮都能正确更新
            self._log(f"DEBUG: Updating {len(self.copy_boot_buttons)} copy BOOT buttons, state: {self.button_states['copy_boot']}")
            for button in self.copy_boot_buttons:
                if button:
                    if self.button_states["copy_boot"] == "active":
                        button.config(style="Active.TButton", state="normal")
                        self._log(f"DEBUG: Copy BOOT button activated")
                    elif self.button_states["copy_boot"] == "completed":
                        button.config(style="Completed.TButton", state="disabled")
                        self._log(f"DEBUG: Copy BOOT button marked as completed")
                    else:
                        button.config(style="Disabled.TButton", state="disabled")
                        self._log(f"DEBUG: Copy BOOT button disabled")
                    # 强制更新界面以确保更改生效
                    button.update_idletasks()
                    
        except Exception as e:
            self._log(f"WARNING: Could not update button colors: {e}")
            import traceback
            self._log(f"ERROR DETAILS: {traceback.format_exc()}")    

    def _show_about_window(self):
            """Displays a simple 'About' dialog with version and credit info."""
            about_message = (f"NAND Fix Pro 中文版 v{self.version}\n\n"
                            "用于修复和重建任天堂Switch eMMC NAND的工具。\n\n"
                            "由sthetix开发和维护\n\n"
                            "中文翻译 南宫镜")
            CustomDialog(self, title="关于 NAND Fix Pro 中文版", message=about_message)    

    def _show_usage_guide_window(self):
        """Creates a new window and displays the contents of usage.txt."""
        try:
            # Determine the path to the usage guide
            try:
                # Path when running as a script
                base_path = Path(__file__).parent
            except NameError:
                # Path when running as a frozen executable (PyInstaller)
                base_path = Path(sys.executable).parent
            
            guide_path = base_path / "lib" / "docs" / "usage.txt"

            if guide_path.is_file():
                with open(guide_path, 'r', encoding='utf-8') as f:
                    guide_content = f.read()
            else:
                guide_content = "错误: 找不到使用指南文件。\n\n" \
                                f"请确保'usage.txt'存在于以下位置:\n{guide_path}"
        except Exception as e:
            guide_content = f"尝试加载使用指南时发生意外错误:\n\n{e}"

        # Create the Toplevel window
        help_win = tk.Toplevel(self)
        help_win.title("使用指南")
        help_win.geometry("700x600")
        help_win.configure(bg=self.BG_COLOR)
        
        # Center the window relative to the parent
        parent_x, parent_y = self.winfo_x(), self.winfo_y()
        parent_w, parent_h = self.winfo_width(), self.winfo_height()
        win_w, win_h = 700, 600
        x = parent_x + (parent_w // 2) - (win_w // 2)
        y = parent_y + (parent_h // 2) - (win_h // 2)
        help_win.geometry(f"+{x}+{y}")
        
        # Create a ScrolledText widget
        text_widget = scrolledtext.ScrolledText(help_win, wrap=tk.WORD,
            bg="#1e1e1e", fg="#d4d4d4", relief="flat", borderwidth=1,
            font=("Segoe UI", 10), insertbackground="#d4d4d4"
        )
        text_widget.pack(expand=True, fill="both", padx=15, pady=15)
        
        # Insert the content and make it read-only
        text_widget.insert(tk.END, guide_content)
        text_widget.config(state="disabled")

        help_win.transient(self)
        help_win.grab_set()    

    def _save_log(self):
        """Save the current log contents to a file."""
        try:
            from tkinter import filedialog
            # Get current timestamp for default filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"nand_fix_log_{timestamp}.txt"
            
            # Open save dialog - use initialfile instead of initialvalue
            file_path = filedialog.asksaveasfilename(
                title="保存日志文件",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
                initialfile=default_filename
            )
            
            if file_path:
                # Get all text from the log widget
                log_content = self.log_widget.get("1.0", tk.END)
                
                # Write to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"NAND Fix Pro v{self.version} 中文版 - 日志导出\n")
                    f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*50 + "\n\n")
                    f.write(log_content)
                
                self._log(f"SUCCESS: Log saved to {file_path}")
                
        except Exception as e:
            self._log(f"ERROR: Failed to save log file. {e}")   


    def _clear_log(self):
        """Clear all content from the log widget."""
        try:
            self.log_widget.config(state="normal")
            self.log_widget.delete("1.0", tk.END)
            self.log_widget.config(state="disabled")
            self._log("Log cleared")
        except Exception as e:
            self._log(f"ERROR: Failed to clear log. {e}") 


    def _reset_application_state(self):
        """将应用程序重置为初始状态以便新的运行。"""
        dialog = CustomDialog(self, title="确认重置",
                            message="您确定要重置应用程序吗？\n\n这将清除日志，重置整个工作流程状态，并删除所有临时文件。",
                            buttons="yesno")
        if not dialog.result:
            self._log("--- 用户取消了重置。")
            return

        # 1. Delete temporary files/folders created by NANDFixPro
        deleted_items = []

        # Delete prod.keys and PRODINFO files
        try:
            keys_path = self.paths['keys'].get()
            if keys_path and os.path.exists(keys_path):
                os.remove(keys_path)
                deleted_items.append("prod.keys")
        except Exception as e:
            self._log(f"WARNING: Could not delete prod.keys: {e}")

        try:
            prodinfo_path = self.paths['prodinfo'].get()
            if prodinfo_path and os.path.exists(prodinfo_path):
                os.remove(prodinfo_path)
                deleted_items.append("PRODINFO")
        except Exception as e:
            self._log(f"WARNING: Could not delete PRODINFO: {e}")

        # Delete all switch_gui_* temp folders
        if self.paths['temp_directory'].get():
            temp_base = self.paths['temp_directory'].get()
            try:
                import shutil
                import glob
                # Find all switch_gui_* folders in the temp directory
                temp_folders = glob.glob(os.path.join(temp_base, "switch_gui_*"))
                deleted_count = 0
                for folder in temp_folders:
                    try:
                        if os.path.isdir(folder):
                            shutil.rmtree(folder)
                            deleted_count += 1
                    except Exception as e:
                        self._log(f"WARNING: Could not delete temp folder {folder}: {e}")

                if deleted_count > 0:
                    deleted_items.append(f"{deleted_count} temp folder(s)")
            except Exception as e:
                self._log(f"WARNING: Error during temp folder cleanup: {e}")

        if deleted_items:
            self._log(f"INFO: Deleted {', '.join(deleted_items)}")

        # 2. Reset the master state dictionary
        self.button_states = {
            "get_keys": "active",
            "level1": "disabled",
            "level2": "disabled",
            "level3": "disabled",
            "copy_boot": "disabled",
            "advanced_user": "disabled"
        }

        # 3. Clear the temporary keys, PRODINFO, and firmware paths from the config
        self.paths["keys"].set("")
        self.paths["prodinfo"].set("")
        self.paths["firmware"].set("")
        self._save_config()

        # 4. Reset the donor PRODINFO flag
        self.donor_prodinfo_from_sd = False

        # 5. Reset console type override checkbox
        self.override_console_type.set(False)
        self.manual_console_type.set("")

        # 6. Re-enable PRODINFO browse button and disable menu

        # 7. Reset the last output directory variable
        self.last_output_dir = None

        # 8. Clear the log and update the UI
        self._clear_log()
        self._log("--- 应用程序已重置。准备进行新的操作。 ---")
        self._validate_paths_and_update_buttons()               

    def _auto_detect_paths(self):
        try: script_dir = Path(__file__).parent
        except NameError: script_dir = Path.cwd()
        
        osfmount_path = Path("C:/Program Files/OSFMount/OSFMount.com")
        if osfmount_path.is_file(): self.paths["osfmount"].set(str(osfmount_path.resolve()))
        
        default_paths = {
            "7z": script_dir / "lib" / "7z" / "7z.exe",
            "emmchaccgen": script_dir / "lib" / "EmmcHaccGen" / "EmmcHaccGen.exe",
            "nxnandmanager": script_dir / "lib" / "NxNandManager" / "NxNandManager.exe",
            "partitions_folder": script_dir / "lib" / "NAND",
        }
        for key, path in default_paths.items():
            if self.paths[key].get(): continue
            full_path = Path(path)
            if full_path.is_file() or full_path.is_dir():
                self.paths[key].set(str(full_path.resolve()))


    def _create_path_selector_row(self, parent, key, label_text, type):
        row = parent.grid_size()[1]
        ttk.Label(parent, text=label_text, font=(self.FONT_FAMILY, 10)).grid(row=row, column=0, sticky="w", padx=5, pady=6)
        
        path_label = ttk.Label(parent, textvariable=self.paths[key],
            relief="solid", anchor="w", padding=(8, 5), background="#3c3c3c", borderwidth=1,
            font=(self.FONT_FAMILY, 9)
        )
        path_label.grid(row=row, column=1, sticky="ew", padx=5, pady=6)
        
        browse_button = ttk.Button(parent, text="浏览...", command=lambda k=key, t=type: self._select_path(k, t), style="TButton")
        browse_button.grid(row=row, column=2, padx=5, pady=6)
        
        # NEW: Store reference to PRODINFO browse button
        if key == "prodinfo":
            self.prodinfo_browse_button = browse_button

    def _reset_prodinfo_browse_button(self):
        """Re-enable the PRODINFO browse button and clear the path."""
        if self.prodinfo_browse_button:
            self.prodinfo_browse_button.config(state="normal")
        self.paths["prodinfo"].set("")
        self._save_config()
        self._validate_paths_and_update_buttons()        
    
    def _setup_tab_content(self, parent_frame, title, info_text, paths):
        parent_frame.columnconfigure(1, weight=1)
        
        # Row 0: Description
        desc_frame = ttk.LabelFrame(parent_frame, text=title, padding="15")
        desc_frame.grid(row=0, column=0, columnspan=3, pady=(5, 15), sticky="ew")
        ttk.Label(desc_frame, text=info_text, wraplength=650, justify=tk.LEFT).pack(anchor="w")

        # Row 1: Input file/folder selectors
        input_frame = ttk.Frame(parent_frame)
        input_frame.grid(row=1, column=0, columnspan=3, sticky="ew")
        input_frame.columnconfigure(1, weight=1)

        for key, label, type in paths:
            self._create_path_selector_row(input_frame, key, label, type)

    def _create_standard_button_area(self, parent_frame, level_name, command, button_ref):
        """Creates a standardized button area at a fixed grid row."""
        # This frame will now always be placed in row 4 of its parent
        button_area_frame = ttk.Frame(parent_frame)
        button_area_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(20, 10))
        
        # Create the main button row inside this standardized area
        button_frame = self._create_main_button_row(button_area_frame, level_name, command, button_ref)
        button_frame.pack(pady=5)
        
        return button_area_frame       

    def _setup_level1_tab(self, parent_frame):
        info_text = ("直接修复Switch eMMC上损坏的SYSTEM分区。\n\n"
                     "• 适用于软件错误、更新失败或仅操作系统受影响的启动问题。\n"
                     "• 此过程会读取Switch自身的PRODINFO和SYSTEM分区来执行修复。\n"
                     "• 此方法保留用户数据，如存档和已安装的游戏。")
        paths = [
            ("firmware", "固件文件夹:", "folder"),
        ]
        self._setup_tab_content(parent_frame, "第1级: 说明", info_text, paths)

        # Row 2: Add a spacer to push the buttons to the bottom of the available area.
        spacer = ttk.Frame(parent_frame)
        spacer.grid(row=2, column=0, sticky="nsew")
        parent_frame.rowconfigure(2, weight=1)

        # Row 3: The empty placeholder frame for the 'Advanced Button'.
        # This frame has padding, which creates the vertical space needed for alignment.
        advanced_frame_placeholder = ttk.Frame(parent_frame)
        advanced_frame_placeholder.grid(row=3, column=0, columnspan=3, pady=20)

        # Add console type override checkbox
        override_checkbox = ttk.Checkbutton(
            advanced_frame_placeholder,
            text="Switch型号检测",
            variable=self.override_console_type,
            command=self._on_override_toggle,
            style="Dark.TCheckbutton"
        )
        override_checkbox.pack(anchor="center")

        # Row 4: The main button area, now in a fixed position.
        self._create_standard_button_area(parent_frame, "Level 1", 
                                          lambda: self._start_threaded_process("Level 1"), 
                                          "start_level1_button")
        self._update_button_colors()

    def _setup_level2_tab(self, parent_frame):
        info_text = ("使用'lib/NAND'文件夹中的干净分区重建NAND。\n\n"
                     "• 当多个分区损坏但PRODINFO仍然可读时使用此选项。\n"
                     "• 此过程会读取Switch的PRODINFO，然后将干净的分区刷写到现有分区上。\n"
                     "• 此过程将擦除所有用户数据。")
        paths = [
            ("firmware", "固件文件夹:", "folder"),
        ]
        self._setup_tab_content(parent_frame, "第2级: 说明", info_text, paths)

        # Row 2: Add a spacer.
        spacer = ttk.Frame(parent_frame)
        spacer.grid(row=2, column=0, sticky="nsew")
        parent_frame.rowconfigure(2, weight=1)

        # Row 3: The frame containing the actual Advanced Button.
        advanced_frame = ttk.Frame(parent_frame)
        advanced_frame.grid(row=3, column=0, columnspan=3, pady=20)
        advanced_button = ttk.Button(advanced_frame, text="高级: 仅修复USER分区",
                                     command=self._start_user_fix_threaded, style="Disabled.TButton", state="disabled")
        advanced_button.pack(ipady=5, ipadx=15)
        self.advanced_user_button = advanced_button

        # Add console type override checkbox below the advanced button
        override_checkbox = ttk.Checkbutton(
            advanced_frame,
            text="Switch型号检测",
            variable=self.override_console_type,
            command=self._on_override_toggle,
            style="Dark.TCheckbutton"
        )
        override_checkbox.pack(anchor="center", pady=(15, 0))

        # Row 4: The main button area, in the same fixed position.
        self._create_standard_button_area(parent_frame, "Level 2", 
                                          lambda: self._start_threaded_process("Level 2"), 
                                          "start_level2_button")
        self._update_button_colors()

    def _setup_level3_tab(self, parent_frame):
        info_text = ("适用于包括PRODINFO在内的NAND完全损坏情况。这是最后手段。\n\n"
                     "• 使用PRODINFO文件和干净的模板重建完整的NAND镜像。\n"
                     "• 脚本会自动检测eMMC大小（32/64GB）以使用正确的NAND骨架。\n"
                     "• 将您的Switch连接到'eMMC RAW GPP'模式(关闭只读)并点击开始。")
        paths = [
            ("firmware", "固件文件夹:", "folder"),
            ("prodinfo", "PRODINFO:", "file"),
        ]
        self._setup_tab_content(parent_frame, "第3级: 说明", info_text, paths)

        # Row 2: Add a spacer.
        spacer = ttk.Frame(parent_frame)
        spacer.grid(row=2, column=0, sticky="nsew")
        parent_frame.rowconfigure(2, weight=1)

        # Row 3: The empty placeholder frame for the 'Advanced Button'.
        advanced_frame_placeholder = ttk.Frame(parent_frame)
        advanced_frame_placeholder.grid(row=3, column=0, columnspan=3, pady=20)
        
        # Row 4: The main button area, in the same fixed position.
        self._create_standard_button_area(parent_frame, "Level 3", 
                                          self._start_level3_threaded, 
                                          "start_level3_button")
        self._update_button_colors()
        

    def _start_user_fix_threaded(self):
        """Starts the targeted USER partition fix in a new thread."""
        self._disable_buttons()
        thread = threading.Thread(target=self._run_user_fix_process)
        thread.daemon = True
        thread.start()

    def _run_user_fix_process(self):
        """Performs a targeted fix of the USER partition only."""
        self._log("\n--- 开始高级操作: 仅修复USER分区 ---")
        temp_dir_obj = None  # To hold the TemporaryDirectory object if created
        try:
            pythoncom.CoInitialize()
            
            # Use a temporary directory for the operation
            if self.paths['temp_directory'].get():
                temp_base = self.paths['temp_directory'].get()
                temp_dir_name = f"switch_gui_user_fix_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                temp_dir = os.path.join(temp_base, temp_dir_name)
                os.makedirs(temp_dir, exist_ok=True)
            else:
                temp_dir_obj = tempfile.TemporaryDirectory(prefix="switch_gui_user_fix_")
                temp_dir = temp_dir_obj.name
            
            self._log(f"INFO: Created temporary directory at: {temp_dir}")
            
            # STEP 1: Detect eMMC with WMI
            self._log("\n[STEP 1/4] Please connect Switch in Hekate eMMC RAW GPP mode (Read-Only OFF).")
            self._log("--- Detecting target eMMC...")
            potential_drives = self._detect_switch_drives_wmi()
            if not potential_drives:
                CustomDialog(self, title="Error", message="No potential Switch eMMC drives found.")
                return

            if len(potential_drives) > 1:
                CustomDialog(self, title="Multiple Drives Found", message="Found multiple drives that could be a Switch eMMC. Please disconnect other USB drives.")
                return
            
            target_drive = potential_drives[0]
            drive_path = target_drive['path']
            
            # STEP 2: Confirm with the user
            msg = (f"Found target eMMC:\n\nPath: {drive_path}\nSize: {target_drive['size']}\nModel: {target_drive['model']}\n\n"
                   "This procedure will alter and fix the USER partition only. All user data on this partition will be erased.\n\n"
                   "Are you sure you want to proceed?")
            
            dialog = CustomDialog(self, title="Confirm USER Partition Fix", message=msg, buttons="yesno")
            if not dialog.result:
                self._log("--- User cancelled the operation.")
                return

            self._log(f"--- SUCCESS: User confirmed eMMC at {drive_path}")

            # STEP 3: Extract the correct USER partition
            self._log("\n[STEP 2/4] Preparing donor USER partition...")
            try:
                script_dir = Path(__file__).parent
            except NameError:
                script_dir = Path.cwd()
            partitions_folder = script_dir / "lib" / "NAND"
            
            target_size_gb = target_drive['size_gb']
            user_archive = "USER-64.7z" if target_size_gb > 40 else "USER-32.7z"
            
            cmd = [self.paths['7z'].get(), 'x', str(partitions_folder / user_archive), f'-o{temp_dir}', '-bsp1', '-y']
            if self._run_command_with_progress(cmd, "Extracting USER partition")[0] != 0:
                self._log("ERROR: Failed to extract USER partition.")
                return
                
            # STEP 4: Flash the USER partition
            self._log("\n[STEP 3/4] Flashing first 100MB of USER partition to eMMC...")
            nx_exe = self.paths['nxnandmanager'].get()
            keyset_path = self.paths['keys'].get()
            user_dec_path = Path(temp_dir) / "USER.dec"

            if not user_dec_path.exists():
                self._log("ERROR: Extracted USER.dec not found.")
                return

            flash_cmd = [nx_exe, '-i', str(user_dec_path), '-o', drive_path, '-part=USER', '-e', '-keyset', keyset_path, 'FORCE']
            
            # --- CHANGED: Use the optimized 100MB flash function ---
            if self._run_and_interrupt_flash(flash_cmd, "USER", 100) != 0:
                self._log("ERROR: Failed to flash USER partition to eMMC.")
                return
            
            self._log("\n[STEP 4/4] Process Complete!")
            self._log("SUCCESS: The USER partition has been replaced.")
            self._log("--- ADVANCED USER FIX FINISHED ---")

            CustomDialog(self, title="Process Complete", 
                message="The USER partition was successfully fixed.\n\n" +
                        "All previous user data has been erased.")

        except Exception as e:
            self._log(f"An unexpected critical error occurred: {e}\n{traceback.format_exc()}")
            self._log("\nINFO: Process finished with an error.")
        finally:
            # Clean up the temporary directory
            if temp_dir_obj:
                temp_dir_obj.cleanup()
            elif 'temp_dir' in locals() and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                self._log(f"INFO: Cleaned up temporary directory: {temp_dir}")

            self._re_enable_buttons()    

    def _get_keys_from_sd(self):
        """Detect SD card and copy prod.keys to temp directory. Detects and imports donor PRODINFO ONLY when on Level 3 tab."""
        try:
            sd_drive = self._detect_switch_sd_card_wmi()
            if not sd_drive:
                # Try manual selection as fallback
                sd_drive = self._manual_select_sd_card()
                if not sd_drive:
                    return

            # Check which tab is currently active
            current_tab = self.tab_control.select()
            level3_tab_id = self.tab_control.tabs()[2]  # Level 3 is the third tab (index 2)
            is_level3 = (current_tab == level3_tab_id)

            # Perform all validation checks
            prod_keys_path = sd_drive / "switch" / "prod.keys"
            prod_keys_found = prod_keys_path.exists()

            restore_path = find_emmc_backup_folder(sd_drive)
            backup_folder_found = restore_path is not None

            # Check for PRODINFO only if on Level 3 tab (since it's only relevant for Level 3)
            donor_prodinfo_path = None
            prodinfo_found = False

            if is_level3:
                possible_prodinfo_paths = [
                    sd_drive / "switch" / "generated_prodinfo_from_donor.bin",
                    sd_drive / "switch" / "PRODINFO",
                    sd_drive / "switch" / "PRODINFO.bin",
                    sd_drive / "PRODINFO",
                    sd_drive / "PRODINFO.bin"
                ]

                for path in possible_prodinfo_paths:
                    if path.exists():
                        try:
                            with open(path, 'rb') as f:
                                if f.read(4) == b'CAL0':
                                    donor_prodinfo_path = path
                                    break
                        except Exception as e:
                            self._log(f"WARNING: Could not validate {path.name}: {e}")
                            continue

                prodinfo_found = donor_prodinfo_path is not None

            # Build validation status message
            check_mark = "✓"
            cross_mark = "✗"

            status_message = "SD Card Validation:\n\n"
            status_message += f"  {check_mark if prod_keys_found else cross_mark}  prod.keys (MANDATORY)\n"
            status_message += f"  {check_mark if backup_folder_found else cross_mark}  backup/[emmcID]/restore folder (MANDATORY)\n"

            # Only show PRODINFO status if on Level 3 tab
            if is_level3:
                status_message += f"  {check_mark if prodinfo_found else cross_mark}  PRODINFO (Optional for Level 3)\n\n"
            else:
                status_message += "\n"

            # Check if mandatory items are present
            if not prod_keys_found or not backup_folder_found:
                status_message += "❌ Cannot proceed!\n\n"
                if not prod_keys_found:
                    status_message += f"Missing: prod.keys at {sd_drive / 'switch' / 'prod.keys'}\n"
                if not backup_folder_found:
                    status_message += f"Missing: backup/[alphanumeric]/restore folder\n"
                status_message += "\nPlease ensure you've created a NAND backup using Hekate and backed up your keys."

                CustomDialog(self, title="Validation Failed", message=status_message)
                return
            
            # Save keys to temp directory
            if self.paths['temp_directory'].get():
                temp_base = self.paths['temp_directory'].get()
            else:
                temp_base = tempfile.gettempdir()
            
            keys_temp_path = Path(temp_base) / "prod.keys"
            shutil.copy2(prod_keys_path, keys_temp_path)
            
            # Auto-populate the keys path
            self.paths["keys"].set(str(keys_temp_path))

            # Process PRODINFO only if found during validation (only happens on Level 3 tab)
            if donor_prodinfo_path and is_level3:
                # Copy donor PRODINFO to temp directory
                prodinfo_temp_path = Path(temp_base) / "PRODINFO"
                shutil.copy2(donor_prodinfo_path, prodinfo_temp_path)

                # Auto-populate the PRODINFO path
                self.paths["prodinfo"].set(str(prodinfo_temp_path))

                # MODIFIED: Set the flag to indicate this PRODINFO came from SD
                self.donor_prodinfo_from_sd = True

                # Disable the PRODINFO browse button if it exists
                if self.prodinfo_browse_button:
                    self.prodinfo_browse_button.config(state="disabled")

                self._log(f"SUCCESS: Donor PRODINFO imported from SD card: {donor_prodinfo_path.name}")

                # Show popup asking if user wants to edit the PRODINFO
                dialog = CustomDialog(self, title="Donor PRODINFO Detected",
                                    message=f"Found donor PRODINFO file: {donor_prodinfo_path.name}\n\nWould you like to edit it (serial, colors, WiFi region) before using in Level 3?",
                                    buttons="yesno")

                if dialog.result:
                    # User wants to edit - open editor immediately after this function completes
                    self.after(100, self._open_prodinfo_editor)  # Delay to ensure dialog cleanup
            
            
            self._save_config()
            self._log(f"SUCCESS: Keys imported from SD card to {keys_temp_path}")
            
            # Update button states
            self.button_states["get_keys"] = "completed"
            
            # Now validate and update all buttons
            self._validate_paths_and_update_buttons()
            
            # Create appropriate success message
            if prodinfo_found and is_level3:
                message = ("Keys and donor PRODINFO obtained!\n\n"
                        "Both prod.keys and donor PRODINFO were found and imported.\n\n"
                        "Please right-click the SD card drive in Windows Explorer and select 'Eject', "
                        "then connect your Switch in eMMC RAW GPP mode.")
            else:
                message = ("Keys obtained!\n\n"
                        f"prod.keys was imported successfully.\n\n"
                        "Please right-click the SD card drive in Windows Explorer and select 'Eject', "
                        "then connect your Switch in eMMC RAW GPP mode.")

            CustomDialog(self, title="Import Complete", message=message)
            
        except Exception as e:
            self._log(f"ERROR: Failed to import from SD card. {e}")
            CustomDialog(self, title="Import Failed", message=f"Failed to import from SD card:\n\n{e}")

    def _copy_boot_files_to_sd(self):
        """Copy BOOT0 and BOOT1 files to the SD card and clean up the temp folder."""
        try:
            # --- FIX: Check for the specific output directory ---
            if not self.last_output_dir or not Path(self.last_output_dir).exists():
                CustomDialog(self, title="Files Not Found", 
                             message="Could not find the output folder from a previous run.\n\nPlease complete a repair process first.")
                return

            output_path = Path(self.last_output_dir)
            boot0_path = output_path / "BOOT0"
            boot1_path = output_path / "BOOT1"
            
            if not (boot0_path.exists() and boot1_path.exists()):
                CustomDialog(self, title="BOOT Files Not Found", 
                             message=f"BOOT0/BOOT1 not found in the output folder:\n{output_path}\n\nPlease complete a repair process first.")
                return
            
            # Detect SD card
            sd_drive = self._detect_switch_sd_card_wmi()
            if not sd_drive:
                # Try manual selection as fallback
                sd_drive = self._manual_select_sd_card()
                if not sd_drive:
                    return
            
            # Find restore folder
            restore_path = find_emmc_backup_folder(sd_drive)
            if not restore_path:
                CustomDialog(self, title="Backup Folder Not Found", 
                             message="Could not find backup/[emmcID]/restore folder on SD card.\n\nPlease ensure you've created a NAND backup using Hekate.")
                return
            
            # Confirm with user
            msg = (f"Copy BOOT files to SD card?\n\n"
                   f"From: {output_path}\n"
                   f"To:   {restore_path}\n\n"
                   f"This will overwrite any existing BOOT0/BOOT1 files.")
            
            dialog = CustomDialog(self, title="Confirm Copy", message=msg, buttons="yesno")
            if not dialog.result:
                return
            
            # Copy files
            shutil.copy2(boot0_path, restore_path / "BOOT0")
            shutil.copy2(boot1_path, restore_path / "BOOT1")

            self._log(f"SUCCESS: BOOT files copied to {restore_path}")

            # --- FIX: Clean up the entire temporary directory ---
            if safe_remove_directory(output_path):
                self._log(f"INFO: Cleaned up temporary directory: {output_path}")
            self.last_output_dir = None # Reset the path after cleanup

            # Delete prod.keys and PRODINFO files after successful completion
            try:
                keys_path = self.paths['keys'].get()
                if keys_path and os.path.exists(keys_path):
                    os.remove(keys_path)
            except Exception as e:
                pass  # Silent cleanup

            try:
                prodinfo_path = self.paths['prodinfo'].get()
                if prodinfo_path and os.path.exists(prodinfo_path):
                    os.remove(prodinfo_path)
            except Exception as e:
                pass  # Silent cleanup

            CustomDialog(self, title="Files Copied",
                         message=f"BOOT0 and BOOT1 successfully copied to:\n{restore_path}\n\nPlease manually eject the SD card. You can now restore them using Hekate.")

            # Update button state
            self.button_states["copy_boot"] = "completed"
            self._update_button_colors()
            
        except Exception as e:
            self._log(f"ERROR: Failed to copy BOOT files to SD card. {e}")
            CustomDialog(self, title="Copy Failed", message=f"Failed to copy BOOT files:\n\n{e}")        

    

    
    # --- THE REST OF YOUR LOGIC IS UNCHANGED ---
    
    def _selective_copy_system_contents(self, source_system_path, drive_letter):
        """
        Selectively copy SYSTEM contents, preserving existing folders like savemeta
        but replacing 'registered' and 'save' folders entirely.
        """
        try:
            self._log("--- Updating SYSTEM partition...")

            contents_dest = drive_letter / "Contents"
            save_dest = drive_letter / "save"
            
            # Process Contents folder with subfolder-level merging
            for source_item in source_system_path.iterdir():
                dest_item = drive_letter / source_item.name
                
                if source_item.name == "Contents":
                    # Handle Contents folder with subfolder-level merging
                    contents_dest.mkdir(exist_ok=True)
                    
                    # Remove ONLY the registered folder if it exists
                    registered_dest = contents_dest / "registered"
                    if registered_dest.exists():
                        self._log("--- Removing existing registered folder...")
                        if not safe_remove_directory(registered_dest):
                            self._log("ERROR: Could not remove existing registered folder")
                            return False
                    
                    # Copy each item from source Contents individually
                    source_contents = source_item
                    for contents_subitem in source_contents.iterdir():
                        dest_subitem = contents_dest / contents_subitem.name
                        
                        if contents_subitem.name == "registered":
                            # Copy the new registered folder
                            if contents_subitem.is_dir():
                                shutil.copytree(contents_subitem, dest_subitem)
                            else:
                                shutil.copy2(contents_subitem, dest_subitem)
                        
                        elif not dest_subitem.exists():
                            # Copy new items (like placehld) that don't exist
                            if contents_subitem.is_dir():
                                shutil.copytree(contents_subitem, dest_subitem)
                            else:
                                shutil.copy2(contents_subitem, dest_subitem)
                
                elif source_item.name == "save":
                    # Handle save folder - ALWAYS replace entirely
                    if save_dest.exists():
                        self._log("--- Removing existing save folder...")
                        if not safe_remove_directory(save_dest):
                            self._log("ERROR: Could not remove existing save folder")
                            return False
                    
                    # Copy the new save folder
                    if source_item.is_dir():
                        shutil.copytree(source_item, save_dest)
                    else:
                        shutil.copy2(source_item, save_dest)
                
                else:
                    # Handle other top-level items
                    if not dest_item.exists():
                        if source_item.is_dir():
                            shutil.copytree(source_item, dest_item)
                        else:
                            shutil.copy2(source_item, dest_item)
            
            self._log("--- SYSTEM partition updated successfully")
            return True
            
        except Exception as e:
            self._log(f"ERROR: Failed to selectively copy SYSTEM contents. Error: {e}")
            import traceback
            self._log(traceback.format_exc())
            return False
            
    def _get_donor_nand_path(self, target_size_gb, temp_dir):
        """
        Automatically detect and extract the appropriate donor NAND based on eMMC size.
        Returns the path to the extracted donor NAND image.
        """
        try:
            script_dir = Path(__file__).parent
        except NameError:
            script_dir = Path.cwd()
        
        nand_lib_dir = script_dir / "lib" / "NAND"
        
        if target_size_gb > 40:
            donor_archive, donor_bin_name, size = (nand_lib_dir / "donor64.7z", "rawnand64.bin", "64GB")
        else:
            donor_archive, donor_bin_name, size = (nand_lib_dir / "donor32.7z", "rawnand32.bin", "32GB")
        self._log(f"--- Target: {size} eMMC, using {donor_archive.name}")
        
        if not donor_archive.is_file():
            self._log(f"ERROR: Donor NAND archive not found: {donor_archive}")
            return None
        
        extract_dir = Path(temp_dir) / "donor_extract"
        extract_dir.mkdir(exist_ok=True)
        
        # --- MODIFIED FOR V1.0.3: Progress Bar ---
        extract_cmd = [self.paths['7z'].get(), 'x', str(donor_archive), f'-o{extract_dir}', '-bsp1', '-y']
        if self._run_command_with_progress(extract_cmd, f"Extracting {size} donor NAND")[0] != 0:
            self._log("ERROR: Failed to extract donor NAND archive.")
            return None
        
        donor_nand_path = extract_dir / donor_bin_name
        if not donor_nand_path.is_file():
            self._log(f"ERROR: Expected donor NAND file not found: {donor_nand_path}")
            return None
        
        self._log(f"--- SUCCESS: Donor NAND extracted to {donor_nand_path}")
        return donor_nand_path      
    
    def _start_level3_threaded(self):
        self._disable_buttons()
        thread = threading.Thread(target=self._start_level3_process); 
        thread.daemon = True; 
        thread.start()

    def _disable_buttons(self):
        for btn in [self.start_level1_button, self.start_level2_button, self.start_level3_button]:
            if btn: btn.config(state="disabled")
        self._disable_prodinfo_menu()

    def _re_enable_buttons(self):
        # Re-enabling is now handled by the validation function
        self._validate_paths_and_update_buttons()
        # Re-enable PRODINFO menu if appropriate
        if self._is_path_valid("prodinfo"):
            self._enable_prodinfo_menu()

    def _on_override_toggle(self):
        """Handle console type override checkbox toggle"""
        if self.override_console_type.get():
            # User is enabling override - show the dialog
            dialog = ConsoleTypeDialog(self, self.manual_console_type.get())

            if dialog.result:
                # User clicked OK - save the selection
                self.manual_console_type.set(dialog.result)
                self._log(f"INFO: Console type override enabled - Using: {dialog.result}")
            else:
                # User clicked Cancel - uncheck the box and reset
                self.override_console_type.set(False)
                self.manual_console_type.set("")
        else:
            # User is disabling override - reset the selection
            self.manual_console_type.set("")
            self._log("INFO: Console type override disabled - Using automatic detection")

    def _on_closing(self):
        """Handle application closing - clean up temp directory and temporary files."""
        try:
            # Clean up prod.keys and PRODINFO files
            try:
                keys_path = self.paths['keys'].get()
                if keys_path and os.path.exists(keys_path):
                    os.remove(keys_path)
            except Exception as e:
                pass  # Silent cleanup

            try:
                prodinfo_path = self.paths['prodinfo'].get()
                if prodinfo_path and os.path.exists(prodinfo_path):
                    os.remove(prodinfo_path)
            except Exception as e:
                pass  # Silent cleanup

            # Clean up the last temp directory if it exists and wasn't copied to SD
            if hasattr(self, 'last_output_dir') and self.last_output_dir and os.path.exists(self.last_output_dir):
                self._log(f"\nINFO: Cleaning up temporary directory on exit: {self.last_output_dir}")
                shutil.rmtree(self.last_output_dir)
                self._log("INFO: Cleanup complete.")
        except Exception as e:
            # Don't block closing if cleanup fails
            print(f"Warning: Could not clean up temp directory on exit: {e}")
        finally:
            self.destroy()
            
    def _start_level3_process(self):
        self._log("--- Starting Level 3 Complete Recovery Process ---")
        temp_dir = None
        try:
            pythoncom.CoInitialize() # <--- ADD THIS LINE
            # Use custom temp directory if set
            if self.paths['temp_directory'].get():
                temp_base = self.paths['temp_directory'].get()
                temp_dir_name = f"switch_gui_level3_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                temp_dir = os.path.join(temp_base, temp_dir_name)
                os.makedirs(temp_dir, exist_ok=True)
                self._log(f"INFO: Using custom temporary directory at: {temp_dir}")
            else:
                # CHANGED: Don't use context manager - create temp dir manually
                temp_dir_name = f"switch_gui_level3_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                temp_dir = os.path.join(tempfile.gettempdir(), temp_dir_name)
                os.makedirs(temp_dir, exist_ok=True)
                self._log(f"INFO: Created temporary directory at: {temp_dir}")

            # Run the process
            self._run_level3_process(temp_dir)

            # --- THIS IS THE FIX ---
            # Save the successful output path for the copy button to use
            self.last_output_dir = temp_dir

            self._log(f"INFO: BOOT files saved to: {temp_dir}")
            self._log(f"INFO: Temp directory will be cleaned after copying BOOT files to SD.")

        except Exception as e:
            self._log(f"An unexpected critical error occurred: {e}\n{traceback.format_exc()}")
            self._log(f"\nINFO: Level 3 process finished with an error.")
            # Clean up temp directory if process failed
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    self._log(f"INFO: Cleaned up temporary directory after error: {temp_dir}")
                except Exception as cleanup_error:
                    self._log(f"WARNING: Could not clean up temp directory: {cleanup_error}")
        finally:
            self._re_enable_buttons()

    def _run_level3_process(self, temp_dir):
        self._log("\n--- WARNING ---")
        self._log("Level 3 will completely overwrite your Switch's eMMC with a reconstructed NAND.")
        self._log("This is irreversible. Ensure you have backups and a stable connection.")

        # ADD THIS LINE:
        if not self._check_disk_space(60): 
            return
        
        self._log("\n[STEP 1/8] Please connect your Switch in Hekate's eMMC RAW GPP mode (Read-Only OFF).")
        self._log("--- Detecting target eMMC...")
        
        # Detect target eMMC
        potential_drives = self._detect_switch_drives_wmi()
        if not potential_drives:
            CustomDialog(self, title="Error", message="No potential Switch eMMC drives found. Please ensure it is connected properly.")
            return

        if len(potential_drives) > 1:
            CustomDialog(self, title="Multiple Drives Found", message="Found multiple drives that could be a Switch eMMC. "
                                                                    "For safety, please disconnect other USB drives of 32GB or 64GB and try again.")
            return
        
        target_drive = potential_drives[0]
        target_size_gb = target_drive['size_gb']
        target_path = target_drive['path']
        
        # Confirm with user
        msg = (f"Found target eMMC:\n\nPath: {target_path}\nSize: {target_drive['size']}\nModel: {target_drive['model']}\n\n"
               "WARNING: ALL DATA ON THIS DRIVE WILL BE PERMANENTLY ERASED.\n\n"
               "This will perform a complete Level 3 recovery. Continue?")
        
        dialog = CustomDialog(self, title="Confirm Level 3 Recovery", message=msg, buttons="yesno")
        if not dialog.result:
            self._log("--- User cancelled Level 3 recovery.")
            return
        
        self._log(f"SUCCESS: User confirmed target eMMC at {target_path} ({target_drive['size']})")
        
        self._log(f"\n[STEP 2/8] Preparing donor NAND skeleton...")

        # Automatically detect and extract donor NAND skeleton based on target eMMC size
        donor_nand_path = self._get_donor_nand_path(target_size_gb, temp_dir)
        if not donor_nand_path:
            self._log("ERROR: Failed to prepare donor NAND skeleton.")
            return

        # Copy donor skeleton to working directory
        working_nand = Path(temp_dir) / "working_nand.img"
        self._log(f"--- Copying donor NAND skeleton to working directory...")
        # --- MODIFIED FOR V1.0.2: Progress Bar ---
        if not self._copy_with_progress(donor_nand_path, working_nand, "Copying NAND skeleton"):
            return
        self._log(f"--- SUCCESS: Working NAND skeleton ready at {working_nand}")
        
        self._log(f"\n[STEP 3/8] Validating donor PRODINFO...")
        prodinfo_path = Path(self.paths['prodinfo'].get())
        if not prodinfo_path.is_file():
            self._log("ERROR: Donor PRODINFO file not found.")
            return
        
        # Validate PRODINFO
        with open(prodinfo_path, 'rb') as f:
            if f.read(4) != b'CAL0':
                error_msg = "The prodinfo is not correct, make sure it is decrypted!"
                self._log(f"ERROR: PRODINFO magic 'CAL0' not found. {error_msg}")
                CustomDialog(self, title="Invalid PRODINFO", message=error_msg)
                return
        
        # Read model from PRODINFO
        with open(prodinfo_path, 'rb') as f:
            f.seek(0x3740)
            product_model_id = int.from_bytes(f.read(4), byteorder='little')
        model_map = {1: "Erista", 3: "V2", 4: "Lite", 6: "OLED"}
        detected_model = model_map.get(product_model_id, "Unknown Mariko")
        self._log(f"SUCCESS: Detected model from PRODINFO: {detected_model}")
        
        self._log(f"\n[STEP 4/8] Generating boot files and system content...")
        emmchaccgen_out_dir = Path(temp_dir) / "emmchaccgen_out"
        emmchaccgen_out_dir.mkdir()
        keyset_path = self.paths['keys'].get()
        
        emmchaccgen_cmd = [self.paths['emmchaccgen'].get(), '--keys', keyset_path, '--fw', self.paths['firmware'].get()]
        if "Mariko" in detected_model or detected_model in ["V2", "Lite", "OLED"]:
            self._log("--- Mariko model detected, using --mariko flag (AutoRCM disabled by default).")
            emmchaccgen_cmd.append('--mariko')
        else:
            self._log("--- Erista model detected, adding --no-autorcm flag by default.")
            emmchaccgen_cmd.append('--no-autorcm')
        
        if self._run_command(emmchaccgen_cmd, cwd=str(emmchaccgen_out_dir))[0] != 0:
            self._log("ERROR: Failed to generate boot files with EmmcHaccGen.")
            return
        
        # Get EmmcHaccGen output folder
        try:
            versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
        except StopIteration:
            self._log("ERROR: No EmmcHaccGen output folder found.")
            return
        
        self._log(f"\n[STEP 5/8] Preparing all partition data from donor archives...")
        nx_exe = self.paths['nxnandmanager'].get()
        partitions_folder = Path(self.paths['partitions_folder'].get())
        
        # --- MODIFIED FOR V1.0.2: Progress Bar for all 7z extractions ---
        for part_info in [("SYSTEM", "SYSTEM.7z"), ("PRODINFOF", "PRODINFOF.7z"), ("SAFE", "SAFE.7z")]:
            part_name, archive_name = part_info
            cmd = [self.paths['7z'].get(), 'x', str(partitions_folder / archive_name), f'-o{temp_dir}', '-bsp1', '-y']
            if self._run_command_with_progress(cmd, f"Extracting {part_name}")[0] != 0:
                self._log(f"ERROR: Failed to extract donor {part_name} partition.")
                return

        user_archive = "USER-64.7z" if target_size_gb > 40 else "USER-32.7z"
        cmd = [self.paths['7z'].get(), 'x', str(partitions_folder / user_archive), f'-o{temp_dir}', '-bsp1', '-y']
        if self._run_command_with_progress(cmd, "Extracting USER")[0] != 0:
            self._log("ERROR: Failed to extract USER partition.")
            return

        system_dec_path = Path(temp_dir) / "SYSTEM.dec"
        
        # Mount and modify SYSTEM
        self._log("--- Mounting SYSTEM partition for modification...")
        osfmount_cmd = [self.paths['osfmount'].get(), '-a', '-t', 'file', '-f', str(system_dec_path), '-o', 'rw', '-m', '#:']
        return_code, output = self._run_command(osfmount_cmd)
        if return_code != 0: 
            self._log("ERROR: Failed to mount SYSTEM partition.")
            return
        
        match = re.search(r"([A-Z]:)", output)
        if not match: 
            self._log("ERROR: Could not determine drive letter.")
            return
        
        drive_letter_str = match.group(1)
        drive_letter = Path(drive_letter_str)
        self._log(f"--- SUCCESS: SYSTEM mounted to {drive_letter}")
        
        try:
            source_system_path = versioned_folder / "SYSTEM"
            
            # For Level 3, complete replacement of specific folders
            self._log("--- Modifying SYSTEM partition for Level 3...")
            
            # Replace Contents/registered completely
            registered_dest = drive_letter / "Contents" / "registered"
            if registered_dest.exists():
                self._log("--- Removing existing registered folder...")
                if not safe_remove_directory(registered_dest):
                    self._log("ERROR: Could not remove existing registered folder")
                    return False
            registered_source = source_system_path / "Contents" / "registered"
            if registered_source.exists():
                shutil.copytree(registered_source, registered_dest)
                self._log(f"--- SUCCESS: Replaced 'registered' folder with {len(list(registered_source.iterdir()))} items")
            
            # Replace save folder completely
            save_dest = drive_letter / "save"
            if save_dest.exists():
                self._log("--- Removing existing save folder...")
                if not safe_remove_directory(save_dest):
                    self._log("ERROR: Could not remove existing save folder")
                    return False
            save_source = source_system_path / "save"
            if save_source.exists():
                shutil.copytree(save_source, save_dest)
                save_files = list(save_source.iterdir())
                self._log(f"--- SUCCESS: Replaced 'save' folder with {len(save_files)} files")
                for save_file in save_files:
                    self._log(f"         - {save_file.name}")
            
            self._log("--- SYSTEM partition modification complete")
            
        except Exception as e:
            self._log(f"ERROR: Failed to modify SYSTEM partition. Error: {e}")
            return
        finally:
            self._log("--- Dismounting SYSTEM partition...")
            self._run_command([self.paths['osfmount'].get(), '-D', '-m', drive_letter_str])
        
        self._log(f"\n[STEP 6/8] Flashing all partitions to donor NAND skeleton...")
        
        partitions_to_flash = {
            "PRODINFO": prodinfo_path,
            "PRODINFOF": Path(temp_dir) / "PRODINFOF.dec",
            "SYSTEM": system_dec_path,
            "SAFE": Path(temp_dir) / "SAFE.dec",
            "USER": Path(temp_dir) / "USER.dec"
        }

        for part_name, part_path in partitions_to_flash.items():
            self._log(f"--- Flashing {part_name} to skeleton...")
            flash_cmd = [nx_exe, '-i', str(part_path), '-o', str(working_nand), f'-part={part_name}', '-e', '-keyset', keyset_path, 'FORCE']
            # Special handling for partial USER flash
            if part_name == "USER":
                if self._run_and_interrupt_flash(flash_cmd, "USER", 100) != 0:
                    self._log(f"ERROR: Failed to partially flash {part_name} to skeleton.")
                    return
            else:
                if self._run_command(flash_cmd)[0] != 0:
                    self._log(f"ERROR: Failed to flash {part_name} to skeleton.")
                    return
        
        # Flash BCPKG2 partitions (unencrypted)
        self._log("--- Flashing BCPKG2 partitions to skeleton...")
        bcpkg2_partitions = ["BCPKG2-1-Normal-Main", "BCPKG2-2-Normal-Sub", "BCPKG2-3-SafeMode-Main", "BCPKG2-4-SafeMode-Sub"]
        for part_name in bcpkg2_partitions:
            bcpkg2_file = versioned_folder / f"{part_name}.bin"
            if not bcpkg2_file.exists():
                self._log(f"ERROR: {bcpkg2_file.name} not found in EmmcHaccGen output.")
                return
            
            flash_cmd = [nx_exe, '-i', str(bcpkg2_file), '-o', str(working_nand), f'-part={part_name}', 'FORCE']
            if self._run_command(flash_cmd)[0] != 0:
                self._log(f"ERROR: Failed to flash {part_name} to skeleton.")
                return
        
        self._log("SUCCESS: All partitions flashed to donor NAND skeleton.")
        
        self._log(f"\n[STEP 7/8] Writing complete NAND image to target eMMC...")
        self._log("--- This may take a few minutes. Do not disconnect the Switch.")
        
        # Raw copy the complete filled skeleton to target eMMC
        if not self._raw_copy_nand_to_emmc(working_nand, target_path):
            self._log("ERROR: Failed to write NAND image to target eMMC.")
            return
        
        self._log(f"\n[STEP 8/8] Saving BOOT0 & BOOT1 to output folder...")

        shutil.copy(versioned_folder / "BOOT0.bin", Path(temp_dir) / "BOOT0")
        shutil.copy(versioned_folder / "BOOT1.bin", Path(temp_dir) / "BOOT1")
        self._log(f"SUCCESS: BOOT0 and BOOT1 saved to {temp_dir}")

        self._log(f"\n[STEP 8/8] Level 3 Recovery Complete!")
        self._log("IMPORTANT: Please flash BOOT0 and BOOT1 manually using Hekate for safety.")
        self._log("Your Switch should now boot with the reconstructed NAND.")
        self._log("\n--- LEVEL 3 COMPLETE RECOVERY FINISHED ---")

        # ADD THESE 3 LINES HERE:
        self.button_states["copy_boot"] = "active"
        self.button_states["level3"] = "completed"
        self._log(f"DEBUG: Setting copy_boot state to active after Level 3 completion")
        self._update_button_colors()
        # 强制更新界面以确保更改生效
        self.update_idletasks()
        
        CustomDialog(self, title="Level 3 Complete", 
                        message="Level 3 recovery completed successfully!\n\n" +
                                "Don't forget to flash BOOT0 and BOOT1 using Hekate.\n\n" +
                                "Your Switch should now boot normally.")
    
    def _raw_copy_nand_to_emmc(self, source_nand, target_drive):
        """Raw copy donor NAND image to target eMMC using optimized partial write of 4GB."""
        target_fd = None
        try:
            self._log(f"--- Opening source NAND image: {source_nand}")
            # --- MODIFIED FOR V1.0.2: Changed to 4GB ---
            copy_size = 4 * (1024**3)
            self._log(f"--- OPTIMIZATION: Writing only first 4GB (covers all essential partitions)")

            self._log(f"--- Opening target drive: {target_drive}")
            try:
                target_fd = os.open(target_drive, os.O_WRONLY | os.O_BINARY)
                self._log(f"--- Successfully opened target drive using os.open")
            except OSError as e:
                self._log(f"ERROR: Failed to open target drive: {e}")
                return False

            try:
                with open(source_nand, 'rb') as src:
                    bytes_copied = 0
                    chunk_size = 1024 * 1024  # 1MB chunks
                    self._log("--- Starting optimized raw write to eMMC (4GB target)...")

                    while bytes_copied < copy_size:
                        remaining = copy_size - bytes_copied
                        chunk = src.read(min(chunk_size, remaining))
                        if not chunk:
                            self._log("--- WARNING: Source file ended before reaching target copy size.")
                            break

                        try:
                            written = os.write(target_fd, chunk)
                            bytes_copied += written
                        except OSError as write_error:
                            self._log(f"ERROR: Write operation failed at {bytes_copied / (1024**3):.2f} GB: {write_error}")
                            raise

                        # --- MODIFIED FOR V1.0.2: Progress Bar ---
                        percent = int((bytes_copied / copy_size) * 100)
                        bar_length = 25
                        filled_length = int(bar_length * percent / 100)
                        bar = '█' * filled_length + '-' * (bar_length - filled_length)
                        progress_gb = bytes_copied / (1024**3)
                        total_gb = copy_size / (1024**3)
                        self._update_progress(f"Writing to eMMC: [{bar}] {percent}% ({progress_gb:.2f}/{total_gb:.2f} GB)")

            finally:
                # Always close the file descriptor safely
                if target_fd is not None:
                    try:
                        self._log("--- Flushing data to target drive...")
                        os.fsync(target_fd)
                    except OSError as fsync_error:
                        self._log(f"WARNING: fsync failed (this may be normal on some systems): {fsync_error}")

                    try:
                        os.close(target_fd)
                        self._log("--- Target drive closed.")
                    except OSError as close_error:
                        self._log(f"WARNING: Failed to close target drive cleanly: {close_error}")

            self._log(f"--- SUCCESS: Copied {bytes_copied / (1024**3):.2f} GB to target eMMC")
            self._log(f"--- All essential partitions written. USER partition is blank and will be initialized by Switch.")
            return True

        except PermissionError:
            self._log("ERROR: Permission denied. Please ensure the script is running as an Administrator.")
            CustomDialog(self, title="Permission Error",
                            message="Permission denied when trying to write to the drive. Please ensure the script is running with Administrator privileges.")
            return False
        except OSError as e:
            if e.errno == 9:  # Bad file descriptor
                self._log(f"ERROR: Bad file descriptor error. This may be due to:")
                self._log("1. USB connection was interrupted during write")
                self._log("2. Drive was disconnected or became unavailable")
                self._log("3. USB controller/driver compatibility issue")
                self._log("4. Windows blocked the operation")
                CustomDialog(self, title="USB Write Error",
                                message=f"Lost connection to the eMMC during write.\n\nPossible solutions:\n• Try a different USB port (preferably USB 2.0)\n• Use a different USB cable\n• Disable USB selective suspend in Windows power settings\n• Try on a different PC\n• Ensure Switch is in proper RCM mode with Hekate")
            elif e.errno == 22:  # Invalid argument
                self._log(f"ERROR: Cannot access physical drive {target_drive}. This may be due to:")
                self._log("1. Drive is mounted/in use by another process")
                self._log("2. Drive access is blocked by antivirus software")
                self._log("3. Insufficient permissions")
                self._log("4. Device not properly connected")
                CustomDialog(self, title="Drive Access Error",
                                message=f"Cannot access the physical drive.\n\nPossible solutions:\n• Ensure no other programs are using the drive\n• Temporarily disable antivirus\n• Run as Administrator\n• Try disconnecting and reconnecting the Switch")
            else:
                self._log(f"ERROR: OS error occurred: {e}")
            return False
        except Exception as e:
            self._log(f"ERROR: A critical error occurred during the raw copy: {e}")
            import traceback
            self._log(traceback.format_exc())
            CustomDialog(self, title="Write Error",
                            message=f"A critical error occurred while writing to the eMMC:\n\n{e}")
            return False

    def _setup_prodinfo_menu(self, menubar):
        """Setup PRODINFO menu item"""
        prodinfo_menu = tk.Menu(menubar, tearoff=0,
            background=self.BG_LIGHT, foreground=self.FG_COLOR,
            activebackground=self.ACCENT_COLOR, activeforeground=self.FG_COLOR,
            relief="flat", borderwidth=0
        )
        menubar.add_cascade(label="PRODINFO编辑器", menu=prodinfo_menu, state="disabled")
        prodinfo_menu.add_command(label="编辑PRODINFO文件", command=self._open_prodinfo_editor)
        
        # Store reference for enabling/disabling
        self.prodinfo_menu_cascade = menubar
        self.prodinfo_menu_index = menubar.index("end")
    
    def _open_prodinfo_editor(self):
        """Open PRODINFO editor dialog"""
        prodinfo_path = self.paths["prodinfo"].get()
        if not prodinfo_path or not Path(prodinfo_path).exists():
            CustomDialog(self, title="无PRODINFO", 
                        message="请先使用'从SD卡获取密钥'或在设置中手动选择PRODINFO文件。")
            return
        
        try:
            dialog = PRODINFOEditorDialog(self, prodinfo_path)
            self.wait_window(dialog)
            
            if hasattr(dialog, 'result') and dialog.result:
                self._log("SUCCESS: PRODINFO file has been updated with custom data")
            
        except Exception as e:
            self._log(f"ERROR: Failed to open PRODINFO editor: {e}")
            CustomDialog(self, title="编辑器错误", message=f"无法打开PRODINFO编辑器:\n{e}")

    def _enable_prodinfo_menu(self):
        """Enable PRODINFO menu after successful PRODINFO load"""
        try:
            if hasattr(self, 'prodinfo_menu_cascade') and hasattr(self, 'prodinfo_menu_index'):
                self.prodinfo_menu_cascade.entryconfig(self.prodinfo_menu_index, state="normal")
        except Exception as e:
            self._log(f"WARNING: Could not enable PRODINFO menu: {e}")

    def _disable_prodinfo_menu(self):
        """Disable PRODINFO menu during processing"""
        try:
            if hasattr(self, 'prodinfo_menu_cascade') and hasattr(self, 'prodinfo_menu_index'):
                self.prodinfo_menu_cascade.entryconfig(self.prodinfo_menu_index, state="disabled")
        except Exception as e:
            self._log(f"WARNING: Could not disable PRODINFO menu: {e}")    

    def _setup_settings_menu(self, menubar):
        settings_menu = tk.Menu(menubar, tearoff=0,
            background=self.BG_LIGHT, foreground=self.FG_COLOR,
            activebackground=self.ACCENT_COLOR, activeforeground=self.FG_COLOR,
            relief="flat", borderwidth=0
        )
        menubar.add_cascade(label="设置", menu=settings_menu)
        paths_to_show = {"7z": "7-Zip (7z.exe)...", "emmchaccgen": "EmmcHaccGen.exe...",
                            "nxnandmanager": "NxNandManager.exe...", "osfmount": "OSFMount.com...",
                            "partitions_folder": "分区文件夹 (NAND)...",
                            "temp_directory": "临时目录..."}
        for key, text in paths_to_show.items():
            file_type = "file" if ".exe" in text or ".com" in text else "folder"
            settings_menu.add_command(label=f"设置 {text}", command=lambda k=key, t=file_type: self._select_path(k, t))

    def _select_path(self, key, type):
        path = ""
        if type == "file":
            # Define specific file type filters for different selections
            file_filters = {
                "7z": [("7-Zip可执行文件", "7z.exe"), ("可执行文件", "*.exe"), ("所有文件", "*.*")],
                "osfmount": [("OSFMount命令", "OSFMount.com"), ("命令文件", "*.com"), ("所有文件", "*.*")],
                "nxnandmanager": [("NxNandManager可执行文件", "NxNandManager.exe"), ("可执行文件", "*.exe"), ("所有文件", "*.*")],
                "emmchaccgen": [("EmmcHaccGen文件", "*.exe *.ini"), ("可执行文件", "*.exe"), ("INI文件", "*.ini"), ("所有文件", "*.*")],
                "keys": [("密钥文件", "*.keys"), ("所有文件", "*.*")],
                "prodinfo": [("PRODINFO文件", "*.*")]
            }
            # Get the filter for the current selection key
            current_filter = file_filters.get(key)
            
            # 映射key到中文名
            key_names = {
                "7z": "7-Zip",
                "osfmount": "OSFMount",
                "nxnandmanager": "NxNandManager",
                "emmchaccgen": "EmmcHaccGen",
                "keys": "密钥",
                "prodinfo": "PRODINFO"
            }
            display_name = key_names.get(key, key.replace('_', ' ').title())
            
            path = filedialog.askopenfilename(
                title=f"选择{display_name}文件",
                filetypes=current_filter
            )

        elif type == "folder":
            # 映射key到中文名
            key_names = {
                "firmware": "固件",
                "partitions_folder": "分区",
                "temp_directory": "临时",
                "output_folder": "输出"
            }
            display_name = key_names.get(key, key.replace('_', ' ').title())
            path = filedialog.askdirectory(title=f"选择{display_name}文件夹")
        
        if path: 
            self.paths[key].set(os.path.normpath(path))
            self._save_config()
            self._validate_paths_and_update_buttons()

    def _log(self, message, end="\n"):
        # Check if log_widget exists before trying to use it
        if hasattr(self, 'log_widget') and self.log_widget:
            # --- MODIFIED FOR V1.0.2: Clean up progress bar before logging new line ---
            last_line = self.log_widget.get("end-2l", "end-1l")
            if last_line.startswith("--- Progress:"):
                self.log_widget.config(state="normal")
                self.log_widget.delete("end-2l", "end-1l")
                self.log_widget.config(state="disabled")

            self.log_widget.config(state="normal")
            self.log_widget.insert(tk.END, message + end)
            self.log_widget.see(tk.END)
            self.log_widget.config(state="disabled")
            self.update_idletasks()
        else:
            # Fall back to print if log widget not available yet
            print(message)

    def _run_command(self, command, cwd=None):
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, creationflags=subprocess.CREATE_NO_WINDOW, cwd=cwd,
                                        bufsize=1, universal_newlines=True)
            output = []
            for line in iter(process.stdout.readline, ''):
                clean_line = line.strip()
                if not clean_line: continue
                output.append(clean_line)
                self._log(clean_line)
            
            process.stdout.close()
            return_code = process.wait()
            return return_code, "\n".join(output)
        except Exception as e:
            self._log(f"FATAL ERROR: Failed to execute command. {e}")
            return -1, str(e)
    
    def _start_threaded_process(self, level):
        self._disable_buttons()
        thread = threading.Thread(target=self._start_process, args=(level,)); thread.daemon = True; thread.start()

    
    def _start_process(self, level):
        self._log(f"--- Starting {level} Process ---")
        temp_dir = None
        try:
            pythoncom.CoInitialize()

            if self.paths['temp_directory'].get():
                temp_base = self.paths['temp_directory'].get()
                temp_dir_name = f"switch_gui_{level.lower().replace(' ', '')}{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                temp_dir = os.path.join(temp_base, temp_dir_name)
                os.makedirs(temp_dir, exist_ok=True)
                self._log(f"INFO: Using custom temporary directory at: {temp_dir}")
            else:
                # CHANGED: Don't use context manager - create temp dir manually
                temp_dir_name = f"switch_gui_{level.lower().replace(' ', '')}{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                temp_dir = os.path.join(tempfile.gettempdir(), temp_dir_name)
                os.makedirs(temp_dir, exist_ok=True)
                self._log(f"INFO: Created temporary directory at: {temp_dir}")

            # Run the process
            if level == "Level 1":
                self._run_level1_process(temp_dir)
            elif level == "Level 2":
                self._run_level2_process(temp_dir)

            # --- THIS IS THE FIX ---
            # Save the successful output path for the copy button to use
            self.last_output_dir = temp_dir

            self._log(f"INFO: BOOT files saved to: {temp_dir}")
            self._log(f"INFO: Temp directory will be cleaned after copying BOOT files to SD.")

        except Exception as e:
            self._log(f"An unexpected critical error occurred: {e}\n{traceback.format_exc()}")
            self._log(f"\nINFO: {level} process finished with an error.")
            # Clean up temp directory if process failed
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    self._log(f"INFO: Cleaned up temporary directory after error: {temp_dir}")
                except Exception as cleanup_error:
                    self._log(f"WARNING: Could not clean up temp directory: {cleanup_error}")
        finally:
            self._re_enable_buttons()

    def _selective_copy_system_contents_level1(self, source_system_path, drive_letter):
        """
        Level 1: Delete only registered folder, then merge everything from EmmcHaccGen
        This overwrites matching files but preserves existing files that aren't in the source
        """
        try:
            self._log("--- Updating system partition...")
            
            # STEP 1: Delete ONLY the existing registered folder
            registered_dest = drive_letter / "Contents" / "registered"
            if registered_dest.exists():
                self._log("--- Removing existing registered folder...")
                if not safe_remove_directory(registered_dest):
                    self._log("ERROR: Could not remove existing registered folder")
                    return False
            
            # STEP 2: Recursively copy/merge everything from EmmcHaccGen
            # This overwrites matching files but leaves other existing files alone
            def merge_copy(src, dst):
                for item in src.iterdir():
                    src_item = item
                    dst_item = dst / item.name
                    
                    if src_item.is_dir():
                        dst_item.mkdir(exist_ok=True)
                        merge_copy(src_item, dst_item)  # Recurse into subdirectories
                    else:
                        shutil.copy2(src_item, dst_item)  # Overwrite file if exists
            
            self._log("--- Copying/merging all files from EmmcHaccGen SYSTEM output...")
            merge_copy(source_system_path, drive_letter)
            
            self._log("--- SUCCESS: System partition updated")
            return True
            
        except Exception as e:
            self._log(f"ERROR: Failed to update system partition. {e}")
            import traceback
            self._log(traceback.format_exc())
            return False
            
        except Exception as e:
            self._log(f"ERROR: Failed to update system partition. {e}")
            import traceback
            self._log(traceback.format_exc())
            return False

    # In class SwitchGuiApp:

    def _run_level1_process(self, temp_dir):
        self._log("\n--- WARNING ---")
        self._log("The Level 1 process will write directly to your Switch's eMMC.")

        if not self._check_disk_space(60):
            return
        
        self._log("\n[STEP 1/8] Please connect your Switch in Hekate's eMMC RAW GPP mode (Read-Only OFF).")
        self._log("--- Detecting target eMMC...")
        potential_drives = self._detect_switch_drives_wmi()
        if not potential_drives:
            CustomDialog(self, title="Error", message="No potential Switch eMMC drives found. Please ensure it is connected properly.")
            return

        if len(potential_drives) > 1:
            CustomDialog(self, title="Multiple Drives Found", message="Found multiple drives that could be a Switch eMMC. "
                                                                    "For safety, please disconnect other USB drives and try again.")
            return
        
        target_drive = potential_drives[0]
        drive_path = target_drive['path']
        
        # --- ADDED: Confirmation Pop-up for Level 1 ---
        msg = (f"Found target eMMC:\n\nPath: {drive_path}\nSize: {target_drive['size']}\nModel: {target_drive['model']}\n\n"
               "This will start the Level 1 System Restore process.\n"
               "User data like saves and games will be preserved.\n\nContinue?")
        
        dialog = CustomDialog(self, title="Confirm Level 1 Restore", message=msg, buttons="yesno")
        if not dialog.result:
            self._log("--- User cancelled Level 1 restore.")
            return
        # --- END OF ADDED CODE ---

        self._log(f"SUCCESS: User confirmed eMMC at {drive_path}")
        nx_exe = self.paths['nxnandmanager'].get()
        
        self._log("--- Dumping and decrypting PRODINFO from eMMC...")
        keyset_path = self.paths['keys'].get()
        prodinfo_path = Path(temp_dir) / "PRODINFO"
        dump_cmd = [nx_exe, '-i', drive_path, '-keyset', keyset_path, '-o', temp_dir, '-d', '-part=PRODINFO']
        
        if self._run_command(dump_cmd)[0] != 0 or not prodinfo_path.exists():
            self._log(f"ERROR: Failed to dump or decrypt PRODINFO from the eMMC. It may be corrupt.")
            CustomDialog(self, title="PRODINFO Error", message="PRODINFO is not found or damaged. Please use Level 2 or Level 3 instead.")
            return

        with open(prodinfo_path, 'rb') as f:
            if f.read(4) != b'CAL0':
                self._log(f"ERROR: The PRODINFO dumped from the eMMC is invalid or encrypted (magic is not CAL0).")
                CustomDialog(self, title="PRODINFO Error", message="PRODINFO is not found or damaged. Please use Level 2 or Level 3 instead.")
                return

        self._log("SUCCESS: PRODINFO is valid and decrypted.")

        self._log(f"\n[STEP 2/8] Reading PRODINFO file...")

        # Check if console type override is enabled
        if self.override_console_type.get() and self.manual_console_type.get():
            # Use manual override
            manual_selection = self.manual_console_type.get()
            self._log(f"INFO: Using manual console type override: {manual_selection}")
            detected_model = "Mariko" if "Mariko" in manual_selection else "Erista"

            # Still read PRODINFO to show what was detected for reference
            with open(prodinfo_path, 'rb') as f:
                f.seek(0x3740)
                model_bytes = f.read(4)
                product_model_id = int.from_bytes(model_bytes, byteorder='little')
            model_map = {1: "Erista", 3: "V2", 4: "Lite", 6: "OLED"}
            auto_detected = model_map.get(product_model_id, "Unknown Mariko")
            self._log(f"INFO: Auto-detected model from PRODINFO: {auto_detected} (ignored due to override)")
        else:
            # Use automatic detection
            with open(prodinfo_path, 'rb') as f:
                f.seek(0x3740)
                model_bytes = f.read(4)
                product_model_id = int.from_bytes(model_bytes, byteorder='little')
            model_map = {1: "Erista", 3: "V2", 4: "Lite", 6: "OLED"}
            detected_model = model_map.get(product_model_id, "Unknown Mariko")
            self._log(f"SUCCESS: Detected model: {detected_model}")

        self._log(f"\n[STEP 3/8] Generating boot files...")
        emmchaccgen_out_dir = Path(temp_dir) / "emmchaccgen_out"
        emmchaccgen_out_dir.mkdir()
        emmchaccgen_cmd = [self.paths['emmchaccgen'].get(), '--keys', keyset_path, '--fw', self.paths['firmware'].get()]
        if "Mariko" in detected_model or detected_model in ["V2", "Lite", "OLED"]:
            self._log("--- Mariko model detected, using --mariko flag (AutoRCM disabled by default).")
            emmchaccgen_cmd.append('--mariko')
        else:
            self._log("--- Erista model detected, adding --no-autorcm flag by default.")
            emmchaccgen_cmd.append('--no-autorcm')
        if self._run_command(emmchaccgen_cmd, cwd=str(emmchaccgen_out_dir))[0] != 0: return

        self._log(f"\n[STEP 4/8] Dumping and decrypting SYSTEM partition from eMMC...")
        dump_cmd = [nx_exe, '-i', drive_path, '-keyset', keyset_path, '-o', temp_dir, '-d', '-part=SYSTEM']
        if self._run_command(dump_cmd)[0] != 0: return
        
        system_dec_path = Path(temp_dir) / "SYSTEM"
        if not system_dec_path.exists(): return self._log("ERROR: SYSTEM file was not created.")
        self._log("SUCCESS: SYSTEM partition decrypted.")
        
        self._log("--- Mounting SYSTEM partition...")
        osfmount_cmd = [self.paths['osfmount'].get(), '-a', '-t', 'file', '-f', str(system_dec_path), '-o', 'rw', '-m', '#:']
        return_code, output = self._run_command(osfmount_cmd)
        if return_code != 0: return
        match = re.search(r"([A-Z]:)", output)
        if not match: return self._log("ERROR: Could not determine drive letter.")
        drive_letter_str = match.group(1)
        drive_letter = Path(drive_letter_str)
        self._log("--- SYSTEM partition mounted")

        try:
            versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
            source_system_path = versioned_folder / "SYSTEM"
            
            success = self._selective_copy_system_contents_level1(source_system_path, drive_letter)
            if not success:
                return
                
        except Exception as e:
            return self._log(f"ERROR: Failed to modify SYSTEM partition contents. Error: {e}")
        finally:
            self._log("--- Dismounting SYSTEM partition...")
            self._run_command([self.paths['osfmount'].get(), '-D', '-m', drive_letter_str])

        self._log(f"\n[STEP 5 & 6/8] Flashing modified SYSTEM back to eMMC...")
        flash_cmd = [nx_exe, '-i', str(system_dec_path), '-o', drive_path, '-part=SYSTEM', '-e', '-keyset', keyset_path, 'FORCE']
        if self._run_command(flash_cmd)[0] != 0:
            return self._log("ERROR: Failed to flash SYSTEM partition back to eMMC.")
        self._log("SUCCESS: SYSTEM partition has been restored.")

        self._log(f"\n[STEP 7/8] Flashing BCPKG2 partitions...")
        versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
        bcpkg2_partitions = ["BCPKG2-1-Normal-Main", "BCPKG2-2-Normal-Sub", "BCPKG2-3-SafeMode-Main", "BCPKG2-4-SafeMode-Sub"]
        for part_name in bcpkg2_partitions:
            bcpkg2_file = versioned_folder / f"{part_name}.bin"
            if not bcpkg2_file.exists(): return self._log(f"ERROR: {bcpkg2_file.name} not found.")
            flash_cmd = [nx_exe, '-i', str(bcpkg2_file), '-o', drive_path, f'-part={part_name}', 'FORCE']
            if self._run_command(flash_cmd)[0] != 0: return self._log(f"ERROR: Failed to flash {part_name}.")
        self._log("SUCCESS: All BCPKG2 partitions have been restored.")

        self._log(f"\n[STEP 8/8] Saving BOOT0 & BOOT1 to output folder...")
        
        versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
        shutil.copy(versioned_folder / "BOOT0.bin", Path(temp_dir) / "BOOT0")
        shutil.copy(versioned_folder / "BOOT1.bin", Path(temp_dir) / "BOOT1")
        self._log(f"SUCCESS: BOOT0 and BOOT1 saved. Please flash them manually using Hekate.")
        self._log("\n--- LEVEL 1 IN-PLACE RESTORE COMPLETE ---")

        CustomDialog(self, title="Level 1 Complete", 
            message="Level 1 restore completed successfully!\n\n" +
                    "NEXT STEP: Disconnect USB cable, reconnect, and mount SD card in Hekate.\n" +
                    "Then click 'Copy BOOT to SD' button.")

        # Update button states AFTER user presses OK on dialog
        self.button_states["level1"] = "completed"
        self.button_states["copy_boot"] = "active"
        self._log(f"DEBUG: Setting copy_boot state to active after Level 1 completion")
        self._update_button_colors()
        # 强制更新界面以确保更改生效
        self.update_idletasks()

    def _run_and_interrupt_flash(self, command, partition_name, target_mb):
        self._log(f"--- Starting partial flash for {partition_name} with a {target_mb}MB target...")
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, creationflags=subprocess.CREATE_NO_WINDOW,
                                        bufsize=1, universal_newlines=True)
            progress_regex = re.compile(rf"Restoring to {partition_name}... (\d+\.\d+)\s*MB")
            for line in iter(process.stdout.readline, ''):
                clean_line = line.strip()
                if not clean_line: continue
                self._log(clean_line)
                match = progress_regex.search(clean_line)
                if match and float(match.group(1)) >= target_mb:
                    self._log(f"--- SUCCESS: Reached target. Terminating flash...")
                    process.terminate()
                    break
            process.stdout.close(); process.wait()
            self._log(f"--- Partial flash for {partition_name} complete.")
            return 0
        except Exception as e:
            self._log(f"FATAL ERROR during interruptible flash: {e}"); return -1

    def _run_level2_process(self, temp_dir):
        self._log("\n--- WARNING ---")
        self._log("The Level 2 process will write directly to your Switch's eMMC.")

        if not self._check_disk_space(60):
            return

        self._log("\n[STEP 1/7] Please connect your Switch in Hekate's eMMC RAW GPP mode (Read-Only OFF).")
        self._log("--- Detecting target eMMC...")
        potential_drives = self._detect_switch_drives_wmi()
        if not potential_drives:
            CustomDialog(self, title="Error", message="No potential Switch eMMC drives found. Please ensure it is connected properly.")
            return

        if len(potential_drives) > 1:
            CustomDialog(self, title="Multiple Drives Found", message="Found multiple drives that could be a Switch eMMC. "
                                                                    "For safety, please disconnect other USB drives and try again.")
            return
        
        target_drive = potential_drives[0]
        drive_path = target_drive['path']
        
        # --- ADDED: Confirmation Pop-up for Level 2 ---
        msg = (f"Found target eMMC:\n\nPath: {drive_path}\nSize: {target_drive['size']}\nModel: {target_drive['model']}\n\n"
               "WARNING: This will start the Level 2 Full Rebuild process.\n"
               "ALL USER DATA (saves, games) WILL BE PERMANENTLY ERASED.\n\nContinue?")
        
        dialog = CustomDialog(self, title="Confirm Level 2 Rebuild", message=msg, buttons="yesno")
        if not dialog.result:
            self._log("--- User cancelled Level 2 rebuild.")
            return
        # --- END OF ADDED CODE ---

        self._log(f"--- SUCCESS: User confirmed eMMC at {drive_path}")
        nx_exe = self.paths['nxnandmanager'].get()
        
        try:
            script_dir = Path(__file__).parent
        except NameError:
            script_dir = Path.cwd()
        partitions_folder = script_dir / "lib" / "NAND"
        keyset_path = self.paths['keys'].get()
        
        self._log("--- Acquiring PRODINFO...")
        prodinfo_path = Path(temp_dir) / "PRODINFO"
        dump_cmd = [nx_exe, '-i', drive_path, '-keyset', keyset_path, '-o', temp_dir, '-d', '-part=PRODINFO']
        
        donor_prodinfo_used = False
        if self._run_command(dump_cmd)[0] != 0 or not prodinfo_path.exists():
            self._log("--- INFO: Could not dump from eMMC. Falling back to donor PRODINFO file.")
            donor_path = Path(self.paths['prodinfo'].get())
            if not donor_path.is_file():
                self._log("ERROR: PRODINFO could not be dumped from eMMC and no donor file was provided.")
                CustomDialog(self, title="PRODINFO Error", message="PRODINFO is not found or damaged. Please use Level 3 instead.")
                return
            shutil.copy(donor_path, prodinfo_path)
            donor_prodinfo_used = True
        else: self._log("--- SUCCESS: PRODINFO dumped from eMMC.")
        
        with open(prodinfo_path, 'rb') as f:
            if f.read(4) != b'CAL0':
                source = "donor file" if donor_prodinfo_used else "eMMC"
                self._log(f"ERROR: The PRODINFO from the {source} is invalid or encrypted (magic is not CAL0).")
                CustomDialog(self, title="PRODINFO Error", message="PRODINFO is not found or damaged. Please use Level 3 instead.")
                return

        self._log(f"\n[STEP 2/7] Reading PRODINFO file...")

        # Check if console type override is enabled
        if self.override_console_type.get() and self.manual_console_type.get():
            # Use manual override
            manual_selection = self.manual_console_type.get()
            self._log(f"INFO: Using manual console type override: {manual_selection}")
            detected_model = "Mariko" if "Mariko" in manual_selection else "Erista"

            # Still read PRODINFO to show what was detected for reference
            with open(prodinfo_path, 'rb') as f:
                f.seek(0x3740)
                product_model_id = int.from_bytes(f.read(4), byteorder='little')
            model_map = {1: "Erista", 3: "V2", 4: "Lite", 6: "OLED"}
            auto_detected = model_map.get(product_model_id, "Unknown Mariko")
            self._log(f"INFO: Auto-detected model from PRODINFO: {auto_detected} (ignored due to override)")
        else:
            # Use automatic detection
            with open(prodinfo_path, 'rb') as f:
                f.seek(0x3740)
                product_model_id = int.from_bytes(f.read(4), byteorder='little')
            model_map = {1: "Erista", 3: "V2", 4: "Lite", 6: "OLED"}
            detected_model = model_map.get(product_model_id, "Unknown Mariko")
            self._log(f"SUCCESS: Detected model: {detected_model}")

        self._log(f"\n[STEP 3/7] Generating boot files...")
        emmchaccgen_out_dir = Path(temp_dir) / "emmchaccgen_out"
        emmchaccgen_out_dir.mkdir()
        emmchaccgen_cmd = [self.paths['emmchaccgen'].get(), '--keys', keyset_path, '--fw', self.paths['firmware'].get()]
        if "Mariko" in detected_model or detected_model in ["V2", "Lite", "OLED"]:
            self._log("--- Mariko model detected, using --mariko flag (AutoRCM disabled by default).")
            emmchaccgen_cmd.append('--mariko')
        else:
            self._log("--- Erista model detected, adding --no-autorcm flag by default.")
            emmchaccgen_cmd.append('--no-autorcm')
        if self._run_command(emmchaccgen_cmd, cwd=str(emmchaccgen_out_dir))[0] != 0: return

        self._log(f"\n[STEP 4/7] Preparing donor SYSTEM partition...")
        cmd = [self.paths['7z'].get(), 'x', str(partitions_folder / "SYSTEM.7z"), f'-o{temp_dir}', '-bsp1', '-y']
        if self._run_command_with_progress(cmd, "Extracting SYSTEM")[0] != 0: return
        system_dec_path = Path(temp_dir) / "SYSTEM.dec"
        
        self._log(f"--- Mounting donor SYSTEM to inject files...")
        osfmount_cmd = [self.paths['osfmount'].get(), '-a', '-t', 'file', '-f', str(system_dec_path), '-o', 'rw', '-m', '#:']
        return_code, output = self._run_command(osfmount_cmd)
        if return_code != 0: return
        match = re.search(r"([A-Z]:)", output)
        if not match: return self._log("ERROR: Could not determine drive letter.")
        drive_letter_str = match.group(1)

        try:
            versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
            source_system_path = versioned_folder / "SYSTEM"
            
            success = self._selective_copy_system_contents(source_system_path, Path(drive_letter_str))
            if not success:
                return
            self._log("--- SUCCESS: New system files injected into donor SYSTEM.")
        except Exception as e:
            return self._log(f"ERROR: Failed to inject files into SYSTEM. Error: {e}")
        finally:
            self._log(f"--- Dismounting drive...")
            self._run_command([self.paths['osfmount'].get(), '-D', '-m', drive_letter_str])

        self._log(f"\n[STEP 5/7] Flashing all data partitions to eMMC...")
        
        flash_cmd = [nx_exe, '-i', str(prodinfo_path), '-o', drive_path, '-part=PRODINFO', '-e', '-keyset', keyset_path, 'FORCE']
        if self._run_command(flash_cmd)[0] != 0: return
        
        flash_cmd = [nx_exe, '-i', str(system_dec_path), '-o', drive_path, '-part=SYSTEM', '-e', '-keyset', keyset_path, 'FORCE']
        if self._run_command(flash_cmd)[0] != 0: return

        partition_map = {"PRODINFOF": {"default": "PRODINFOF.7z"},
                            "USER": {"OLED": "USER-64.7z", "default": "USER-32.7z"},
                            "SAFE": {"default": "SAFE.7z"}}
        for part_name, archive_map in partition_map.items():
            archive_name = archive_map.get(detected_model, archive_map["default"])
            cmd = [self.paths['7z'].get(), 'x', str(partitions_folder / archive_name), f'-o{temp_dir}', '-bsp1', '-y']
            if self._run_command_with_progress(cmd, f"Extracting {part_name}")[0] == 0:
                dec_file_path = Path(temp_dir) / f"{part_name}.dec"
                flash_cmd = [nx_exe, '-i', str(dec_file_path), '-o', drive_path, f'-part={part_name}', '-e', '-keyset', keyset_path, 'FORCE']
                if part_name == "USER" and not donor_prodinfo_used:
                    if self._run_and_interrupt_flash(flash_cmd, "USER", 100) != 0: return
                else:
                    if self._run_command(flash_cmd)[0] != 0: return
        
        self._log("SUCCESS: All data partitions have been restored.")

        self._log(f"\n[STEP 6/7] Flashing BCPKG2 partitions...")
        versioned_folder = next(d for d in emmchaccgen_out_dir.iterdir() if d.is_dir())
        bcpkg2_partitions = ["BCPKG2-1-Normal-Main", "BCPKG2-2-Normal-Sub", "BCPKG2-3-SafeMode-Main", "BCPKG2-4-SafeMode-Sub"]
        for part_name in bcpkg2_partitions:
            bcpkg2_file = versioned_folder / f"{part_name}.bin"
            if not bcpkg2_file.exists(): return self._log(f"ERROR: {bcpkg2_file.name} not found.")
            flash_cmd = [nx_exe, '-i', str(bcpkg2_file), '-o', drive_path, f'-part={part_name}', 'FORCE']
            if self._run_command(flash_cmd)[0] != 0: return self._log(f"ERROR: Failed to flash {part_name}.")
        self._log("SUCCESS: All BCPKG2 partitions have been restored.")

        self._log(f"\n[STEP 7/7] Saving BOOT0 & BOOT1 to output folder...")
        
        shutil.copy(versioned_folder / "BOOT0.bin", Path(temp_dir) / "BOOT0")
        shutil.copy(versioned_folder / "BOOT1.bin", Path(temp_dir) / "BOOT1")
        self._log(f"SUCCESS: BOOT0 and BOOT1 saved. Please flash them manually using Hekate.")
        self._log("\n--- LEVEL 2 IN-PLACE REBUILD COMPLETE ---")

        CustomDialog(self, title="Level 2 Complete", 
            message="Level 2 rebuild completed successfully!\n\n" +
                    "NEXT STEP: Disconnect USB cable, reconnect, and mount SD card in Hekate.\n" +
                    "Then click 'Copy BOOT to SD' button.")

        # Update button states AFTER user presses OK on dialog
        self.button_states["level2"] = "completed"
        self.button_states["copy_boot"] = "active"
        self._log(f"DEBUG: Setting copy_boot state to active after Level 2 completion")
        self._update_button_colors()
        # 强制更新界面以确保更改生效
        self.update_idletasks()

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if __name__ == "__main__":
    # --- START: ADDED DEPENDENCY INSTALLER ---
    import subprocess
    import sys
    import importlib

    def install_dependencies():
        """Checks for and installs required packages if they are missing."""
        required_packages = ['wmi', 'psutil']
        for package in required_packages:
            try:
                # Try to import the package to see if it's installed
                importlib.import_module(package)
                print(f"INFO: Dependency '{package}' is already installed.")
            except ImportError:
                print(f"INFO: Dependency '{package}' not found. Attempting to install...")
                try:
                    # Use sys.executable to ensure pip from the correct python environment is used
                    # Use flags to suppress installation output unless there's an error
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    print(f"SUCCESS: Successfully installed '{package}'.")
                except subprocess.CalledProcessError:
                    # If installation fails, show a clear error message box and exit
                    error_msg = (f"Failed to automatically install the required package: '{package}'.\n\n"
                                 f"Please install it manually by opening a command prompt/terminal and running:\n\n"
                                 f"pip install {package}")
                    print(f"ERROR: {error_msg}")
                    ctypes.windll.user32.MessageBoxW(0, error_msg, "Dependency Error", 0x10) # 0x10 = MB_ICONERROR
                    sys.exit(1) # Exit the script if a critical dependency can't be installed

    install_dependencies()
    # --- END: ADDED DEPENDENCY INSTALLER ---

    # --- WRAP THE APP STARTUP IN A TRY/EXCEPT BLOCK ---
    app = None
    try:
        if is_admin():
            app = SwitchGuiApp()
            app.mainloop()
        else:
            # Relaunch as admin
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    except Exception as e:
        # If any error happens here, the excepthook at the top will catch it,
        # log it to error_log.txt, and exit the program safely.
        raise e