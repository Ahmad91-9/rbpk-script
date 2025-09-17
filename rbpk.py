import sys
import time
import threading
import requests
import pandas as pd

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QPushButton,
    QVBoxLayout, QCheckBox, QFileDialog, QMessageBox, QTextEdit
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QTextCursor

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager


class OrderAutomationApp(QMainWindow):
    # Signals for thread-safe UI updates
    log_signal = Signal(str)
    info_signal = Signal(str, str)   # (title, message)
    error_signal = Signal(str, str)  # (title, message)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("RB-PK Order Automation")
        self.setGeometry(200, 200, 600, 600)
        self.setFixedSize(600, 600)

        self.driver = None
        self.LOG_FILE = "log.txt"

        self.init_ui()

        # Connect signals
        self.log_signal.connect(self.append_log)
        self.info_signal.connect(lambda t, m: QMessageBox.information(self, t, m))
        self.error_signal.connect(lambda t, m: QMessageBox.critical(self, t, m))

    def get_logged_in_user(self):
        """
        Fetch logged-in SaaS username.
        This is injected from the SaaS app before launching.
        Example:
            sys._saas_logged_in_user = "ahmad123"
        """
        return getattr(sys, "_saas_logged_in_user", "Guest")

    def init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Username (pre-filled + read-only)
        layout.addWidget(QLabel("User ID:"))
        self.user_entry = QLineEdit()
        self.user_entry.setText(self.get_logged_in_user())
        self.user_entry.setReadOnly(True)
        layout.addWidget(self.user_entry)

        # Password
        layout.addWidget(QLabel("Password:"))
        self.pass_entry = QLineEdit()
        self.pass_entry.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.pass_entry)

        self.show_pass_chk = QCheckBox("Show Password")
        self.show_pass_chk.stateChanged.connect(self.toggle_password)
        layout.addWidget(self.show_pass_chk)

        # File selection
        layout.addWidget(QLabel("Select Excel/CSV File:"))
        self.file_entry = QLineEdit()
        layout.addWidget(self.file_entry)

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_file)
        layout.addWidget(self.browse_btn)

        # Start button
        self.start_btn = QPushButton("Start Automation")
        self.start_btn.setStyleSheet("background-color: green; color: white;")
        self.start_btn.clicked.connect(self.start_thread)
        layout.addWidget(self.start_btn)

        # Dark mode toggle
        self.dark_toggle = QCheckBox("Dark Mode")
        self.dark_toggle.stateChanged.connect(self.toggle_theme)
        layout.addWidget(self.dark_toggle)

        # Logs
        layout.addWidget(QLabel("Logs:"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(self.log_box)

    def toggle_password(self):
        self.pass_entry.setEchoMode(QLineEdit.Normal if self.show_pass_chk.isChecked() else QLineEdit.Password)

    def toggle_theme(self):
        dark = self.dark_toggle.isChecked()
        if dark:
            self.setStyleSheet("background-color: #1e1e1e; color: white;")
            self.pass_entry.setStyleSheet("background-color: #2e2e2e; color: white;")
            self.file_entry.setStyleSheet("background-color: #2e2e2e; color: white;")
            self.log_box.setStyleSheet("background-color: #121212; color: white;")
        else:
            self.setStyleSheet("")
            self.pass_entry.setStyleSheet("")
            self.file_entry.setStyleSheet("")
            self.log_box.setStyleSheet("")

    def browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Excel or CSV File",
            "", "Excel Files (*.xlsx *.xls);;CSV Files (*.csv)"
        )
        if path:
            self.file_entry.setText(path)

    # -------- Logging --------
    def append_log(self, message: str):
        self.log_box.append(message)
        self.log_box.moveCursor(QTextCursor.End)
        with open(self.LOG_FILE, "a", encoding="utf-8") as f:
            f.write(message + "\n")

    def write_log(self, message: str):
        self.log_signal.emit(message)

    # -------- Bot helpers --------
    def wait_for_elem(self, xpath, timeout=20, clickable=False):
        condition = EC.element_to_be_clickable if clickable else EC.presence_of_element_located
        return WebDriverWait(self.driver, timeout).until(condition((By.XPATH, xpath)))

    def handle_popup(self, timeout=3):
        try:
            WebDriverWait(self.driver, timeout).until(EC.alert_is_present())
            alert = self.driver.switch_to.alert
            alert_text = alert.text
            alert.accept()
            self.write_log(f"Popup handled: {alert_text}")
            return alert_text
        except:
            return None

    # -------- Threads --------
    def start_thread(self):
        if not self.is_connected():
            QMessageBox.critical(self, "Network Error", "No internet connection. Please check and try again.")
            return

        user = self.user_entry.text().strip()
        password = self.pass_entry.text().strip()
        file_path = self.file_entry.text().strip()

        if not user or not password or not file_path:
            QMessageBox.warning(self, "Missing Input", "Please fill all fields and choose a file.")
            return

        # Disable controls while bot runs
        self.start_btn.setEnabled(False)
        self.pass_entry.setEnabled(False)
        self.file_entry.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.dark_toggle.setEnabled(False)

        threading.Thread(target=self.start_bot, args=(user, password, file_path), daemon=True).start()

    def start_bot(self, user, password, file_path):
        try:
            open(self.LOG_FILE, "w").close()
            self.write_log("[*] Starting automation...")

            options = Options()
            options.add_argument("--disable-gpu")
            options.add_argument("--ignore-certificate-errors")
            options.add_experimental_option('excludeSwitches', ['enable-logging'])

            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=options)
            self.driver.get("https://rb-pk.np.accenture.com/RB_PK/Logon.aspx?SR=1429x858")
            self.driver.maximize_window()

            df = pd.read_csv(file_path) if file_path.endswith(".csv") else pd.read_excel(file_path)

            # Login
            self.wait_for_elem("//input[@id='txtUserid']").send_keys(user)
            self.wait_for_elem("//input[@id='txtPasswd']").send_keys(password)
            self.wait_for_elem("//a[@id='btnLogin']", clickable=True).click()

            # Navigate to Order Page
            self.wait_for_elem("//li[@id='li_ROOT_tab_Main_itm_Txn_li']//a[@id='ROOT_tab_Main_itm_Txn']", clickable=True).click()
            self.wait_for_elem("//a[@id='pag_TxnRoot_tab_Main_itm_Order']", clickable=True).click()
            time.sleep(2)

            # Process rows
            for index, row in df.iterrows():
                try:
                    if pd.isna(row.get("Customer")):
                        self.write_log(f"\n[Row {index+1}] Skipped (No Customer)")
                        continue

                    has_product = any(
                        pd.notna(row.get(f'P{i}')) and pd.notna(row.get(f'EA{i}')) for i in range(1, 10)
                    )
                    if not has_product:
                        self.write_log(f"\n[Row {index+1}] Skipped (No valid product entries)")
                        continue

                    self.write_log(f"\n[Row {index+1}] Processing: {row.to_dict()}")

                    self.wait_for_elem("//input[@id='pag_T_Order_btn_AddOrder_Value']", clickable=True).click()
                    self.handle_popup()

                    cust_input = self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_sel_n_CUST_CD_Value']")
                    cust_input.clear()
                    cust_input.send_keys(str(row['Customer']))

                    self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_btn_n_Add_Value']", clickable=True).click()
                    self.handle_popup()

                    for i in range(1, 10):
                        prod_key, qty_key = f'P{i}', f'EA{i}'
                        prod, qty = row.get(prod_key), row.get(qty_key)

                        if pd.isna(prod) or pd.isna(qty):
                            continue

                        product_code = str(int(prod)).strip() if isinstance(prod, float) and prod.is_integer() else str(prod).strip()
                        quantity = str(int(qty)).strip() if isinstance(qty, float) and qty.is_integer() else str(qty).strip()

                        try:
                            prd_input = self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_sel_n_PRD_CD_Value']")
                            prd_input.clear()
                            prd_input.send_keys(product_code)

                            self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_btn_n_Add_Value']", clickable=True).click()
                            self.handle_popup()

                            qty_input = self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_txt_n_UOM1_PRD_QTY_Value']")
                            qty_input.clear()
                            qty_input.send_keys(quantity)

                            self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_btn_n_Add_Value']", clickable=True).click()
                            self.handle_popup()
                        except Exception as e:
                            self.write_log(f"[!] Failed to process product P{i} in row {index+1}: {e}")
                            continue

                    self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_btn_n_Promotion_Value']", clickable=True).click()
                    self.handle_popup()

                    self.wait_for_elem("//input[@id='pag_TO_NewGeneral_PT_frm_Detail_Save_Value']", clickable=True).click()
                    self.handle_popup()

                except Exception as e:
                    self.write_log(f"[!] ERROR processing row {index+1}: {e}")
                    continue

            self.write_log("\n[✓] All orders processed successfully.")
            self.info_signal.emit("Done", "All orders have been processed.")

        except Exception as e:
            self.write_log(f"[!] ERROR: {e}")
            self.error_signal.emit("Error", str(e))
        finally:
            # Re-enable controls
            self.start_btn.setEnabled(True)
            self.pass_entry.setEnabled(True)
            self.file_entry.setEnabled(True)
            self.browse_btn.setEnabled(True)
            self.dark_toggle.setEnabled(True)

    @staticmethod
    def is_connected():
        try:
            requests.get("https://www.google.com", timeout=3)
            return True
        except:
            return False


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = OrderAutomationApp()
    window.show()
    sys.exit(app.exec())
