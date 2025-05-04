#!/usr/bin/env python3
import sys
import os
import json
import csv
import secrets
import string
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QPushButton, QLineEdit,
                           QTextEdit, QMessageBox, QFileDialog, QSpinBox,
                           QFrame, QGridLayout, QScrollArea, QComboBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor, QPixmap

class PasswordManager:
    def __init__(self, file_path=None):
        if file_path is None:
            file_path = os.path.expanduser('~/.passmanager/passwords.json')
        self.file_path = file_path
        self.key = self.load_key()
        self.fernet = Fernet(self.key)
        self.passwords = self.load_passwords()
        # Default categories
        self.categories = ["1", "2", "3", "4"]
        if "categories" not in self.passwords:
            self.passwords["categories"] = {}
            for category in self.categories:
                self.passwords["categories"][category] = {}
            self.save_passwords()

    def load_key(self):
        key_path = os.path.expanduser('~/.passmanager/secret.key')
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        if os.path.exists(key_path):
            with open(key_path, 'rb') as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as key_file:
                key_file.write(key)
            os.chmod(key_path, 0o600)  # Set permissions to read/write for owner only
            return key

    def load_passwords(self):
        if os.path.exists(self.file_path):
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                return json.loads(decrypted_data)
        return {}

    def save_passwords(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.passwords).encode())
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)
        with open(self.file_path, 'wb') as file:
            file.write(encrypted_data)

    def add_password(self, service, username, password, category="1"):
        if category not in self.passwords["categories"]:
            self.passwords["categories"][category] = {}
        self.passwords["categories"][category][service] = {'username': username, 'password': password}
        self.save_passwords()

    def get_password(self, service, category=None):
        if category:
            if category in self.passwords["categories"] and service in self.passwords["categories"][category]:
                return self.passwords["categories"][category][service]
        else:
            # Search in all categories
            for cat, services in self.passwords["categories"].items():
                if service in services:
                    return services[service]
        return None

    def update_password(self, service, username, password, category=None):
        if category:
            if category in self.passwords["categories"] and service in self.passwords["categories"][category]:
                self.passwords["categories"][category][service] = {'username': username, 'password': password}
                self.save_passwords()
                return True
        else:
            # Search and update in all categories
            for cat, services in self.passwords["categories"].items():
                if service in services:
                    services[service] = {'username': username, 'password': password}
                    self.save_passwords()
                    return True
        return False

    def delete_password(self, service, category=None):
        if category:
            if category in self.passwords["categories"] and service in self.passwords["categories"][category]:
                del self.passwords["categories"][category][service]
                self.save_passwords()
                return True
        else:
            # Search and delete in all categories
            for cat, services in self.passwords["categories"].items():
                if service in services:
                    del services[service]
                    self.save_passwords()
                    return True
        return False

    def search_password(self, keyword, category=None):
        results = {}
        if category:
            if category in self.passwords["categories"]:
                cat_services = self.passwords["categories"][category]
                results.update({service: creds for service, creds in cat_services.items() 
                              if keyword.lower() in service.lower()})
        else:
            # Search in all categories
            for cat, services in self.passwords["categories"].items():
                cat_results = {service: creds for service, creds in services.items() 
                              if keyword.lower() in service.lower()}
                results.update(cat_results)
        return results

    def get_categories(self):
        return list(self.passwords["categories"].keys())

    def import_passwords(self, csv_file):
        try:
            with open(csv_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    service = row['service']
                    username = row['username']
                    password = row['password']
                    category = row.get('category', '1')  # Default to category 1 if not specified
                    self.add_password(service, username, password, category)
            return True
        except Exception as e:
            print(f"Error importing passwords: {e}")
            return False

    def export_passwords(self, csv_file):
        try:
            with open(csv_file, 'w', newline='') as file:
                fieldnames = ['category', 'service', 'username', 'password']
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                for category, services in self.passwords["categories"].items():
                    for service, creds in services.items():
                        writer.writerow({
                            'category': category,
                            'service': service, 
                            'username': creds['username'], 
                            'password': creds['password']
                        })
            return True
        except Exception as e:
            print(f"Error exporting passwords: {e}")
            return False

    def generate_password(self, length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for i in range(length))
        return password

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.password_manager = PasswordManager()
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("Securonis Password Manager")
        self.setGeometry(100, 100, 600, 250)
        

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        

        top_panel = QWidget()
        top_panel.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
                border-radius: 0px;
                padding: 0px;
                margin: 0px;
            }
        """)
        top_layout = QVBoxLayout(top_panel)
        top_layout.setSpacing(1)
        top_layout.setContentsMargins(1, 1, 1, 1)
        

        first_row = QHBoxLayout()
        first_row.setSpacing(2)
        first_row.setContentsMargins(0, 0, 0, 0)
        

        second_row = QHBoxLayout()
        second_row.setSpacing(2)
        second_row.setContentsMargins(0, 0, 0, 0)
        

        third_row = QHBoxLayout()
        third_row.setSpacing(2)
        third_row.setContentsMargins(0, 0, 0, 0)
        

        button_style = """
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 3px 5px;
                border-radius: 5px;
                font-weight: bold;
                font-size: 12px;
                min-width: 120px;
                margin: 1px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QPushButton:pressed {
                background-color: #1d1d1d;
            }
            QPushButton:disabled {
                background-color: #1d1d1d;
                color: #666666;
            }
        """

        menu_buttons = [
            ("Add Password", self.show_add_password),
            ("Get Password", self.show_get_password),
            ("Update Password", self.show_update_password),
            ("Delete Password", self.show_delete_password),
            ("Search Passwords", self.show_search_password),
            ("Import CSV", self.import_passwords),
            ("Export CSV", self.export_passwords),
            ("Generate Password", self.show_generate_password),
            ("Show All Passwords", self.show_all_passwords)
        ]

        for text, callback in menu_buttons[:4]:
            btn = QPushButton(text)
            btn.setStyleSheet(button_style)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(callback)
            first_row.addWidget(btn)
        

        for text, callback in menu_buttons[4:8]:
            btn = QPushButton(text)
            btn.setStyleSheet(button_style)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(callback)
            second_row.addWidget(btn)
            
        # Add Show All Passwords button in the third row
        show_all_btn = QPushButton(menu_buttons[8][0])
        show_all_btn.setStyleSheet(button_style)
        show_all_btn.setCursor(Qt.PointingHandCursor)
        show_all_btn.clicked.connect(menu_buttons[8][1])
        third_row.addWidget(show_all_btn)
        
        top_layout.addLayout(first_row)
        top_layout.addLayout(second_row)
        top_layout.addLayout(third_row)
        main_layout.addWidget(top_panel)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMaximumHeight(150)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 0px;
                padding: 5px;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                line-height: 1.4;
            }
            QScrollBar:vertical {
                border: none;
                background-color: #2d2d2d;
                width: 6px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #42d4d4;
                border-radius: 2px;
                min-height: 15px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #3d3d3d;
            }
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        main_layout.addWidget(self.output_text)
        
        self.set_dark_theme()
        
    def set_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(26, 26, 26))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(45, 45, 45))
        palette.setColor(QPalette.AlternateBase, QColor(35, 35, 35))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(45, 45, 45))
        palette.setColor(QPalette.ButtonText, Qt.white)
        self.setPalette(palette)
        
    def show_add_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Add Password")
        dialog.setGeometry(200, 200, 400, 280)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 12px;
            }
            QLineEdit, QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png);
                width: 12px;
                height: 12px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                selection-background-color: #3d3d3d;
                selection-color: #42d4d4;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        category_label = QLabel("Category:")
        category_combo = QComboBox()
        for category in self.password_manager.get_categories():
            category_combo.addItem(category)
        
        service_label = QLabel("Service Name:")
        service_input = QLineEdit()
        service_input.setPlaceholderText("Enter service name")
        
        username_label = QLabel("Username:")
        username_input = QLineEdit()
        username_input.setPlaceholderText("Enter username")
        
        password_label = QLabel("Password:")
        password_input = QLineEdit()
        password_input.setPlaceholderText("Enter password")
        password_input.setEchoMode(QLineEdit.Password)
        
        layout.addWidget(category_label)
        layout.addWidget(category_combo)
        layout.addWidget(service_label)
        layout.addWidget(service_input)
        layout.addWidget(username_label)
        layout.addWidget(username_input)
        layout.addWidget(password_label)
        layout.addWidget(password_input)
        
        button_layout = QHBoxLayout()
        save_btn = QPushButton("Save")
        cancel_btn = QPushButton("Cancel")
        
        save_btn.clicked.connect(lambda: self.add_password(
            service_input.text(),
            username_input.text(),
            password_input.text(),
            category_combo.currentText(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(save_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()
        
    def add_password(self, service, username, password, category, dialog):
        if not all([service, username, password]):
            QMessageBox.warning(dialog, "Error", "Please fill all fields!")
            return
            
        self.password_manager.add_password(service, username, password, category)
        self.output_text.setText(f"Password added for service: {service} (Category: {category})")
        dialog.close()
        
    def show_get_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Get Password")
        dialog.setGeometry(200, 200, 300, 140)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                selection-background-color: #3d3d3d;
                selection-color: #42d4d4;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 10, 10, 10)
        
        category_label = QLabel("Category (optional):")
        category_combo = QComboBox()
        category_combo.addItem("All Categories")
        for category in self.password_manager.get_categories():
            category_combo.addItem(category)
        
        service_label = QLabel("Service Name:")
        service_input = QLineEdit()
        service_input.setPlaceholderText("Enter service name")
        
        layout.addWidget(category_label)
        layout.addWidget(category_combo)
        layout.addWidget(service_label)
        layout.addWidget(service_input)
        
        button_layout = QHBoxLayout()
        get_btn = QPushButton("Get")
        cancel_btn = QPushButton("Cancel")
        
        get_btn.clicked.connect(lambda: self.get_password(
            service_input.text(), 
            None if category_combo.currentText() == "All Categories" else category_combo.currentText(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(get_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()
        
    def get_password(self, service, category, dialog):
        if not service:
            QMessageBox.warning(dialog, "Error", "Please enter service name!")
            return
            
        password_info = self.password_manager.get_password(service, category)
        if password_info:
            self.output_text.setText(f"Service: {service}\nUsername: {password_info['username']}\nPassword: {password_info['password']}")
        else:
            self.output_text.setText("Service not found.")
        dialog.close()
        
    def show_update_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Update Password")
        dialog.setGeometry(200, 200, 300, 240)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                selection-background-color: #3d3d3d;
                selection-color: #42d4d4;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 10, 10, 10)
        
        category_label = QLabel("Category (optional):")
        category_combo = QComboBox()
        category_combo.addItem("All Categories")
        for category in self.password_manager.get_categories():
            category_combo.addItem(category)
        
        service_label = QLabel("Service Name:")
        service_input = QLineEdit()
        service_input.setPlaceholderText("Enter service name")
        
        username_label = QLabel("New Username:")
        username_input = QLineEdit()
        username_input.setPlaceholderText("Enter new username")
        
        password_label = QLabel("New Password:")
        password_input = QLineEdit()
        password_input.setPlaceholderText("Enter new password")
        password_input.setEchoMode(QLineEdit.Password)
        
        layout.addWidget(category_label)
        layout.addWidget(category_combo)
        layout.addWidget(service_label)
        layout.addWidget(service_input)
        layout.addWidget(username_label)
        layout.addWidget(username_input)
        layout.addWidget(password_label)
        layout.addWidget(password_input)
        
        button_layout = QHBoxLayout()
        update_btn = QPushButton("Update")
        cancel_btn = QPushButton("Cancel")
        
        update_btn.clicked.connect(lambda: self.update_password(
            service_input.text(),
            username_input.text(),
            password_input.text(),
            None if category_combo.currentText() == "All Categories" else category_combo.currentText(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(update_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()
        
    def update_password(self, service, username, password, category, dialog):
        if not all([service, username, password]):
            QMessageBox.warning(dialog, "Error", "Please fill all fields!")
            return
            
        if self.password_manager.update_password(service, username, password, category):
            self.output_text.setText(f"Password updated for service: {service}")
        else:
            self.output_text.setText("Service not found.")
        dialog.close()
        
    def show_delete_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Delete Password")
        dialog.setGeometry(200, 200, 300, 140)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                selection-background-color: #3d3d3d;
                selection-color: #42d4d4;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 10, 10, 10)
        
        category_label = QLabel("Category (optional):")
        category_combo = QComboBox()
        category_combo.addItem("All Categories")
        for category in self.password_manager.get_categories():
            category_combo.addItem(category)
        
        service_label = QLabel("Service Name:")
        service_input = QLineEdit()
        service_input.setPlaceholderText("Enter service name")
        
        layout.addWidget(category_label)
        layout.addWidget(category_combo)
        layout.addWidget(service_label)
        layout.addWidget(service_input)
        
        button_layout = QHBoxLayout()
        delete_btn = QPushButton("Delete")
        cancel_btn = QPushButton("Cancel")
        
        delete_btn.clicked.connect(lambda: self.delete_password(
            service_input.text(), 
            None if category_combo.currentText() == "All Categories" else category_combo.currentText(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(delete_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()
        
    def delete_password(self, service, category, dialog):
        if not service:
            QMessageBox.warning(dialog, "Error", "Please enter service name!")
            return
            
        if self.password_manager.delete_password(service, category):
            self.output_text.setText(f"Deleted password for service: {service}")
        else:
            self.output_text.setText("Service not found.")
        dialog.close()
        
    def show_search_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Search Passwords")
        dialog.setGeometry(200, 200, 300, 140)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 11px;
            }
            QLineEdit, QComboBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
            QLineEdit:focus, QComboBox:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QComboBox::drop-down {
                border: 0px;
            }
            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: white;
                selection-background-color: #3d3d3d;
                selection-color: #42d4d4;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 10, 10, 10)
        
        category_label = QLabel("Category (optional):")
        category_combo = QComboBox()
        category_combo.addItem("All Categories")
        for category in self.password_manager.get_categories():
            category_combo.addItem(category)
        
        keyword_label = QLabel("Search Keyword:")
        keyword_input = QLineEdit()
        keyword_input.setPlaceholderText("Enter keyword to search")
        
        layout.addWidget(category_label)
        layout.addWidget(category_combo)
        layout.addWidget(keyword_label)
        layout.addWidget(keyword_input)
        
        button_layout = QHBoxLayout()
        search_btn = QPushButton("Search")
        cancel_btn = QPushButton("Cancel")
        
        search_btn.clicked.connect(lambda: self.search_password(
            keyword_input.text(), 
            None if category_combo.currentText() == "All Categories" else category_combo.currentText(),
            dialog
        ))
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(search_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()
        
    def search_password(self, keyword, category, dialog):
        if not keyword:
            QMessageBox.warning(dialog, "Error", "Please enter a keyword!")
            return
            
        results = self.password_manager.search_password(keyword, category)
        
        if not results:
            self.output_text.setText("No matching services found.")
        else:
            output = "Search Results:\n\n"
            for service, creds in results.items():
                output += f"Service: {service}\nUsername: {creds['username']}\nPassword: {creds['password']}\n\n"
            self.output_text.setText(output)
        dialog.close()
        
    def import_passwords(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select CSV File", "", "CSV Files (*.csv)")
        if file_path:
            self.password_manager.import_passwords(file_path)
            self.output_text.setText("Passwords imported successfully.")
            
    def export_passwords(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save CSV File", "", "CSV Files (*.csv)")
        if file_path:
            self.password_manager.export_passwords(file_path)
            self.output_text.setText(f"Passwords exported to {file_path}")
            
    def show_generate_password(self):
        dialog = QWidget()
        dialog.setWindowTitle("Generate Password")
        dialog.setGeometry(200, 200, 300, 120)
        dialog.setStyleSheet("""
            QWidget {
                background-color: #1a1a1a;
            }
            QLabel {
                color: white;
                font-size: 11px;
            }
            QLineEdit {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
            QLineEdit:focus {
                border: 1px solid #42d4d4;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
                font-weight: bold;
                font-size: 11px;
            }
            QPushButton:hover {
                background-color: #3d3d3d;
                border: 1px solid #42d4d4;
                color: #42d4d4;
            }
            QSpinBox {
                background-color: #2d2d2d;
                color: white;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 4px;
                font-size: 11px;
            }
        """)
        layout = QVBoxLayout(dialog)
        layout.setSpacing(5)
        layout.setContentsMargins(10, 10, 10, 10)
        

        length_layout = QHBoxLayout()
        length_label = QLabel("Password Length:")
        length_spin = QSpinBox()
        length_spin.setRange(8, 32)
        length_spin.setValue(12)
        length_layout.addWidget(length_label)
        length_layout.addWidget(length_spin)
        layout.addLayout(length_layout)

        password_display = QLineEdit()
        password_display.setReadOnly(True)
        password_display.setPlaceholderText("Generated password will appear here")
        layout.addWidget(password_display)
        
        button_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate")
        copy_btn = QPushButton("Copy")
        cancel_btn = QPushButton("Cancel")
        
        def generate():
            password = self.password_manager.generate_password(length_spin.value())
            password_display.setText(password)
            
        def copy():
            if password_display.text():
                QApplication.clipboard().setText(password_display.text())
                QMessageBox.information(dialog, "Success", "Password copied to clipboard!")
                
        generate_btn.clicked.connect(generate)
        copy_btn.clicked.connect(copy)
        cancel_btn.clicked.connect(dialog.close)
        
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(copy_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)
        
        dialog.show()

    def show_all_passwords(self):
        output = "All Passwords by Category:\n\n"
        
        for category in self.password_manager.get_categories():
            category_passwords = self.password_manager.passwords["categories"][category]
            if category_passwords:
                output += f"Category: {category}\n"
                output += "-" * 40 + "\n"
                
                for service, creds in category_passwords.items():
                    output += f"Service: {service}\n"
                    output += f"Username: {creds['username']}\n"
                    output += f"Password: {creds['password']}\n"
                    output += "-" * 30 + "\n"
                
                output += "\n"
        
        if output == "All Passwords by Category:\n\n":
            output += "No passwords stored."
        
        self.output_text.setText(output)

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = PasswordManagerGUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
