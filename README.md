# User Management System

A secure and modern desktop-based User Management System built using **Python, Tkinter, and SQLite**.  
The project provides authentication, role-based access control, profile management, password reset, login security, and an admin dashboard with a modern dark-themed GUI.

---

## ✨ Features

- Secure user registration and login
- Password hashing using PBKDF2-HMAC-SHA256
- Admin & User role management
- Account lockout after multiple failed login attempts
- Password reset using secure tokens
- Profile editing and password changing
- Login history tracking
- Activate/Deactivate accounts
- Search and filter users
- Export user data to CSV
- Modern dark-themed Tkinter interface

---

## 🛠️ Technologies Used

- Python
- Tkinter & ttk
- SQLite3
- hashlib
- threading
- csv


---

## 🚀 Installation & Run

```bash
git clone https://github.com/your-username/user-management-system.git
cd user-management-system
python main.py
```

---

## 🔑 Default Admin Login

| Username | Password |
|----------|-----------|
| admin | Admin@123 |

---

## 🗄️ Database

The application automatically creates:

```text
user_management.db
```

### Tables Included
- users
- login_attempts
- reset_tokens

---

## 🔒 Security Features

- Salted password hashing
- Login attempt tracking
- Temporary account lockout
- Secure reset token generation
- Input validation and sanitization

---

## 📸 Main Modules

- Login System
- Registration System
- Forgot Password
- Profile Management
- Security Panel
- Admin Dashboard
- CSV Export System

---
