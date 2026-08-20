# Secure File Sharing System

## Task 5 - Secure File Sharing System

SecureShare is a Python Flask web application that demonstrates secure file storage and sharing.

The system allows authenticated users to upload and download files while protecting stored files using encryption.

It also implements role-based access control and temporary expiring download links.

---

## Features

- User registration
- User authentication
- Password hashing
- Secure file upload
- File encryption before storage
- Secure file decryption during download
- Role-based access control
- User and administrator roles
- File ownership checks
- Temporary download links
- Link expiration
- Secure filenames
- File type restrictions
- Maximum upload size
- File deletion
- SQLite database

---

## Technologies Used

- Python 3
- Flask
- SQLite
- Cryptography / Fernet
- Werkzeug
- HTML
- CSS

---

## Project Structure

```text
task5/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── uploads/
    └── .gitkeep