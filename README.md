## 🔥 **Enterprise Payroll Management System**

*A Complete Python + MySQL Solution for Automating Payroll, Attendance & HR Tasks*

> 📍 **Final Project for Database Systems Course**
> 📚 Developed to apply real-world relational database design, secure authentication, and backend logic with a clean GUI.

### 📌 Project Overview

This Enterprise Payroll Management System is a comprehensive solution designed to streamline payroll processing, attendance tracking, leave management, and loan administration for businesses of all sizes. Built with Python (Tkinter for GUI) and MySQL, this system provides an intuitive interface for HR and finance teams to manage employee data efficiently.

---

### 👨‍💻 **About Me**

Hi, I'm **M.Ilyas Khan**, a passionate Python developer and AI engineering student with a strong focus on backend systems and database management. This project reflects my ability to build secure, scalable, and user-friendly applications by applying classroom theory to real-world problems.

---

### 🧠 **Why This Project?**

Manual payroll and HR tasks lead to **errors**, **data loss**, and **inefficiency**. I built this system to solve those problems using Python and MySQL — turning database concepts like **normalization**, **foreign keys**, and **transactions** into a fully working tool.

---

### 🌟 **Key Features**

* **👥 Employee Management** – Add/update/delete employee records
* **📅 Attendance Tracker** – Daily logging with leave and overtime options
* **💰 Payroll Automation** – Calculates net salary, tax, overtime, and generates PDF payslips
* **🏝️ Leave Management** – Employees can apply for leave, admins can approve/reject
* **💳 Loan Tracking** – Manage employee loans with auto-deductions
* **📊 Reports & Analytics** – Downloadable payroll summaries, attendance logs, tax data
* **🔐 Secure Login** – Admin-auth with `bcrypt` password hashing
* **🛡️ Backup & Restore** – Built-in MySQL export/import system

---

### 🛠️ **Technologies Used**

| Component    | Tech Stack                    |
| ------------ | ----------------------------- |
| **Frontend** | Python (Tkinter)              |
| **Backend**  | MySQL + `pymysql`             |
| **Security** | `bcrypt`                      |
| **Reports**  | `fpdf`                        |
| **Extras**   | `tkcalendar`, `Pillow` for UI |

---

### ⚙️ **How to Run the Project**

#### ✅ **Prerequisites**

* Python 3.8+
* MySQL Server
* Install required libraries:

  ```bash
  pip install pymysql bcrypt fpdf tkcalendar pillow
  ```

#### 📥 **Step-by-Step Setup**

1. **Create MySQL Database**

   SQL
   Download the provided SQL file and run it in MySQL to create all the required tables automatically.

2. **Configure DB in Code**
   In `payroll_system.py`:

   ```python
   DB_CONFIG = {
       'host': 'localhost',
       'user': 'root',
       'password': 'yourpassword',
       'database': 'payroll_system',
       'charset': 'utf8mb4',
       'cursorclass': pymysql.cursors.DictCursor
   }
   ```

3. **Launch Application**

   ```bash
   python payroll_system.py
   ```

4. **First Time Login**

   * Register an admin account
   * Use your credentials to access full features

---

### 🧠 **Concepts Applied from Course**

* **Database Normalization** (1NF-3NF)
* **Foreign Keys & Relations**
* **Secure Login (bcrypt)**
* **Transactions** (for payroll processing)
* **Backup & Restore** using SQL dumps
* **CRUD Operations with Tkinter GUI**

---

### 📈 **What I Learned**

* Database structure matters more than code early on
* Hashing + Authentication is a must for real apps
* UX improvements (like filters and bulk actions) make a huge difference
* Connecting frontend and backend taught me full-stack discipline
