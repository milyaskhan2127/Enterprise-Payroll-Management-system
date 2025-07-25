import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import pymysql
from datetime import datetime, date
from fpdf import FPDF
import bcrypt
import os
from tkcalendar import Calendar, DateEntry
from PIL import Image, ImageTk
import webbrowser

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '453814586',
    'database': 'payroll_system',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Style Configuration
STYLE_CONFIG = {
    'font_family': 'Segoe UI',
    'primary_color': "#6d59ff",
    'secondary_color': "#3729b9",
    'accent_color': '#e74c3c',
    'success_color': '#2ecc71',
    'warning_color': '#f39c12',
    'danger_color': '#e74c3c',
    'light_color': '#ecf0f1',
    'dark_color': '#2c3e50',
    'text_color': '#333333',
    'white' : '#FFFFFF',
    'login' : "#985AEA",
    'border_radius': 5,
    'padding': (10, 5)
}

class Database:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.connection = pymysql.connect(**DB_CONFIG)
        return cls._instance
    
    def get_cursor(self):
        return self.connection.cursor()
    
    def commit(self):
        self.connection.commit()
    
    def close(self):
        if self.connection:
            self.connection.close()
            Database._instance = None

class StyledButton(ttk.Button):
    def __init__(self, master=None, **kwargs):
        style_name = f"CustomButton{len(master.children)}.TButton"
        style = ttk.Style()
        style.configure(style_name, 
                      foreground=STYLE_CONFIG['login'],
                      background=STYLE_CONFIG['primary_color'],
                      font=(STYLE_CONFIG['font_family'], 10, 'bold'),
                      padding=STYLE_CONFIG['padding'],
                      borderwidth=0,
                      focusthickness=3,
                      focuscolor=STYLE_CONFIG['secondary_color'],
                      relief='flat',
                      anchor='center')
        style.map(style_name,
                 foreground=[('pressed', STYLE_CONFIG['dark_color']), ('active', STYLE_CONFIG['dark_color'])],
                 background=[('pressed', STYLE_CONFIG['secondary_color']), ('active', STYLE_CONFIG['secondary_color'])])
        
        kwargs['style'] = style_name
        super().__init__(master, **kwargs)

class StyledEntry(ttk.Entry):
    def __init__(self, master=None, **kwargs):
        style_name = f"CustomEntry{len(master.children)}.TEntry"
        style = ttk.Style()
        style.configure(style_name, 
                      foreground=STYLE_CONFIG['dark_color'],
                      background=STYLE_CONFIG['light_color'],
                      font=(STYLE_CONFIG['font_family'], 10),
                      padding=STYLE_CONFIG['padding'],
                      relief='flat',
                      bordercolor=STYLE_CONFIG['primary_color'],
                      lightcolor=STYLE_CONFIG['primary_color'],
                      darkcolor=STYLE_CONFIG['primary_color'])
        
        kwargs['style'] = style_name
        super().__init__(master, **kwargs)

class StyledLabel(ttk.Label):
    def __init__(self, master=None, **kwargs):
        style_name = f"CustomLabel{len(master.children)}.TLabel"
        style = ttk.Style()
        style.configure(style_name, 
                      foreground=STYLE_CONFIG['text_color'],
                      background=STYLE_CONFIG['light_color'],
                      font=(STYLE_CONFIG['font_family'], 10),
                      padding=STYLE_CONFIG['padding'],
                      anchor='w')
        kwargs['style'] = style_name
        super().__init__(master, **kwargs)

class StyledCombobox(ttk.Combobox):
    def __init__(self, master=None, **kwargs):
        style_name = f"CustomCombobox{len(master.children)}.TCombobox"
        style = ttk.Style()
        style.configure(style_name, 
                      foreground=STYLE_CONFIG['dark_color'],
                      background=STYLE_CONFIG['light_color'],
                      font=(STYLE_CONFIG['font_family'], 10),
                      padding=STYLE_CONFIG['padding'])
        kwargs['style'] = style_name
        super().__init__(master, **kwargs)

class StyledTreeview(ttk.Treeview):
    def __init__(self, master=None, **kwargs):
        style_name = f"CustomTreeview{len(master.children)}.Treeview"
        style = ttk.Style()
        style.configure(style_name, 
                      foreground=STYLE_CONFIG['text_color'],
                      background=STYLE_CONFIG['light_color'],
                      font=(STYLE_CONFIG['font_family'], 10),
                      rowheight=25,
                      fieldbackground=STYLE_CONFIG['light_color'])
        style.configure(f"{style_name}.Heading", 
                      foreground=STYLE_CONFIG['dark_color'],
                      background=STYLE_CONFIG['primary_color'],
                      font=(STYLE_CONFIG['font_family'], 10, 'bold'),
                      relief='flat')
        style.map(style_name,
                 background=[('selected', STYLE_CONFIG['secondary_color'])])
        kwargs['style'] = style_name
        super().__init__(master, **kwargs)

class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Payroll System - Login")
        self.root.geometry("400x310")
        self.root.resizable(False, False)
        self.root.configure(bg=STYLE_CONFIG['light_color'])
        
        self.setup_ui()
        self.center_window()
    
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding=20, style='Custom.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Style configuration
        style = ttk.Style()
        style.configure('Custom.TFrame', background=STYLE_CONFIG['light_color'])
        
        # Logo or title
        title_label = StyledLabel(main_frame, text="PAYROLL SYSTEM", font=(STYLE_CONFIG['font_family'], 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Login form
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=10)
        
        # Username
        username_label = StyledLabel(form_frame, text="Username:")
        username_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.username_entry = StyledEntry(form_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Password
        password_label = StyledLabel(form_frame, text="Password:")
        password_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.password_entry = StyledEntry(form_frame, width=25, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Login button
        login_button = StyledButton(form_frame, text="Login", command=self.authenticate)
        login_button.grid(row=2, column=0, columnspan=2, pady=10, sticky=tk.EW)

        # Register button (only shown if no admin exists)
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT COUNT(*) as count FROM admin")
        result = cursor.fetchone()
        
        if result['count'] == 0:
            register_button = StyledButton(form_frame, text="Register Admin", command=self.show_register)
            register_button.grid(row=3, column=0, columnspan=2, pady=5, sticky=tk.EW)

    
    def show_register(self):
        register_window = tk.Toplevel(self.root)
        register_window.title("Register Admin")
        register_window.geometry("400x380")
        register_window.resizable(False, False)
        register_window.configure(bg=STYLE_CONFIG['light_color'])
        
        # Center the window
        register_window.update_idletasks()
        width = register_window.winfo_width()
        height = register_window.winfo_height()
        x = (register_window.winfo_screenwidth() // 2) - (width // 2)
        y = (register_window.winfo_screenheight() // 2) - (height // 2)
        register_window.geometry(f'{width}x{height}+{x}+{y}')
        
        # Main frame
        main_frame = ttk.Frame(register_window, padding=20, style='Custom.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = StyledLabel(main_frame, text="REGISTER ADMIN", font=(STYLE_CONFIG['font_family'], 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Form frame
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(pady=10)
        
        # Full Name
        name_label = StyledLabel(form_frame, text="Full Name:")
        name_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.name_entry = StyledEntry(form_frame, width=25)
        self.name_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Email
        email_label = StyledLabel(form_frame, text="Email:")
        email_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.email_entry = StyledEntry(form_frame, width=25)
        self.email_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Username
        username_label = StyledLabel(form_frame, text="Username:")
        username_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_username_entry = StyledEntry(form_frame, width=25)
        self.new_username_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Password
        password_label = StyledLabel(form_frame, text="Password:")
        password_label.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.new_password_entry = StyledEntry(form_frame, width=25, show="*")
        self.new_password_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Confirm Password
        confirm_label = StyledLabel(form_frame, text="Confirm Password:")
        confirm_label.grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.confirm_password_entry = StyledEntry(form_frame, width=25, show="*")
        self.confirm_password_entry.grid(row=4, column=1, padx=5, pady=5)
        
        # Register button
        register_button = StyledButton(form_frame, text="Register", command=self.register_admin)
        register_button.grid(row=5, column=0, columnspan=2, pady=10, sticky=tk.EW)
    
    def register_admin(self):
        name = self.name_entry.get()
        email = self.email_entry.get()
        username = self.new_username_entry.get()
        password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        if not all([name, email, username, password, confirm_password]):
            messagebox.showerror("Error", "All fields are required!")
            return
        
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        db = Database()
        cursor = db.get_cursor()
        
        try:
            cursor.execute("INSERT INTO admin (username, password, full_name, email) VALUES (%s, %s, %s, %s)",
                          (username, hashed_password.decode('utf-8'), name, email))
            db.commit()
            messagebox.showinfo("Success", "Admin registered successfully!")
            self.root.focus_force()
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.username_entry.insert(0, username)
            self.new_username_entry.master.destroy()
        except pymysql.IntegrityError:
            messagebox.showerror("Error", "Username already exists!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to register admin: {str(e)}")
    
    def authenticate(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required!")
            return
        
        db = Database()
        cursor = db.get_cursor()
        
        try:
            cursor.execute("SELECT password FROM admin WHERE username = %s", (username,))
            result = cursor.fetchone()
            
            if result and bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                self.root.destroy()
                root = tk.Tk()
                app = PayrollSystem(root)
                root.mainloop()
            else:
                messagebox.showerror("Error", "Invalid username or password!")
        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {str(e)}")

class PayrollSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Employee Payroll System")
        self.root.geometry("1200x700")
        self.root.state('zoomed')  # Start maximized
        self.root.configure(bg=STYLE_CONFIG['light_color'])
        
        # Setup styles
        self.setup_styles()
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_employee_tab()
        self.create_attendance_tab()
        self.create_payroll_tab()
        self.create_reports_tab()
        self.create_leave_tab()
        self.create_loan_tab()
        self.create_exit_tab()
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
        # Load initial data
        self.load_initial_data()
        
        # Add menu bar
        self.create_menu_bar()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure main styles
        style.configure('.', font=(STYLE_CONFIG['font_family'], 10))
        style.configure('TNotebook', background=STYLE_CONFIG['light_color'])
        style.configure('TNotebook.Tab', 
                       padding=[15, 5], 
                       font=(STYLE_CONFIG['font_family'], 10, 'bold'),
                       background=STYLE_CONFIG['light_color'],
                       foreground=STYLE_CONFIG['dark_color'])
        style.map('TNotebook.Tab', 
                 background=[('selected', STYLE_CONFIG['primary_color'])],
                 foreground=[('selected', STYLE_CONFIG['light_color'])])
        
        # Configure frame styles
        style.configure('Custom.TFrame', background=STYLE_CONFIG['light_color'])
        style.configure('Header.TFrame', background=STYLE_CONFIG['primary_color'])
        
        # Configure label styles
        style.configure('Header.TLabel', 
                      font=(STYLE_CONFIG['font_family'], 12, 'bold'),
                      background=STYLE_CONFIG['primary_color'],
                      foreground=STYLE_CONFIG['light_color'],
                      padding=5)
        
        # Configure button styles
        style.configure('Primary.TButton', 
                      font=(STYLE_CONFIG['font_family'], 10, 'bold'),
                      foreground=STYLE_CONFIG['light_color'],
                      background=STYLE_CONFIG['primary_color'],
                      padding=STYLE_CONFIG['padding'],
                      borderwidth=0,
                      focusthickness=3,
                      focuscolor=STYLE_CONFIG['secondary_color'],
                      relief='flat')
        style.map('Primary.TButton',
                 foreground=[('pressed', STYLE_CONFIG['light_color']), ('active', STYLE_CONFIG['light_color'])],
                 background=[('pressed', STYLE_CONFIG['secondary_color']), ('active', STYLE_CONFIG['secondary_color'])])
        
        style.configure('Success.TButton', background=STYLE_CONFIG['success_color'])
        style.configure('Warning.TButton', background=STYLE_CONFIG['warning_color'])
        style.configure('Danger.TButton',
            font=(STYLE_CONFIG['font_family'], 10, 'bold'),
            foreground=STYLE_CONFIG['light_color'],
            background=STYLE_CONFIG['danger_color'],
            padding=STYLE_CONFIG['padding'],
            borderwidth=0,
            focusthickness=3,
            focuscolor=STYLE_CONFIG['secondary_color'],
            relief='flat'
        )
        style.map('Danger.TButton',
            foreground=[('pressed', STYLE_CONFIG['light_color']), ('active', STYLE_CONFIG['light_color'])],
            background=[('pressed', STYLE_CONFIG['accent_color']), ('active', STYLE_CONFIG['accent_color'])]
        )
        
        style.configure('Clear.TButton',
            font=(STYLE_CONFIG['font_family'], 10, 'bold'),
            foreground=STYLE_CONFIG['primary_color'],
            background=STYLE_CONFIG['light_color'],
            padding=STYLE_CONFIG['padding'],
            borderwidth=0,
            focusthickness=3,
            focuscolor=STYLE_CONFIG['secondary_color'],
            relief='flat'
        )
        style.map('Clear.TButton',
            foreground=[('pressed', STYLE_CONFIG['primary_color']), ('active', STYLE_CONFIG['primary_color'])],
            background=[('pressed', STYLE_CONFIG['secondary_color']), ('active', STYLE_CONFIG['secondary_color'])]
        )
        
        style.map('TEntry',
        selectbackground=[('!disabled', STYLE_CONFIG['secondary_color'])],
        selectforeground=[('!disabled', STYLE_CONFIG['light_color'])]
        )
        style.map('TCombobox',
            selectbackground=[('!disabled', STYLE_CONFIG['secondary_color'])],
            selectforeground=[('!disabled', STYLE_CONFIG['light_color'])]
        )
        
        # Configure entry styles
        style.configure('TEntry', 
                      foreground=STYLE_CONFIG['dark_color'],
                      background=STYLE_CONFIG['light_color'],
                      padding=STYLE_CONFIG['padding'],
                      relief='flat',
                      bordercolor=STYLE_CONFIG['primary_color'],
                      lightcolor=STYLE_CONFIG['primary_color'],
                      darkcolor=STYLE_CONFIG['primary_color'])
        
        # Configure combobox styles
        style.configure('TCombobox', 
                      foreground=STYLE_CONFIG['dark_color'],
                      background=STYLE_CONFIG['light_color'],
                      padding=STYLE_CONFIG['padding'],
                      relief='flat',
                      bordercolor=STYLE_CONFIG['primary_color'],
                      lightcolor=STYLE_CONFIG['primary_color'],
                      darkcolor=STYLE_CONFIG['primary_color'])
        
        # Configure treeview styles
        style.configure('Treeview', 
                      foreground=STYLE_CONFIG['text_color'],
                      background=STYLE_CONFIG['light_color'],
                      rowheight=25,
                      fieldbackground=STYLE_CONFIG['light_color'])
        style.configure('Treeview.Heading', 
                      foreground=STYLE_CONFIG['light_color'],
                      background=STYLE_CONFIG['primary_color'],
                      font=(STYLE_CONFIG['font_family'], 10, 'bold'),
                      relief='flat')
        style.map('Treeview',
                 background=[('selected', STYLE_CONFIG['secondary_color'])])
        

    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Backup Database", command=self.backup_database)
        tools_menu.add_command(label="Restore Database", command=self.restore_database)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard_tab(self):
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # Header frame
        header_frame = ttk.Frame(self.dashboard_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="PAYROLL SYSTEM DASHBOARD", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Stats frame
        stats_frame = ttk.Frame(self.dashboard_tab)
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Employee count
        emp_frame = ttk.Frame(stats_frame, style='Custom.TFrame')
        emp_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5) 
        
        emp_label = ttk.Label(emp_frame, text="Total Employees", style='Custom.TLabel', background=STYLE_CONFIG['light_color'])
        emp_label.pack(pady=5)
        self.emp_count = ttk.Label(emp_frame, text="0", font=(STYLE_CONFIG['font_family'], 24, 'bold'), background=STYLE_CONFIG['light_color'])
        self.emp_count.pack(pady=10)
        
        # Payroll count
        payroll_frame = ttk.Frame(stats_frame, style='Custom.TFrame')
        payroll_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)
        payroll_label = ttk.Label(payroll_frame, text="This Month's Payroll", style='Custom.TLabel', background=STYLE_CONFIG['light_color'])
        payroll_label.pack(pady=5)
        self.payroll_count = ttk.Label(payroll_frame, text="0", font=(STYLE_CONFIG['font_family'], 24, 'bold'), background=STYLE_CONFIG['light_color'])
        self.payroll_count.pack(pady=10)
        
        # Attendance count
        att_frame = ttk.Frame(stats_frame, style='Custom.TFrame')
        att_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)
        att_label = ttk.Label(att_frame, text="Today's Attendance", style='Custom.TLabel',background=STYLE_CONFIG['light_color'])
        att_label.pack(pady=5)
        self.att_count = ttk.Label(att_frame, text="0", font=(STYLE_CONFIG['font_family'], 24, 'bold'), background=STYLE_CONFIG['light_color'])
        self.att_count.pack(pady=10)
        
        # Leave count
        leave_frame = ttk.Frame(stats_frame, style='Custom.TFrame')
        leave_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, padx=5)
        leave_label = ttk.Label(leave_frame, text="Pending Leaves", style='Custom.TLabel', background=STYLE_CONFIG['light_color'])
        leave_label.pack(pady=5)
        self.leave_count = ttk.Label(leave_frame, text="0", font=(STYLE_CONFIG['font_family'], 24, 'bold'), background=STYLE_CONFIG['light_color'])
        self.leave_count.pack(pady=10)
        
        # Recent activity frame
        activity_frame = ttk.LabelFrame(self.dashboard_tab, text="Recent Activity", padding=10)
        activity_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ("type", "date", "details")
        self.activity_tree = StyledTreeview(activity_frame, columns=columns, show="headings")
        
        for col in columns:
            self.activity_tree.heading(col, text=col.title())
            self.activity_tree.column(col, width=150, anchor=tk.W)
        
        self.activity_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_employee_tab(self):
        # Employee Management Tab
        self.employee_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.employee_tab, text="Employee Management")
        
        # Header frame
        header_frame = ttk.Frame(self.employee_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="EMPLOYEE MANAGEMENT", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Main content frame
        content_frame = ttk.Frame(self.employee_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for form
        form_frame = ttk.LabelFrame(content_frame, text="Employee Details", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Employee form fields
        ttk.Label(form_frame, text="Employee ID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.emp_id_entry = StyledEntry(form_frame)
        self.emp_id_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Full Name:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.name_entry = StyledEntry(form_frame)
        self.name_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Department:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.department_entry = StyledEntry(form_frame)
        self.department_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Position:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.position_entry = StyledEntry(form_frame)
        self.position_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Basic Salary:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.salary_entry = StyledEntry(form_frame)
        self.salary_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Hire Date:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.hire_date_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd')
        self.hire_date_entry.grid(row=5, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Contact:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.contact_entry = StyledEntry(form_frame)
        self.contact_entry.grid(row=6, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Email:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.email_entry = StyledEntry(form_frame)
        self.email_entry.grid(row=7, column=1, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Bank Account:").grid(row=8, column=0, sticky=tk.W, pady=5)
        self.bank_entry = StyledEntry(form_frame)
        self.bank_entry.grid(row=8, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons frame
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=9, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Add Employee", style='Primary.TButton', command=self.add_employee).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Update Employee", style='Primary.TButton', command=self.update_employee).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Employee", style='Danger.TButton', command=self.delete_employee).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", style='Clear.TButton', command=self.clear_employee_form).pack(side=tk.LEFT, padx=5)
        
        # Right frame for employee list
        list_frame = ttk.LabelFrame(content_frame, text="Employee List", padding=10)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Search frame
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.emp_search_entry = StyledEntry(search_frame)
        self.emp_search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.emp_search_entry.bind('<KeyRelease>', self.search_employees)
        
        ttk.Button(search_frame, text="Search", style='Primary.TButton', command=self.search_employees).pack(side=tk.LEFT, padx=5)
        
        # Employee list treeview
        columns = ("emp_id", "name", "department", "position", "salary", "hire_date")
        self.employee_tree = StyledTreeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.employee_tree.heading(col, text=col.replace("_", " ").title())
            self.employee_tree.column(col, width=120, anchor=tk.W)
        
        self.employee_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.employee_tree.yview)
        self.employee_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind treeview select event
        self.employee_tree.bind("<<TreeviewSelect>>", self.on_employee_select)
    
    def create_attendance_tab(self):
        # Attendance Management Tab
        self.attendance_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.attendance_tab, text="Attendance Tracking")
        
        # Header frame
        header_frame = ttk.Frame(self.attendance_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="ATTENDANCE MANAGEMENT", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Main content frame
        content_frame = ttk.Frame(self.attendance_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for attendance form
        form_frame = ttk.LabelFrame(content_frame, text="Record Attendance", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Date entry
        ttk.Label(form_frame, text="Date:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.attendance_date_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd')
        self.attendance_date_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.attendance_date_entry.set_date(datetime.now())
        
        # Employee selection
        ttk.Label(form_frame, text="Employee:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.attendance_emp_var = tk.StringVar()
        self.attendance_emp_combobox = StyledCombobox(form_frame, textvariable=self.attendance_emp_var, state="readonly")
        self.attendance_emp_combobox.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Status selection
        ttk.Label(form_frame, text="Status:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.attendance_status_var = tk.StringVar()
        self.attendance_status_combobox = StyledCombobox(form_frame, textvariable=self.attendance_status_var, 
                                                       values=["Present", "Absent", "Half Day", "Leave"])
        self.attendance_status_combobox.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        self.attendance_status_combobox.set("Present")
        
        # Hours worked
        ttk.Label(form_frame, text="Hours Worked:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.hours_worked_entry = StyledEntry(form_frame)
        self.hours_worked_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        self.hours_worked_entry.insert(0, "8.0")
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.attendance_notes_entry = tk.Text(form_frame, height=4, width=25, font=(STYLE_CONFIG['font_family'], 10))
        self.attendance_notes_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Record Attendance", style='Primary.TButton', command=self.record_attendance).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Bulk Import", style='Primary.TButton', command=self.bulk_import_attendance).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", style='Clear.TButton', command=self.clear_attendance_form).pack(side=tk.LEFT, padx=5)
        
        # Right frame for attendance list
        list_frame = ttk.LabelFrame(content_frame, text="Attendance Records", padding=10)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Filter frame
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Employee:").pack(side=tk.LEFT, padx=5)
        self.filter_emp_var = tk.StringVar()
        self.filter_emp_combobox = StyledCombobox(filter_frame, textvariable=self.filter_emp_var, state="readonly")
        self.filter_emp_combobox.pack(side=tk.LEFT, padx=5)
        self.filter_emp_combobox.bind("<<ComboboxSelected>>", self.filter_attendance)
        
        ttk.Label(filter_frame, text="Filter by Month:").pack(side=tk.LEFT, padx=5)
        self.filter_month_var = tk.StringVar()
        self.filter_month_combobox = StyledCombobox(filter_frame, textvariable=self.filter_month_var, 
                                                  values=["All"] + [str(i) for i in range(1, 13)], state="readonly")
        self.filter_month_combobox.pack(side=tk.LEFT, padx=5)
        self.filter_month_combobox.set("All")
        self.filter_month_combobox.bind("<<ComboboxSelected>>", self.filter_attendance)
        
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_attendance_filters).pack(side=tk.LEFT, padx=5)
        
        # Attendance list treeview
        columns = ("id", "emp_id", "name", "date", "status", "hours", "notes")
        self.attendance_tree = StyledTreeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.attendance_tree.heading(col, text=col.replace("_", " ").title())
            self.attendance_tree.column(col, width=120, anchor=tk.W)
        
        self.attendance_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.attendance_tree.yview)
        self.attendance_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to view notes
        self.attendance_tree.bind("<Double-1>", self.view_attendance_notes)
    
    def create_payroll_tab(self):
        # Payroll Processing Tab
        self.payroll_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.payroll_tab, text="Payroll Processing")
        
        # Header frame
        header_frame = ttk.Frame(self.payroll_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="PAYROLL PROCESSING", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Main content frame
        content_frame = ttk.Frame(self.payroll_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for payroll form
        form_frame = ttk.LabelFrame(content_frame, text="Process Payroll", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Month and year selection
        ttk.Label(form_frame, text="Month:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.payroll_month_var = tk.StringVar()
        self.payroll_month_combobox = StyledCombobox(form_frame, textvariable=self.payroll_month_var, 
                                                   values=[str(i) for i in range(1, 13)], state="readonly")
        self.payroll_month_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.payroll_month_combobox.set(datetime.now().month)
        
        ttk.Label(form_frame, text="Year:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.payroll_year_var = tk.StringVar()
        self.payroll_year_combobox = StyledCombobox(form_frame, textvariable=self.payroll_year_var, 
                                                   values=[str(i) for i in range(2020, 2031)], state="readonly")
        self.payroll_year_combobox.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.payroll_year_combobox.set(datetime.now().year)
        
        # Employee selection
        ttk.Label(form_frame, text="Employee:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.payroll_emp_var = tk.StringVar()
        self.payroll_emp_combobox = StyledCombobox(form_frame, textvariable=self.payroll_emp_var, state="readonly")
        self.payroll_emp_combobox.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Calculate Payroll", style='Primary.TButton', command=self.calculate_payroll).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Process All", style='Primary.TButton', command=self.process_all_payroll).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate Payslip", style='Clear.TButton', command=self.generate_payslip).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Mark as Paid", style='Clear.TButton', command=self.mark_as_paid).pack(side=tk.LEFT, padx=5)
        
        # Right frame for payroll list
        list_frame = ttk.LabelFrame(content_frame, text="Payroll Records", padding=10)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Filter frame
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Employee:").pack(side=tk.LEFT, padx=5)
        self.payroll_filter_emp_var = tk.StringVar()
        self.payroll_filter_emp_combobox = StyledCombobox(filter_frame, textvariable=self.payroll_filter_emp_var, state="readonly")
        self.payroll_filter_emp_combobox.pack(side=tk.LEFT, padx=5)
        self.payroll_filter_emp_combobox.bind("<<ComboboxSelected>>", self.filter_payroll)
        
        ttk.Label(filter_frame, text="Filter by Month:").pack(side=tk.LEFT, padx=5)
        self.payroll_filter_month_var = tk.StringVar()
        self.payroll_filter_month_combobox = StyledCombobox(filter_frame, textvariable=self.payroll_filter_month_var, 
                                                          values=["All"] + [str(i) for i in range(1, 13)], state="readonly")
        self.payroll_filter_month_combobox.pack(side=tk.LEFT, padx=5)
        self.payroll_filter_month_combobox.set("All")
        self.payroll_filter_month_combobox.bind("<<ComboboxSelected>>", self.filter_payroll)
        
        ttk.Label(filter_frame, text="Filter by Year:").pack(side=tk.LEFT, padx=5)
        self.payroll_filter_year_var = tk.StringVar()
        self.payroll_filter_year_combobox = StyledCombobox(filter_frame, textvariable=self.payroll_filter_year_var, 
                                                         values=["All"] + [str(i) for i in range(2020, 2031)], state="readonly")
        self.payroll_filter_year_combobox.pack(side=tk.LEFT, padx=5)
        self.payroll_filter_year_combobox.set("All")
        self.payroll_filter_year_combobox.bind("<<ComboboxSelected>>", self.filter_payroll)
        
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_payroll_filters).pack(side=tk.LEFT, padx=5)
        
        # Payroll records treeview
        columns = ("id", "emp_id", "name", "month", "year", "basic", "overtime", "allowances", 
                  "deductions", "tax", "net_salary", "status")
        self.payroll_tree = StyledTreeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.payroll_tree.heading(col, text=col.replace("_", " ").title())
            self.payroll_tree.column(col, width=100, anchor=tk.W)
        
        self.payroll_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.payroll_tree.yview)
        self.payroll_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_reports_tab(self):
        # Reports Tab
        self.reports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_tab, text="Reports")
        
        # Header frame
        header_frame = ttk.Frame(self.reports_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="REPORTS", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Report selection frame
        report_frame = ttk.LabelFrame(self.reports_tab, text="Generate Reports", padding=10)
        report_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Report type selection
        ttk.Label(report_frame, text="Report Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.report_type_var = tk.StringVar()
        self.report_type_combobox = StyledCombobox(report_frame, textvariable=self.report_type_var, 
                                                 values=["Monthly Payroll Summary", 
                                                        "Employee Salary Report",
                                                        "Tax Deduction Report",
                                                        "Department-wise Salary Report",
                                                        "Attendance Summary"], state="readonly")
        self.report_type_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Month and year selection
        ttk.Label(report_frame, text="Month:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.report_month_var = tk.StringVar()
        self.report_month_combobox = StyledCombobox(report_frame, textvariable=self.report_month_var, 
                                                  values=[str(i) for i in range(1, 13)], state="readonly")
        self.report_month_combobox.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        self.report_month_combobox.set(datetime.now().month)
        
        ttk.Label(report_frame, text="Year:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.report_year_var = tk.StringVar()
        self.report_year_combobox = StyledCombobox(report_frame, textvariable=self.report_year_var, 
                                                values=[str(i) for i in range(2020, 2031)], state="readonly")
        self.report_year_combobox.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        self.report_year_combobox.set(datetime.now().year)
        
        # Generate button
        ttk.Button(report_frame, text="Generate Report", style='Primary.TButton', command=self.generate_report).grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(report_frame, text="Export to PDF", style='Clear.TButton', command=self.export_report_to_pdf).grid(row=4, column=0, columnspan=2, pady=5)
        
        # Report display area
        self.report_text = tk.Text(self.reports_tab, wrap=tk.WORD, font=('Courier', 10))
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Add these lines to properly configure the scrollbar
        scrollbar = ttk.Scrollbar(self.reports_tab, command=self.report_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.report_text.config(yscrollcommand=scrollbar.set)
    
        # Make text widget read-only by default
        self.report_text.config(state=tk.DISABLED)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.report_text)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.report_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.report_text.yview)
    
    def create_leave_tab(self):
        # Leave Management Tab
        self.leave_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.leave_tab, text="Leave Management")
        
        # Header frame
        header_frame = ttk.Frame(self.leave_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="LEAVE MANAGEMENT", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Main content frame
        content_frame = ttk.Frame(self.leave_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for leave application
        form_frame = ttk.LabelFrame(content_frame, text="Leave Application", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Employee selection
        ttk.Label(form_frame, text="Employee:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.leave_emp_var = tk.StringVar()
        self.leave_emp_combobox = StyledCombobox(form_frame, textvariable=self.leave_emp_var, state="readonly")
        self.leave_emp_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Leave type
        ttk.Label(form_frame, text="Leave Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.leave_type_var = tk.StringVar()
        self.leave_type_combobox = StyledCombobox(form_frame, textvariable=self.leave_type_var, 
                                                values=["Sick Leave", "Casual Leave", "Earned Leave", "Maternity Leave", "Paternity Leave", "Unpaid Leave"])
        self.leave_type_combobox.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Start date
        ttk.Label(form_frame, text="Start Date:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.leave_start_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd')
        self.leave_start_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # End date
        ttk.Label(form_frame, text="End Date:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.leave_end_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd')
        self.leave_end_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Reason
        ttk.Label(form_frame, text="Reason:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.leave_reason_entry = tk.Text(form_frame, height=4, width=25, font=(STYLE_CONFIG['font_family'], 10))
        self.leave_reason_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Apply Leave", style='Primary.TButton', command=self.apply_leave).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Approve Leave", style='Clear.TButton', command=self.approve_leave).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Reject Leave", style='Danger.TButton', command=self.reject_leave).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", style='Clear.TButton', command=self.clear_leave_form).pack(side=tk.LEFT, padx=5)

        # Right frame for leave list
        list_frame = ttk.LabelFrame(content_frame, text="Leave Records", padding=10)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Filter frame
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Employee:").pack(side=tk.LEFT, padx=5)
        self.leave_filter_emp_var = tk.StringVar()
        self.leave_filter_emp_combobox = StyledCombobox(filter_frame, textvariable=self.leave_filter_emp_var, state="readonly")
        self.leave_filter_emp_combobox.pack(side=tk.LEFT, padx=5)
        self.leave_filter_emp_combobox.bind("<<ComboboxSelected>>", self.filter_leaves)
        
        ttk.Label(filter_frame, text="Filter by Status:").pack(side=tk.LEFT, padx=5)
        self.leave_filter_status_var = tk.StringVar()
        self.leave_filter_status_combobox = StyledCombobox(filter_frame, textvariable=self.leave_filter_status_var, 
                                                         values=["All", "Pending", "Approved", "Rejected"], state="readonly")
        self.leave_filter_status_combobox.pack(side=tk.LEFT, padx=5)
        self.leave_filter_status_combobox.set("All")
        self.leave_filter_status_combobox.bind("<<ComboboxSelected>>", self.filter_leaves)
        
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_leave_filters).pack(side=tk.LEFT, padx=5)
        
        # Leave records treeview
        columns = ("id", "emp_id", "name", "start_date", "end_date", "leave_type", "status")
        self.leave_tree = StyledTreeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.leave_tree.heading(col, text=col.replace("_", " ").title())
            self.leave_tree.column(col, width=120, anchor=tk.W)
        
        self.leave_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.leave_tree.yview)
        self.leave_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to view reason
        self.leave_tree.bind("<Double-1>", self.view_leave_reason)
    
    def create_loan_tab(self):
        # Loan Management Tab
        self.loan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.loan_tab, text="Loan Management")
 
        # Header frame
        header_frame = ttk.Frame(self.loan_tab, style='Header.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        header_label = ttk.Label(header_frame, text="LOAN MANAGEMENT", style='Header.TLabel')
        header_label.pack(pady=5)
        
        # Main content frame
        content_frame = ttk.Frame(self.loan_tab)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left frame for loan form
        form_frame = ttk.LabelFrame(content_frame, text="Loan Management", padding=10)
        form_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        # Employee selection
        ttk.Label(form_frame, text="Employee:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.loan_emp_var = tk.StringVar()
        self.loan_emp_combobox = StyledCombobox(form_frame, textvariable=self.loan_emp_var, state="readonly")
        self.loan_emp_combobox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Loan amount
        ttk.Label(form_frame, text="Loan Amount:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.loan_amount_entry = StyledEntry(form_frame)
        self.loan_amount_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Duration (months)
        ttk.Label(form_frame, text="Duration (months):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.loan_duration_entry = StyledEntry(form_frame)
        self.loan_duration_entry.grid(row=2, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Start date
        ttk.Label(form_frame, text="Start Date:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.loan_start_entry = DateEntry(form_frame, date_pattern='yyyy-mm-dd')
        self.loan_start_entry.grid(row=3, column=1, padx=5, pady=5, sticky=tk.EW)
        self.loan_start_entry.set_date(datetime.now())
        
        # Notes
        ttk.Label(form_frame, text="Notes:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.loan_notes_entry = tk.Text(form_frame, height=4, width=25, font=(STYLE_CONFIG['font_family'], 10))
        self.loan_notes_entry.grid(row=4, column=1, padx=5, pady=5, sticky=tk.EW)
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Add Loan", style='Primary.TButton', command=self.add_loan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Mark as Completed", style='Clear.TButton', command=self.complete_loan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", style='Clear.TButton', command=self.clear_loan_form).pack(side=tk.LEFT, padx=5)

        # Right frame for loan list
        list_frame = ttk.LabelFrame(content_frame, text="Loan Records", padding=10)
        list_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Filter frame
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Employee:").pack(side=tk.LEFT, padx=5)
        self.loan_filter_emp_var = tk.StringVar()
        self.loan_filter_emp_combobox = StyledCombobox(filter_frame, textvariable=self.loan_filter_emp_var, state="readonly")
        self.loan_filter_emp_combobox.pack(side=tk.LEFT, padx=5)
        self.loan_filter_emp_combobox.bind("<<ComboboxSelected>>", self.filter_loans)
        
        ttk.Label(filter_frame, text="Filter by Status:").pack(side=tk.LEFT, padx=5)
        self.loan_filter_status_var = tk.StringVar()
        self.loan_filter_status_combobox = StyledCombobox(filter_frame, textvariable=self.loan_filter_status_var, 
                                                         values=["All", "Active", "Completed"], state="readonly")
        self.loan_filter_status_combobox.pack(side=tk.LEFT, padx=5)
        self.loan_filter_status_combobox.set("All")
        self.loan_filter_status_combobox.bind("<<ComboboxSelected>>", self.filter_loans)
        
        ttk.Button(filter_frame, text="Clear Filters", command=self.clear_loan_filters).pack(side=tk.LEFT, padx=5)
        
        # Loan records treeview
        columns = ("id", "emp_id", "name", "amount", "start_date", "duration", "monthly", "remaining", "status")
        self.loan_tree = StyledTreeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            self.loan_tree.heading(col, text=col.replace("_", " ").title())
            self.loan_tree.column(col, width=100, anchor=tk.W)
        
        self.loan_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.loan_tree.yview)
        self.loan_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind double-click event to view notes
        self.loan_tree.bind("<Double-1>", self.view_loan_details)
    
    def create_exit_tab(self):
        self.exit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.exit_tab, text="Exit")
        exit_frame = ttk.Frame(self.exit_tab)
        exit_frame.pack(expand=True)
        ttk.Label(exit_frame, text="Exit Application", font=(STYLE_CONFIG['font_family'], 14, 'bold')).pack(pady=30)
        ttk.Button(exit_frame, text="Exit", style='Clear.TButton', command=self.root.quit).pack(pady=10, ipadx=20, ipady=5)
        
    def on_tab_changed(self, event):
        selected_tab = event.widget.select()
        tab_text = event.widget.tab(selected_tab, "text")
        if tab_text == "Exit":
            self.root.quit()
    
    def load_initial_data(self):
        # Load employee names for comboboxes
        self.load_employee_names()
        self.load_filter_employee_names()
        self.load_payroll_employee_names()
        self.load_payroll_filter_employee_names()
        self.load_leave_employee_names()
        self.load_leave_filter_employee_names()
        self.load_loan_employee_names()
        self.load_loan_filter_employee_names()
        
        # Load data for treeviews
        self.load_employees()
        self.load_attendance()
        self.load_payroll()
        self.load_leaves()
        self.load_loans()
        
        # Update dashboard counts
        self.update_dashboard_counts()
    
    def update_dashboard_counts(self):
        db = Database()
        cursor = db.get_cursor()
        
        # Employee count
        cursor.execute("SELECT COUNT(*) as count FROM employees")
        self.emp_count.config(text=str(cursor.fetchone()['count']))
        
        # This month's payroll count
        current_month = datetime.now().month
        current_year = datetime.now().year
        cursor.execute("SELECT COUNT(*) as count FROM payroll WHERE month = %s AND year = %s", (current_month, current_year))
        self.payroll_count.config(text=str(cursor.fetchone()['count']))
        
        # Today's attendance count
        today = date.today().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) as count FROM attendance WHERE date = %s", (today,))
        self.att_count.config(text=str(cursor.fetchone()['count']))
        
        # Pending leaves count
        cursor.execute("SELECT COUNT(*) as count FROM leaves WHERE status = 'Pending'")
        self.leave_count.config(text=str(cursor.fetchone()['count']))
        
        # Recent activity
        self.activity_tree.delete(*self.activity_tree.get_children())
        
        # Recent payrolls
        cursor.execute("""
            SELECT 'Payroll' as type, CONCAT('Processed payroll for ', e.name, ' (', p.month, '/', p.year, ')') as details, 
                   p.created_at as date
            FROM payroll p
            JOIN employees e ON p.emp_id = e.emp_id
            ORDER BY p.created_at DESC
            LIMIT 5
        """)
        for row in cursor.fetchall():
            self.activity_tree.insert("", tk.END, values=(row['type'], row['date'].strftime('%Y-%m-%d'), row['details']))
        
        # Recent leaves
        cursor.execute("""
            SELECT 'Leave' as type, CONCAT(e.name, ' applied for ', l.leave_type, ' (', l.start_date, ' to ', l.end_date, ')') as details,
                   l.created_at as date
            FROM leaves l
            JOIN employees e ON l.emp_id = e.emp_id
            ORDER BY l.created_at DESC
            LIMIT 5
        """)
        for row in cursor.fetchall():
            self.activity_tree.insert("", tk.END, values=(row['type'], row['date'].strftime('%Y-%m-%d'), row['details']))
    
    # Database operations
    def load_employees(self):
        self.employee_tree.delete(*self.employee_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name, department, position, basic_salary, hire_date FROM employees")
        rows = cursor.fetchall()
        
        for row in rows:
            self.employee_tree.insert("", tk.END, values=(
                row['emp_id'], row['name'], row['department'], row['position'], 
                f"{row['basic_salary']:.2f}", row['hire_date']
            ))
    
    def load_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.attendance_emp_combobox['values'] = [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
    
    def load_filter_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.filter_emp_combobox['values'] = ["All"] + [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
        self.filter_emp_combobox.set("All")
    
    def load_payroll_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.payroll_emp_combobox['values'] = [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
    
    def load_payroll_filter_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.payroll_filter_emp_combobox['values'] = ["All"] + [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
        self.payroll_filter_emp_combobox.set("All")
    
    def load_leave_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.leave_emp_combobox['values'] = [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
    
    def load_leave_filter_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.leave_filter_emp_combobox['values'] = ["All"] + [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
        self.leave_filter_emp_combobox.set("All")
    
    def load_loan_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.loan_emp_combobox['values'] = [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
    
    def load_loan_filter_employee_names(self):
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id, name FROM employees ORDER BY name")
        employees = cursor.fetchall()
        self.loan_filter_emp_combobox['values'] = ["All"] + [f"{emp['emp_id']} - {emp['name']}" for emp in employees]
        self.loan_filter_emp_combobox.set("All")
    
    def load_attendance(self):
        self.attendance_tree.delete(*self.attendance_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        query = """
        SELECT a.id, a.emp_id, e.name, a.date, a.status, a.hours_worked, a.notes 
        FROM attendance a
        JOIN employees e ON a.emp_id = e.emp_id
        ORDER BY a.date DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            self.attendance_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['date'], 
                row['status'], row['hours_worked'], 
                row['notes'][:30] + "..." if row['notes'] and len(row['notes']) > 30 else row['notes']
            ))
    
    def load_payroll(self):
        self.payroll_tree.delete(*self.payroll_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        query = """
        SELECT p.id, p.emp_id, e.name, p.month, p.year, p.basic_salary, p.overtime_pay, 
               p.allowances, p.deductions, p.tax_amount, p.net_salary, p.status
        FROM payroll p
        JOIN employees e ON p.emp_id = e.emp_id
        ORDER BY p.year DESC, p.month DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            self.payroll_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['month'], row['year'], 
                f"{row['basic_salary']:.2f}", f"{row['overtime_pay']:.2f}", 
                f"{row['allowances']:.2f}", f"{row['deductions']:.2f}", 
                f"{row['tax_amount']:.2f}", f"{row['net_salary']:.2f}", 
                row['status']
            ))
    
    def load_leaves(self):
        self.leave_tree.delete(*self.leave_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        query = """
        SELECT l.id, l.emp_id, e.name, l.start_date, l.end_date, l.leave_type, l.status
        FROM leaves l
        JOIN employees e ON l.emp_id = e.emp_id
        ORDER BY l.start_date DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            self.leave_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['start_date'], 
                row['end_date'], row['leave_type'], row['status']
            ))
    
    def load_loans(self):
        self.loan_tree.delete(*self.loan_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        query = """
        SELECT l.id, l.emp_id, e.name, l.amount, l.start_date, l.duration_months, 
               l.monthly_payment, l.remaining_amount, l.status
        FROM loans l
        JOIN employees e ON l.emp_id = e.emp_id
        ORDER BY l.start_date DESC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        
        for row in rows:
            self.loan_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], 
                f"{row['amount']:.2f}", row['start_date'], row['duration_months'], 
                f"{row['monthly_payment']:.2f}", f"{row['remaining_amount']:.2f}", 
                row['status']
            ))
    
    # Employee management methods
    def add_employee(self):
        emp_id = self.emp_id_entry.get()
        name = self.name_entry.get()
        department = self.department_entry.get()
        position = self.position_entry.get()
        salary = self.salary_entry.get()
        hire_date = self.hire_date_entry.get()
        contact = self.contact_entry.get()
        email = self.email_entry.get()
        bank_account = self.bank_entry.get()
        
        if not emp_id or not name or not salary:
            messagebox.showerror("Error", "Employee ID, Name and Salary are required!")
            return
        
        try:
            salary = float(salary)
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("""
                INSERT INTO employees (emp_id, name, department, position, basic_salary, hire_date, contact, email, bank_account)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (emp_id, name, department, position, salary, hire_date, contact, email, bank_account))
            db.commit()
            messagebox.showinfo("Success", "Employee added successfully!")
            self.load_employees()
            self.load_employee_names()
            self.load_filter_employee_names()
            self.load_payroll_employee_names()
            self.load_payroll_filter_employee_names()
            self.load_leave_employee_names()
            self.load_leave_filter_employee_names()
            self.load_loan_employee_names()
            self.load_loan_filter_employee_names()
            self.clear_employee_form()
            self.update_dashboard_counts()
        except pymysql.IntegrityError:
            messagebox.showerror("Error", "Employee ID already exists!")
        except ValueError:
            messagebox.showerror("Error", "Salary must be a number!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add employee: {str(e)}")
    
    def update_employee(self):
        selected = self.employee_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an employee to update!")
            return
        
        emp_id = self.emp_id_entry.get()
        name = self.name_entry.get()
        department = self.department_entry.get()
        position = self.position_entry.get()
        salary = self.salary_entry.get()
        hire_date = self.hire_date_entry.get()
        contact = self.contact_entry.get()
        email = self.email_entry.get()
        bank_account = self.bank_entry.get()
        
        if not emp_id or not name or not salary:
            messagebox.showerror("Error", "Employee ID, Name and Salary are required!")
            return
        
        try:
            salary = float(salary)
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("""
                UPDATE employees 
                SET name=%s, department=%s, position=%s, basic_salary=%s, hire_date=%s, contact=%s, email=%s, bank_account=%s
                WHERE emp_id=%s
            """, (name, department, position, salary, hire_date, contact, email, bank_account, emp_id))
            db.commit()
            messagebox.showinfo("Success", "Employee updated successfully!")
            self.load_employees()
            self.load_employee_names()
            self.load_filter_employee_names()
            self.load_payroll_employee_names()
            self.load_payroll_filter_employee_names()
            self.load_leave_employee_names()
            self.load_leave_filter_employee_names()
            self.load_loan_employee_names()
            self.load_loan_filter_employee_names()
            self.update_dashboard_counts()
        except ValueError:
            messagebox.showerror("Error", "Salary must be a number!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update employee: {str(e)}")
    
    def delete_employee(self):
        selected = self.employee_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select an employee to delete!")
            return
        
        emp_id = self.employee_tree.item(selected)['values'][0]
        
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this employee? This will also delete all related records."):
            try:
                db = Database()
                cursor = db.get_cursor()
                
                # Delete related records first (due to foreign key constraints)
                cursor.execute("DELETE FROM attendance WHERE emp_id=%s", (emp_id,))
                cursor.execute("DELETE FROM leaves WHERE emp_id=%s", (emp_id,))
                cursor.execute("DELETE FROM payroll WHERE emp_id=%s", (emp_id,))
                cursor.execute("DELETE FROM loans WHERE emp_id=%s", (emp_id,))
                
                # Then delete the employee
                cursor.execute("DELETE FROM employees WHERE emp_id=%s", (emp_id,))
                db.commit()
                
                messagebox.showinfo("Success", "Employee deleted successfully!")
                self.load_employees()
                self.load_employee_names()
                self.load_filter_employee_names()
                self.load_payroll_employee_names()
                self.load_payroll_filter_employee_names()
                self.load_leave_employee_names()
                self.load_leave_filter_employee_names()
                self.load_loan_employee_names()
                self.load_loan_filter_employee_names()
                self.clear_employee_form()
                self.update_dashboard_counts()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete employee: {str(e)}")
    
    def clear_employee_form(self):
        self.emp_id_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.department_entry.delete(0, tk.END)
        self.position_entry.delete(0, tk.END)
        self.salary_entry.delete(0, tk.END)
        self.hire_date_entry.set_date(datetime.now())
        self.contact_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
        self.bank_entry.delete(0, tk.END)
    
    def on_employee_select(self, event):
        selected = self.employee_tree.selection()
        if not selected:
            return
        
        values = self.employee_tree.item(selected)['values']
        self.clear_employee_form()
        
        self.emp_id_entry.insert(0, values[0])
        self.name_entry.insert(0, values[1])
        self.department_entry.insert(0, values[2])
        self.position_entry.insert(0, values[3])
        self.salary_entry.insert(0, values[4])
        self.hire_date_entry.set_date(datetime.strptime(values[5], '%Y-%m-%d'))
        
        # Get additional details from database
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT contact, email, bank_account FROM employees WHERE emp_id=%s", (values[0],))
        details = cursor.fetchone()
        
        if details:
            self.contact_entry.insert(0, details['contact'] if details['contact'] else "")
            self.email_entry.insert(0, details['email'] if details['email'] else "")
            self.bank_entry.insert(0, details['bank_account'] if details['bank_account'] else "")
    
    def search_employees(self, event=None):
        search_term = self.emp_search_entry.get()
        
        self.employee_tree.delete(*self.employee_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        
        query = """
        SELECT emp_id, name, department, position, basic_salary, hire_date 
        FROM employees
        WHERE emp_id LIKE %s OR name LIKE %s OR department LIKE %s OR position LIKE %s
        """
        params = (f"%{search_term}%", f"%{search_term}%", f"%{search_term}%", f"%{search_term}%")
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        for row in rows:
            self.employee_tree.insert("", tk.END, values=(
                row['emp_id'], row['name'], row['department'], row['position'], 
                f"{row['basic_salary']:.2f}", row['hire_date']
            ))
    
    # Attendance management methods
    def record_attendance(self):
        emp_str = self.attendance_emp_var.get()
        if not emp_str:
            messagebox.showerror("Error", "Please select an employee!")
            return
        
        emp_id = emp_str.split(" - ")[0]
        date = self.attendance_date_entry.get()
        status = self.attendance_status_var.get()
        hours_worked = self.hours_worked_entry.get()
        notes = self.attendance_notes_entry.get("1.0", tk.END).strip()
        
        if not date or not status:
            messagebox.showerror("Error", "Date and Status are required!")
            return
        
        try:
            hours_worked = float(hours_worked) if hours_worked else 0.0
            db = Database()
            cursor = db.get_cursor()
            
            # Check if attendance already recorded for this employee on this date
            cursor.execute("SELECT id FROM attendance WHERE emp_id=%s AND date=%s", (emp_id, date))
            if cursor.fetchone():
                if not messagebox.askyesno("Confirm", "Attendance already recorded for this employee on this date. Update it?"):
                    return
                
                cursor.execute("""
                    UPDATE attendance 
                    SET status=%s, hours_worked=%s, notes=%s
                    WHERE emp_id=%s AND date=%s
                """, (status, hours_worked, notes, emp_id, date))
            else:
                cursor.execute("""
                    INSERT INTO attendance (emp_id, date, status, hours_worked, notes)
                    VALUES (%s, %s, %s, %s, %s)
                """, (emp_id, date, status, hours_worked, notes))
            
            db.commit()
            messagebox.showinfo("Success", "Attendance recorded successfully!")
            self.load_attendance()
            self.update_dashboard_counts()
        except ValueError:
            messagebox.showerror("Error", "Hours worked must be a number!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to record attendance: {str(e)}")
    
    def bulk_import_attendance(self):
        # Ask for date
        date = self.attendance_date_entry.get()
        if not date:
            messagebox.showerror("Error", "Please enter a date!")
            return
        
        # Ask for default status and hours
        default_status = simpledialog.askstring("Default Status", "Enter default status (Present/Absent/Half Day/Leave):", 
                                              initialvalue="Present")
        if not default_status or default_status not in ["Present", "Absent", "Half Day", "Leave"]:
            return
        
        default_hours = simpledialog.askfloat("Default Hours", "Enter default hours worked:", initialvalue=8.0)
        if default_hours is None:
            return
        
        # Get all employees
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT emp_id FROM employees")
        employees = cursor.fetchall()
        
        if not employees:
            messagebox.showerror("Error", "No employees found!")
            return
        
        # Record default attendance for all employees
        count = 0
        for emp in employees:
            emp_id = emp['emp_id']
            try:
                # Check if attendance already exists
                cursor.execute("SELECT id FROM attendance WHERE emp_id=%s AND date=%s", (emp_id, date))
                if cursor.fetchone():
                    continue  # Skip if already exists
                
                cursor.execute("""
                    INSERT INTO attendance (emp_id, date, status, hours_worked)
                    VALUES (%s, %s, %s, %s)
                """, (emp_id, date, default_status, default_hours))
                count += 1
            except Exception:
                continue
        
        db.commit()
        messagebox.showinfo("Success", f"Attendance recorded for {count} employees!")
        self.load_attendance()
        self.update_dashboard_counts()
    
    def view_attendance_notes(self, event):
        selected = self.attendance_tree.selection()
        if not selected:
            return
        
        att_id = self.attendance_tree.item(selected)['values'][0]
        
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT notes FROM attendance WHERE id=%s", (att_id,))
        result = cursor.fetchone()
        
        notes = result['notes'] if result and result['notes'] else "No notes available"
        
        # Create a dialog to show the notes
        dialog = tk.Toplevel(self.root)
        dialog.title("Attendance Notes")
        dialog.geometry("500x300")
        
        text = tk.Text(dialog, wrap=tk.WORD, font=(STYLE_CONFIG['font_family'], 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, notes)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def filter_attendance(self, event=None):
        emp_filter = self.filter_emp_var.get()
        month_filter = self.filter_month_var.get()
        
        query = """
        SELECT a.id, a.emp_id, e.name, a.date, a.status, a.hours_worked, a.notes 
        FROM attendance a
        JOIN employees e ON a.emp_id = e.emp_id
        WHERE 1=1
        """
        
        params = []
        
        if emp_filter != "All":
            emp_id = emp_filter.split(" - ")[0]
            query += " AND a.emp_id = %s"
            params.append(emp_id)
        
        if month_filter != "All":
            query += " AND MONTH(a.date) = %s"
            params.append(int(month_filter))
        
        query += " ORDER BY a.date DESC"
        
        self.attendance_tree.delete(*self.attendance_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        for row in rows:
            self.attendance_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['date'], 
                row['status'], row['hours_worked'], 
                row['notes'][:30] + "..." if row['notes'] and len(row['notes']) > 30 else row['notes']
            ))
    
    def clear_attendance_filters(self):
        self.filter_emp_var.set("All")
        self.filter_month_var.set("All")
        self.load_attendance()
    
    def clear_attendance_form(self):
        self.attendance_emp_var.set('')
        self.attendance_date_entry.set_date(datetime.now())
        self.attendance_status_var.set("Present")
        self.hours_worked_entry.delete(0, tk.END)
        self.hours_worked_entry.insert(0, "8.0")
        self.attendance_notes_entry.delete("1.0", tk.END)
    
    # Payroll processing methods
    def calculate_payroll(self):
        emp_str = self.payroll_emp_var.get()
        if not emp_str:
            messagebox.showerror("Error", "Please select an employee!")
            return
        
        emp_id = emp_str.split(" - ")[0]
        month = self.payroll_month_var.get()
        year = self.payroll_year_var.get()
        
        if not month or not year:
            messagebox.showerror("Error", "Month and Year are required!")
            return
        
        try:
            month = int(month)
            year = int(year)
            
            # Check if payroll already processed for this employee/month/year
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("SELECT id FROM payroll WHERE emp_id=%s AND month=%s AND year=%s", (emp_id, month, year))
            if cursor.fetchone():
                if not messagebox.askyesno("Confirm", "Payroll already processed for this period. Update it?"):
                    return
            
            # Get employee basic salary
            cursor.execute("SELECT basic_salary FROM employees WHERE emp_id=%s", (emp_id,))
            result = cursor.fetchone()
            if not result:
                messagebox.showerror("Error", "Employee not found!")
                return
            
            basic_salary = float(result['basic_salary'])
            
            # Calculate overtime (assuming overtime is paid at 1.5x hourly rate)
            # First get hourly rate (assuming 8 hours/day and 22 days/month)
            hourly_rate = basic_salary / (8 * 22)
            
            # Get total overtime hours for the month
            query = """
            SELECT SUM(hours_worked - 8) 
            FROM attendance 
            WHERE emp_id=%s 
            AND MONTH(date) = %s 
            AND YEAR(date) = %s
            AND hours_worked > 8
            AND status != 'Leave'
            """
            params = (emp_id, month, year)
            cursor.execute(query, params)
            overtime_hours = cursor.fetchone()['SUM(hours_worked - 8)'] or 0.0
            overtime_pay = overtime_hours * hourly_rate * 1.5
            
            # Calculate absence deductions (only for more than 5 absences)
            query = """
            SELECT COUNT(*) 
            FROM attendance 
            WHERE emp_id=%s 
            AND MONTH(date) = %s 
            AND YEAR(date) = %s
            AND status = 'Absent'
            """
            cursor.execute(query, params)
            absences = cursor.fetchone()['COUNT(*)'] or 0
            
            absence_deduction = 0.0
            if absences > 5:
                daily_rate = basic_salary / 22
                absence_deduction = (absences - 5) * daily_rate * 0.10  # Deduct 10% of daily rate per absence over 5
            
            # Calculate tax (simplified tax calculation)
            gross_salary = basic_salary + overtime_pay
            tax_amount = self.calculate_tax(gross_salary)
            
            # Calculate allowances (fixed 10% of basic salary for this example)
            allowances = basic_salary * 0.10
            
            # Calculate loan deductions
            cursor.execute("SELECT monthly_payment FROM loans WHERE emp_id=%s AND status='Active'", (emp_id,))
            loans = cursor.fetchall()
            loan_deductions = sum(loan['monthly_payment'] for loan in loans) if loans else 0.0
            
            # Calculate total deductions
            total_deductions = absence_deduction + loan_deductions + tax_amount
            
            # Calculate net salary
            net_salary = gross_salary + allowances - total_deductions
            
            # Insert or update payroll record
            cursor.execute("""
                INSERT INTO payroll 
                (emp_id, month, year, basic_salary, overtime_pay, allowances, deductions, tax_amount, net_salary, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pending')
                ON DUPLICATE KEY UPDATE
                basic_salary=%s, overtime_pay=%s, allowances=%s, deductions=%s, tax_amount=%s, net_salary=%s, status='Pending'
            """, (
                emp_id, month, year, basic_salary, overtime_pay, allowances, total_deductions, tax_amount, net_salary,
                basic_salary, overtime_pay, allowances, total_deductions, tax_amount, net_salary
            ))
            
            db.commit()
            messagebox.showinfo("Success", "Payroll calculated successfully!")
            self.load_payroll()
            self.update_dashboard_counts()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to calculate payroll: {str(e)}")
    
    def calculate_tax(self, gross_salary):
        # Simplified tax calculation based on slabs
        if gross_salary <= 250000:  # 0% tax
            return 0
        elif gross_salary <= 500000:  # 5% on amount above 250k
            return (gross_salary - 250000) * 0.05
        elif gross_salary <= 1000000:  # 10% on amount above 500k + 12,500
            return (gross_salary - 500000) * 0.10 + 12500
        else:  # 20% on amount above 1M + 62,500
            return (gross_salary - 1000000) * 0.20 + 62500
    
    def process_all_payroll(self):
        month = self.payroll_month_var.get()
        year = self.payroll_year_var.get()
        
        if not month or not year:
            messagebox.showerror("Error", "Month and Year are required!")
            return
        
        try:
            month = int(month)
            year = int(year)
            
            # Get all employees
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("SELECT emp_id FROM employees")
            employees = cursor.fetchall()
            
            if not employees:
                messagebox.showerror("Error", "No employees found!")
                return
            
            # Process payroll for each employee
            count = 0
            for emp in employees:
                emp_id = emp['emp_id']
                
                # Skip if payroll already processed
                cursor.execute("SELECT id FROM payroll WHERE emp_id=%s AND month=%s AND year=%s", (emp_id, month, year))
                if cursor.fetchone():
                    continue
                
                # Calculate payroll (similar to calculate_payroll method)
                cursor.execute("SELECT basic_salary FROM employees WHERE emp_id=%s", (emp_id,))
                result = cursor.fetchone()
                if not result:
                    continue
                
                basic_salary = float(result['basic_salary'])
                
                hourly_rate = basic_salary / (8 * 22)
                
                query = """
                SELECT SUM(hours_worked - 8) 
                FROM attendance 
                WHERE emp_id=%s 
                AND MONTH(date) = %s 
                AND YEAR(date) = %s
                AND hours_worked > 8
                AND status != 'Leave'
                """
                params = (emp_id, month, year)
                cursor.execute(query, params)
                overtime_hours = cursor.fetchone()['SUM(hours_worked - 8)'] or 0.0
                overtime_pay = overtime_hours * hourly_rate * 1.5
                
                query = """
                SELECT COUNT(*) 
                FROM attendance 
                WHERE emp_id=%s 
                AND MONTH(date) = %s 
                AND YEAR(date) = %s
                AND status = 'Absent'
                """
                cursor.execute(query, params)
                absences = cursor.fetchone()['COUNT(*)'] or 0
                
                absence_deduction = 0.0
                if absences > 5:
                    daily_rate = basic_salary / 22
                    absence_deduction = (absences - 5) * daily_rate * 0.10
                
                gross_salary = basic_salary + overtime_pay
                tax_amount = self.calculate_tax(gross_salary)
                
                allowances = basic_salary * 0.10
                
                cursor.execute("SELECT monthly_payment FROM loans WHERE emp_id=%s AND status='Active'", (emp_id,))
                loans = cursor.fetchall()
                loan_deductions = sum(loan['monthly_payment'] for loan in loans) if loans else 0.0
                
                total_deductions = absence_deduction + loan_deductions + tax_amount
                net_salary = gross_salary + allowances - total_deductions
                
                cursor.execute("""
                    INSERT INTO payroll 
                    (emp_id, month, year, basic_salary, overtime_pay, allowances, deductions, tax_amount, net_salary, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'Pending')
                """, (emp_id, month, year, basic_salary, overtime_pay, allowances, total_deductions, tax_amount, net_salary))
                
                count += 1
            
            db.commit()
            messagebox.showinfo("Success", f"Payroll processed for {count} employees!")
            self.load_payroll()
            self.update_dashboard_counts()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process payroll: {str(e)}")
    
    def mark_as_paid(self):
        selected = self.payroll_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a payroll record to mark as paid!")
            return
        
        payroll_id = self.payroll_tree.item(selected)['values'][0]
        
        try:
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("UPDATE payroll SET status='Paid', payment_date=CURDATE() WHERE id=%s", (payroll_id,))
            db.commit()
            messagebox.showinfo("Success", "Payroll marked as paid successfully!")
            self.load_payroll()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to mark payroll as paid: {str(e)}")
    
    def generate_payslip(self):
        selected = self.payroll_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a payroll record to generate payslip!")
            return
        
        payroll_id = self.payroll_tree.item(selected)['values'][0]
        
        # Get payroll details
        db = Database()
        cursor = db.get_cursor()
        query = """
        SELECT p.emp_id, e.name, p.month, p.year, p.basic_salary, p.overtime_pay, 
               p.allowances, p.deductions, p.tax_amount, p.net_salary, e.position, e.department,
               e.bank_account, e.contact, e.email
        FROM payroll p
        JOIN employees e ON p.emp_id = e.emp_id
        WHERE p.id = %s
        """
        cursor.execute(query, (payroll_id,))
        payroll_data = cursor.fetchone()
        
        if not payroll_data:
            messagebox.showerror("Error", "Payroll record not found!")
            return
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        
        # Company header
        pdf.set_font("Arial", 'B', 16)
        pdf.cell(200, 10, txt="ABC Company", ln=1, align='C')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="123 Business Street, City", ln=1, align='C')
        pdf.cell(200, 10, txt="Payslip", ln=1, align='C')
        pdf.ln(10)
        
        # Pay period
        month_name = datetime.strptime(str(payroll_data['month']), "%m").strftime("%B")
        pdf.cell(200, 10, txt=f"Pay Period: {month_name} {payroll_data['year']}", ln=1, align='C')
        pdf.ln(10)
        
        # Employee details
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Employee Details", ln=1)
        pdf.set_font("Arial", size=12)
        
        pdf.cell(50, 10, txt="Employee ID:", ln=0)
        pdf.cell(50, 10, txt=payroll_data['emp_id'], ln=1)
        
        pdf.cell(50, 10, txt="Name:", ln=0)
        pdf.cell(50, 10, txt=payroll_data['name'], ln=1)
        
        pdf.cell(50, 10, txt="Department:", ln=0)
        pdf.cell(50, 10, txt=payroll_data['department'], ln=1)
        
        pdf.cell(50, 10, txt="Position:", ln=0)
        pdf.cell(50, 10, txt=payroll_data['position'], ln=1)
        
        pdf.cell(50, 10, txt="Bank Account:", ln=0)
        pdf.cell(50, 10, txt=payroll_data['bank_account'] if payroll_data['bank_account'] else "N/A", ln=1)
        pdf.ln(10)
        
        # Earnings
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Earnings", ln=1)
        pdf.set_font("Arial", size=12)
        
        pdf.cell(100, 10, txt="Basic Salary", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['basic_salary']:.2f}", ln=1)
        
        pdf.cell(100, 10, txt="Overtime Pay", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['overtime_pay']:.2f}", ln=1)
        
        pdf.cell(100, 10, txt="Allowances", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['allowances']:.2f}", ln=1)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(100, 10, txt="Total Earnings", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['basic_salary'] + payroll_data['overtime_pay'] + payroll_data['allowances']:.2f}", ln=1)
        pdf.ln(10)
        
        # Deductions
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(200, 10, txt="Deductions", ln=1)
        pdf.set_font("Arial", size=12)
        
        pdf.cell(100, 10, txt="Tax", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['tax_amount']:.2f}", ln=1)
        
        pdf.cell(100, 10, txt="Other Deductions", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['deductions'] - payroll_data['tax_amount']:.2f}", ln=1)
        
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(100, 10, txt="Total Deductions", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['deductions']:.2f}", ln=1)
        pdf.ln(10)
        
        # Net Salary
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(100, 10, txt="Net Salary", ln=0)
        pdf.cell(50, 10, txt=f"${payroll_data['net_salary']:.2f}", ln=1)
        
        # Payment details
        pdf.ln(15)
        pdf.set_font("Arial", 'I', 10)
        pdf.cell(200, 10, txt="Payment will be processed within 3 working days", ln=1, align='C')
        
        # Save PDF
        filename = f"payslip_{payroll_data['emp_id']}_{payroll_data['month']}_{payroll_data['year']}.pdf"
        pdf.output(filename)
        
        messagebox.showinfo("Success", f"Payslip generated as {filename}")
        webbrowser.open(filename)
    
    def filter_payroll(self, event=None):
        emp_filter = self.payroll_filter_emp_var.get()
        month_filter = self.payroll_filter_month_var.get()
        year_filter = self.payroll_filter_year_var.get()
        
        query = """
        SELECT p.id, p.emp_id, e.name, p.month, p.year, p.basic_salary, p.overtime_pay, 
               p.allowances, p.deductions, p.tax_amount, p.net_salary, p.status
        FROM payroll p
        JOIN employees e ON p.emp_id = e.emp_id
        WHERE 1=1
        """
        
        params = []
        
        if emp_filter != "All":
            emp_id = emp_filter.split(" - ")[0]
            query += " AND p.emp_id = %s"
            params.append(emp_id)
        
        if month_filter != "All":
            query += " AND p.month = %s"
            params.append(int(month_filter))
        
        if year_filter != "All":
            query += " AND p.year = %s"
            params.append(int(year_filter))
        
        query += " ORDER BY p.year DESC, p.month DESC"
        
        self.payroll_tree.delete(*self.payroll_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        for row in rows:
            self.payroll_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['month'], row['year'], 
                f"{row['basic_salary']:.2f}", f"{row['overtime_pay']:.2f}", 
                f"{row['allowances']:.2f}", f"{row['deductions']:.2f}", 
                f"{row['tax_amount']:.2f}", f"{row['net_salary']:.2f}", 
                row['status']
            ))
    
    def clear_payroll_filters(self):
        self.payroll_filter_emp_var.set("All")
        self.payroll_filter_month_var.set("All")
        self.payroll_filter_year_var.set("All")
        self.load_payroll()
    
    # Leave management methods
    def apply_leave(self):
        emp_str = self.leave_emp_var.get()
        if not emp_str:
            messagebox.showerror("Error", "Please select an employee!")
            return
        
        emp_id = emp_str.split(" - ")[0]
        leave_type = self.leave_type_var.get()
        start_date = self.leave_start_entry.get()
        end_date = self.leave_end_entry.get()
        reason = self.leave_reason_entry.get("1.0", tk.END).strip()
        
        if not leave_type or not start_date or not end_date:
            messagebox.showerror("Error", "Leave type, start date and end date are required!")
            return
        
        try:
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("""
                INSERT INTO leaves (emp_id, start_date, end_date, leave_type, status, reason)
                VALUES (%s, %s, %s, %s, 'Pending', %s)
            """, (emp_id, start_date, end_date, leave_type, reason))
            
            db.commit()
            messagebox.showinfo("Success", "Leave application submitted successfully!")
            self.load_leaves()
            self.update_dashboard_counts()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to apply leave: {str(e)}")
    
    def approve_leave(self):
        selected = self.leave_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a leave application to approve!")
            return
        
        leave_id = self.leave_tree.item(selected)['values'][0]
        
        try:
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("UPDATE leaves SET status='Approved' WHERE id=%s", (leave_id,))
            db.commit()
            messagebox.showinfo("Success", "Leave approved successfully!")
            self.load_leaves()
            self.update_dashboard_counts()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to approve leave: {str(e)}")
    
    def reject_leave(self):
        selected = self.leave_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a leave application to reject!")
            return
        
        leave_id = self.leave_tree.item(selected)['values'][0]
        
        try:
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("UPDATE leaves SET status='Rejected' WHERE id=%s", (leave_id,))
            db.commit()
            messagebox.showinfo("Success", "Leave rejected successfully!")
            self.load_leaves()
            self.update_dashboard_counts()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reject leave: {str(e)}")
    
    def view_leave_reason(self, event):
        selected = self.leave_tree.selection()
        if not selected:
            return
        
        leave_id = self.leave_tree.item(selected)['values'][0]
        
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT reason FROM leaves WHERE id=%s", (leave_id,))
        result = cursor.fetchone()
        
        reason = result['reason'] if result and result['reason'] else "No reason provided"
        
        # Create a dialog to show the reason
        dialog = tk.Toplevel(self.root)
        dialog.title("Leave Reason")
        dialog.geometry("500x300")
        
        text = tk.Text(dialog, wrap=tk.WORD, font=(STYLE_CONFIG['font_family'], 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, reason)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def filter_leaves(self, event=None):
        emp_filter = self.leave_filter_emp_var.get()
        status_filter = self.leave_filter_status_var.get()
        
        query = """
        SELECT l.id, l.emp_id, e.name, l.start_date, l.end_date, l.leave_type, l.status
        FROM leaves l
        JOIN employees e ON l.emp_id = e.emp_id
        WHERE 1=1
        """
        
        params = []
        
        if emp_filter != "All":
            emp_id = emp_filter.split(" - ")[0]
            query += " AND l.emp_id = %s"
            params.append(emp_id)
        
        if status_filter != "All":
            query += " AND l.status = %s"
            params.append(status_filter)
        
        query += " ORDER BY l.start_date DESC"
        
        self.leave_tree.delete(*self.leave_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        for row in rows:
            self.leave_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], row['start_date'], 
                row['end_date'], row['leave_type'], row['status']
            ))
    
    def clear_leave_filters(self):
        self.leave_filter_emp_var.set("All")
        self.leave_filter_status_var.set("All")
        self.load_leaves()
    
    def clear_leave_form(self):
        self.leave_emp_var.set('')
        self.leave_type_var.set('')
        self.leave_start_entry.set_date(datetime.now())
        self.leave_end_entry.set_date(datetime.now())
        self.leave_reason_entry.delete("1.0", tk.END)
    
    # Loan management methods
    def add_loan(self):
        emp_str = self.loan_emp_var.get()
        if not emp_str:
            messagebox.showerror("Error", "Please select an employee!")
            return
        
        emp_id = emp_str.split(" - ")[0]
        amount = self.loan_amount_entry.get()
        duration = self.loan_duration_entry.get()
        start_date = self.loan_start_entry.get()
        notes = self.loan_notes_entry.get("1.0", tk.END).strip()
        
        if not amount or not duration or not start_date:
            messagebox.showerror("Error", "Amount, duration and start date are required!")
            return
        
        try:
            amount = float(amount)
            duration = int(duration)
            
            if amount <= 0 or duration <= 0:
                messagebox.showerror("Error", "Amount and duration must be positive numbers!")
                return
            
            monthly_payment = amount / duration;
            
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("""
                INSERT INTO loans (emp_id, amount, start_date, duration_months, monthly_payment, remaining_amount, status, notes)
                VALUES (%s, %s, %s, %s, %s, %s, 'Active', %s)
            """, (emp_id, amount, start_date, duration, monthly_payment, amount, notes))
            
            db.commit()
            messagebox.showinfo("Success", "Loan added successfully!")
            self.load_loans()
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numbers!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add loan: {str(e)}")
    
    def complete_loan(self):
        selected = self.loan_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Please select a loan to mark as completed!")
            return
        
        loan_id = self.loan_tree.item(selected)['values'][0]
        
        try:
            db = Database()
            cursor = db.get_cursor()
            cursor.execute("UPDATE loans SET status='Completed', remaining_amount=0 WHERE id=%s", (loan_id,))
            db.commit()
            messagebox.showinfo("Success", "Loan marked as completed successfully!")
            self.load_loans()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to complete loan: {str(e)}")
    
    def view_loan_details(self, event):
        selected = self.loan_tree.selection()
        if not selected:
            return
        
        loan_id = self.loan_tree.item(selected)['values'][0]
        
        db = Database()
        cursor = db.get_cursor()
        cursor.execute("SELECT notes FROM loans WHERE id=%s", (loan_id,))
        result = cursor.fetchone()
        
        notes = result['notes'] if result and result['notes'] else "No notes available"
        
        # Create a dialog to show the notes
        dialog = tk.Toplevel(self.root)
        dialog.title("Loan Details")
        dialog.geometry("500x300")
        
        text = tk.Text(dialog, wrap=tk.WORD, font=(STYLE_CONFIG['font_family'], 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, notes)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def filter_loans(self, event=None):
        emp_filter = self.loan_filter_emp_var.get()
        status_filter = self.loan_filter_status_var.get()
        
        query = """
        SELECT l.id, l.emp_id, e.name, l.amount, l.start_date, l.duration_months, 
               l.monthly_payment, l.remaining_amount, l.status
        FROM loans l
        JOIN employees e ON l.emp_id = e.emp_id
        WHERE 1=1
        """
        
        params = []
        
        if emp_filter != "All":
            emp_id = emp_filter.split(" - ")[0]
            query += " AND l.emp_id = %s"
            params.append(emp_id)
        
        if status_filter != "All":
            query += " AND l.status = %s"
            params.append(status_filter)
        
        query += " ORDER BY l.start_date DESC"
        
        self.loan_tree.delete(*self.loan_tree.get_children())
        db = Database()
        cursor = db.get_cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        for row in rows:
            self.loan_tree.insert("", tk.END, values=(
                row['id'], row['emp_id'], row['name'], 
                f"{row['amount']:.2f}", row['start_date'], row['duration_months'], 
                f"{row['monthly_payment']:.2f}", f"{row['remaining_amount']:.2f}", 
                row['status']
            ))
    
    def clear_loan_filters(self):
        self.loan_filter_emp_var.set("All")
        self.loan_filter_status_var.set("All")
        self.load_loans()
    
    def clear_loan_form(self):
        self.loan_emp_var.set('')
        self.loan_amount_entry.delete(0, tk.END)
        self.loan_duration_entry.delete(0, tk.END)
        self.loan_start_entry.set_date(datetime.now())
        self.loan_notes_entry.delete("1.0", tk.END)
    
    # Report generation methods
    def generate_report(self):
        try:
            report_type = self.report_type_var.get()
            month = self.report_month_var.get()
            year = self.report_year_var.get()
            
            if not report_type:
                messagebox.showerror("Error", "Please select a report type!")
                return
            
            if not month or not year:
                messagebox.showerror("Error", "Please select both month and year!")
                return
            
            # Clear the report text widget
            self.report_text.config(state=tk.NORMAL)  # Enable editing
            self.report_text.delete(1.0, tk.END)
            
            try:
                month = int(month)
                year = int(year)
                
                if report_type == "Monthly Payroll Summary":
                    self.generate_monthly_payroll_report(month, year)
                elif report_type == "Employee Salary Report":
                    self.generate_employee_salary_report()
                elif report_type == "Tax Deduction Report":
                    self.generate_tax_report(month, year)
                elif report_type == "Department-wise Salary Report":
                    self.generate_department_report(month, year)
                elif report_type == "Attendance Summary":
                    self.generate_attendance_report(month, year)
                else:
                    messagebox.showerror("Error", "Invalid report type selected!")
            except ValueError:
                messagebox.showerror("Error", "Month and Year must be numbers!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {str(e)}")
        finally:
            self.report_text.config(state=tk.DISABLED)  # Disable editing
    
    def export_report_to_pdf(self):
        report_text = self.report_text.get("1.0", tk.END)
        if not report_text.strip():
            messagebox.showerror("Error", "No report to export!")
            return
        
        # Ask for filename
        filename = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF Files", "*.pdf")],
            title="Save Report As"
        )
        
        if not filename:
            return
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        
        # Add report text
        for line in report_text.split('\n'):
            pdf.cell(0, 5, txt=line, ln=1)
        
        # Save PDF
        pdf.output(filename)
        messagebox.showinfo("Success", f"Report exported to {filename}")
        webbrowser.open(filename)
    
    def generate_monthly_payroll_report(self, month, year):
        try:
            print(f"Generating monthly payroll report for {month}/{year}")  # Debug
            
            db = Database()
            cursor = db.get_cursor()
            
            query = """
            SELECT e.department, COUNT(p.id) as employees, SUM(p.basic_salary) as basic_salary, 
                SUM(p.overtime_pay) as overtime_pay, SUM(p.allowances) as allowances, 
                SUM(p.deductions) as deductions, SUM(p.tax_amount) as tax_amount, 
                SUM(p.net_salary) as net_salary
            FROM payroll p
            JOIN employees e ON p.emp_id = e.emp_id
            WHERE p.month = %s AND p.year = %s
            GROUP BY e.department
            """
            
            print(f"Executing query: {query}")  # Debug
            cursor.execute(query, (month, year))
            results = cursor.fetchall()
            print(f"Query returned {len(results)} rows")  # Debug
            
            month_name = datetime.strptime(str(month), "%m").strftime("%B")
            self.report_text.insert(tk.END, f"Monthly Payroll Summary - {month_name} {year}\n\n")
            self.report_text.insert(tk.END, "Department           Employees  Basic Salary  Overtime  Allowances  Deductions  Tax       Net Salary\n")
            self.report_text.insert(tk.END, "-"*100 + "\n")
            
            for row in results:
                line = f"{row['department']:<20} {row['employees']:>10} {row['basic_salary']:>12.2f} {row['overtime_pay']:>9.2f} {row['allowances']:>10.2f} {row['deductions']:>10.2f} {row['tax_amount']:>8.2f} {row['net_salary']:>11.2f}\n"
                self.report_text.insert(tk.END, line)
            
            if not results:
                self.report_text.insert(tk.END, "No payroll data found for the selected period.\n")
                return
            
            # Add totals
            query = """
            SELECT COUNT(p.id) as employees, SUM(p.basic_salary) as basic_salary, 
                SUM(p.overtime_pay) as overtime_pay, SUM(p.allowances) as allowances, 
                SUM(p.deductions) as deductions, SUM(p.tax_amount) as tax_amount, 
                SUM(p.net_salary) as net_salary
            FROM payroll p
            WHERE p.month = %s AND p.year = %s
            """
            
            cursor.execute(query, (month, year))
            totals = cursor.fetchone()
            
            self.report_text.insert(tk.END, "-"*100 + "\n")
            self.report_text.insert(tk.END, f"{'TOTAL':<20} {totals['employees']:>10} {totals['basic_salary']:>12.2f} {totals['overtime_pay']:>9.2f} {totals['allowances']:>10.2f} {totals['deductions']:>10.2f} {totals['tax_amount']:>8.2f} {totals['net_salary']:>11.2f}\n")
            
        except Exception as e:
            print(f"Error in generate_monthly_payroll_report: {str(e)}")  # Debug
            raise  # Re-raise the exception
    def generate_employee_salary_report(self):
        db = Database()
        cursor = db.get_cursor()
        
        query = """
        SELECT e.emp_id, e.name, e.department, e.position, e.basic_salary
        FROM employees e
        ORDER BY e.department, e.name
        """
        
        cursor.execute(query)
        results = cursor.fetchall()
        
        self.report_text.insert(tk.END, "Employee Salary Report\n\n")
        self.report_text.insert(tk.END, "ID       Name                      Department      Position          Basic Salary\n")
        self.report_text.insert(tk.END, "-"*100 + "\n")
        
        for row in results:
            line = f"{row['emp_id']:<8} {row['name']:<25} {row['department']:<15} {row['position']:<16} {row['basic_salary']:>12.2f}\n"
            self.report_text.insert(tk.END, line)
    
    def generate_tax_report(self, month, year):
        db = Database()
        cursor = db.get_cursor()
        
        query = """
        SELECT e.emp_id, e.name, p.basic_salary + p.overtime_pay + p.allowances as gross_salary, p.tax_amount
        FROM payroll p
        JOIN employees e ON p.emp_id = e.emp_id
        WHERE p.month = %s AND p.year = %s
        ORDER BY p.tax_amount DESC
        """
        
        cursor.execute(query, (month, year))
        results = cursor.fetchall()
        
        month_name = datetime.strptime(str(month), "%m").strftime("%B")
        self.report_text.insert(tk.END, f"Tax Deduction Report - {month_name} {year}\n\n")
        self.report_text.insert(tk.END, "ID       Name                      Gross Salary  Tax Amount\n")
        self.report_text.insert(tk.END, "-"*100 + "\n")
        
        for row in results:
            line = f"{row['emp_id']:<8} {row['name']:<25} {row['gross_salary']:>12.2f} {row['tax_amount']:>10.2f}\n"
            self.report_text.insert(tk.END, line)
        
        # Add total
        query = """
        SELECT SUM(p.tax_amount) as total_tax
        FROM payroll p
        WHERE p.month = %s AND p.year = %s
        """
        
        cursor.execute(query, (month, year))
        total_tax = cursor.fetchone()['total_tax'] or 0.0
        
        self.report_text.insert(tk.END, "-"*100 + "\n")
        self.report_text.insert(tk.END, f"{'TOTAL TAX':<58} {total_tax:>10.2f}\n")
    
    def generate_department_report(self, month, year):
        db = Database()
        cursor = db.get_cursor()
        
        query = """
        SELECT e.department, AVG(p.basic_salary) as avg_salary, MIN(p.basic_salary) as min_salary, 
               MAX(p.basic_salary) as max_salary, SUM(p.basic_salary) as total_salary
        FROM payroll p
        JOIN employees e ON p.emp_id = e.emp_id
        WHERE p.month = %s AND p.year = %s
        GROUP BY e.department
        ORDER BY SUM(p.basic_salary) DESC
        """
        
        cursor.execute(query, (month, year))
        results = cursor.fetchall()
        
        month_name = datetime.strptime(str(month), "%m").strftime("%B")
        self.report_text.insert(tk.END, f"Department-wise Salary Report - {month_name} {year}\n\n")
        self.report_text.insert(tk.END, "Department           Avg Salary  Min Salary  Max Salary  Total Salary\n")
        self.report_text.insert(tk.END, "-"*100 + "\n")
        
        for row in results:
            line = f"{row['department']:<20} {row['avg_salary']:>10.2f} {row['min_salary']:>11.2f} {row['max_salary']:>11.2f} {row['total_salary']:>12.2f}\n"
            self.report_text.insert(tk.END, line)
    
    def generate_attendance_report(self, month, year):
        db = Database()
        cursor = db.get_cursor()
        
        query = """
        SELECT e.emp_id, e.name, 
               SUM(CASE WHEN a.status = 'Present' THEN 1 ELSE 0 END) as present_days,
               SUM(CASE WHEN a.status = 'Absent' THEN 1 ELSE 0 END) as absent_days,
               SUM(CASE WHEN a.status = 'Half Day' THEN 1 ELSE 0 END) as half_days,
               SUM(CASE WHEN a.status = 'Leave' THEN 1 ELSE 0 END) as leave_days,
               SUM(a.hours_worked) as total_hours
        FROM attendance a
        JOIN employees e ON a.emp_id = e.emp_id
        WHERE MONTH(a.date) = %s AND YEAR(a.date) = %s
        GROUP BY e.emp_id, e.name
        """
        
        cursor.execute(query, (month, year))
        results = cursor.fetchall()
        
        month_name = datetime.strptime(str(month), "%m").strftime("%B")
        self.report_text.insert(tk.END, f"Attendance Summary - {month_name} {year}\n\n")
        self.report_text.insert(tk.END, "ID       Name                      Present  Absent  Half Day  Leave  Total Hours\n")
        self.report_text.insert(tk.END, "-"*100 + "\n")
        
        for row in results:
            line = f"{row['emp_id']:<8} {row['name']:<25} {row['present_days']:>7} {row['absent_days']:>7} {row['half_days']:>9} {row['leave_days']:>6} {row['total_hours']:>11.1f}\n"
            self.report_text.insert(tk.END, line)
    
    # Menu methods
    def export_data(self):
        # Ask which data to export
        data_type = simpledialog.askstring("Export Data", "Enter data type to export (employees/attendance/payroll/leaves/loans):")
        if not data_type or data_type.lower() not in ["employees", "attendance", "payroll", "leaves", "loans"]:
            return
        
        # Ask for filename
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")],
            title=f"Save {data_type.capitalize()} Data As"
        )
        
        if not filename:
            return
        
        try:
            db = Database()
            cursor = db.get_cursor()
            
            if data_type.lower() == "employees":
                query = "SELECT * FROM employees"
                cursor.execute(query)
                data = cursor.fetchall()
                
                with open(filename, 'w') as f:
                    # Write header
                    f.write("emp_id,name,department,position,basic_salary,hire_date,contact,email,bank_account,created_at,updated_at\n")
                    
                    # Write data
                    for row in data:
                        f.write(f"{row['emp_id']},{row['name']},{row['department']},{row['position']},{row['basic_salary']},{row['hire_date']},{row['contact']},{row['email']},{row['bank_account']},{row['created_at']},{row['updated_at']}\n")
            
            elif data_type.lower() == "attendance":
                query = """
                SELECT a.*, e.name 
                FROM attendance a
                JOIN employees e ON a.emp_id = e.emp_id
                """
                cursor.execute(query)
                data = cursor.fetchall()
                
                with open(filename, 'w') as f:
                    f.write("id,emp_id,name,date,status,hours_worked,notes,created_at\n")
                    for row in data:
                        f.write(f"{row['id']},{row['emp_id']},{row['name']},{row['date']},{row['status']},{row['hours_worked']},{row['notes']},{row['created_at']}\n")
            
            elif data_type.lower() == "payroll":
                query = """
                SELECT p.*, e.name 
                FROM payroll p
                JOIN employees e ON p.emp_id = e.emp_id
                """
                cursor.execute(query)
                data = cursor.fetchall()
                
                with open(filename, 'w') as f:
                    f.write("id,emp_id,name,month,year,basic_salary,overtime_pay,allowances,deductions,tax_amount,net_salary,status,payment_date,created_at,updated_at\n")
                    for row in data:
                        f.write(f"{row['id']},{row['emp_id']},{row['name']},{row['month']},{row['year']},{row['basic_salary']},{row['overtime_pay']},{row['allowances']},{row['deductions']},{row['tax_amount']},{row['net_salary']},{row['status']},{row['payment_date']},{row['created_at']},{row['updated_at']}\n")
            
            elif data_type.lower() == "leaves":
                query = """
                SELECT l.*, e.name 
                FROM leaves l
                JOIN employees e ON l.emp_id = e.emp_id
                """
                cursor.execute(query)
                data = cursor.fetchall()
                
                with open(filename, 'w') as f:
                    f.write("id,emp_id,name,start_date,end_date,leave_type,status,reason,created_at,updated_at\n")
                    for row in data:
                        f.write(f"{row['id']},{row['emp_id']},{row['name']},{row['start_date']},{row['end_date']},{row['leave_type']},{row['status']},{row['reason']},{row['created_at']},{row['updated_at']}\n")
            
            elif data_type.lower() == "loans":
                query = """
                SELECT l.*, e.name 
                FROM loans l
                JOIN employees e ON l.emp_id = e.emp_id
                """
                cursor.execute(query)
                data = cursor.fetchall()
                
                with open(filename, 'w') as f:
                    f.write("id,emp_id,name,amount,start_date,duration_months,monthly_payment,remaining_amount,status,notes,created_at,updated_at\n")
                    for row in data:
                        f.write(f"{row['id']},{row['emp_id']},{row['name']},{row['amount']},{row['start_date']},{row['duration_months']},{row['monthly_payment']},{row['remaining_amount']},{row['status']},{row['notes']},{row['created_at']},{row['updated_at']}\n")
            
            messagebox.showinfo("Success", f"{data_type.capitalize()} data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def backup_database(self):
        # Ask for filename
        filename = filedialog.asksaveasfilename(
            defaultextension=".sql",
            filetypes=[("SQL Files", "*.sql")],
            title="Save Database Backup As"
        )
        
        if not filename:
            return
        
        try:
            # Using mysqldump command (requires mysqldump in system path)
            import subprocess
            command = f"mysqldump -u {DB_CONFIG['user']} -p{DB_CONFIG['password']} {DB_CONFIG['database']} > {filename}"
            subprocess.run(command, shell=True, check=True)
            messagebox.showinfo("Success", f"Database backup saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to backup database: {str(e)}")
    
    def restore_database(self):
        # Ask for filename
        filename = filedialog.askopenfilename(
            filetypes=[("SQL Files", "*.sql")],
            title="Select Database Backup File"
        )
        
        if not filename:
            return
        
        if not messagebox.askyesno("Confirm", "This will overwrite the current database. Continue?"):
            return
        
        try:
            # Using mysql command (requires mysql in system path)
            import subprocess
            command = f"mysql -u {DB_CONFIG['user']} -p{DB_CONFIG['password']} {DB_CONFIG['database']} < {filename}"
            subprocess.run(command, shell=True, check=True)
            messagebox.showinfo("Success", "Database restored successfully!")
            
            # Reload all data
            self.load_initial_data()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore database: {str(e)}")
    
    def show_user_guide(self):
        guide = """
        Payroll System User Guide
        
        1. Employee Management:
           - Add, update, or delete employee records
           - View employee details and search for employees
        
        2. Attendance Tracking:
           - Record daily attendance for employees
           - Filter attendance by employee or month
           - Bulk import attendance for all employees
        
        3. Payroll Processing:
           - Calculate payroll for individual employees or all employees
           - Generate payslips in PDF format
           - Mark payroll as paid
        
        4. Leave Management:
           - Apply for employee leaves
           - Approve or reject leave applications
           - Track leave status
        
        5. Loan Management:
           - Add employee loans
           - Track loan payments and status
           - Mark loans as completed
        
        6. Reports:
           - Generate various reports (payroll, tax, attendance, etc.)
           - Export reports to PDF
        
        For more assistance, please contact support.
        """
        
        dialog = tk.Toplevel(self.root)
        dialog.title("User Guide")
        dialog.geometry("600x400")
        
        text = tk.Text(dialog, wrap=tk.WORD, font=(STYLE_CONFIG['font_family'], 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, guide)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def show_about(self):
        about = """
        Payroll System
        
        Version: 2.0
        Developed by: Muhammad Ilyas Khan
        
        Features:
        - Employee management
        - Attendance tracking
        - Payroll processing
        - Leave management
        - Loan management
        - Comprehensive reporting
        
        © 2025 Your Company Name. All rights reserved.
        """
        
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("400x300")
        
        text = tk.Text(dialog, wrap=tk.WORD, font=(STYLE_CONFIG['font_family'], 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(tk.END, about)
        text.config(state=tk.DISABLED)
        
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)

def main():
    root = tk.Tk()
    login = LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()