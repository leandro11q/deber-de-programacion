
import customtkinter as ctk
import sqlite3
import os
import hashlib
import binascii
import secrets
from tkinter import messagebox, simpledialog, ttk

DB_FILE = "app_data.db"

# -----------------------
# Utility: password hashing (PBKDF2-HMAC-SHA256)
# -----------------------
def hash_password(password: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return binascii.hexlify(salt).decode(), binascii.hexlify(dk).decode()

def verify_password(stored_salt_hex: str, stored_hash_hex: str, provided_password: str) -> bool:
    salt = binascii.unhexlify(stored_salt_hex.encode())
    _, new_hash = hash_password(provided_password, salt)
    return secrets.compare_digest(new_hash, stored_hash_hex)

# -----------------------
# Database helpers
# -----------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        salt TEXT NOT NULL,
        passhash TEXT NOT NULL
    )
    """)
    # Knowledge table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS knowledge (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        keyword TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL
    )
    """)
    # Insert sample rows if empty
    cur.execute("SELECT COUNT(*) FROM knowledge")
    if cur.fetchone()[0] == 0:
        sample = [
            ("python", "Lenguaje de programación de alto nivel, multiparadigma."),
            ("tkinter", "Librería estándar de GUI para Python."),
            ("customtkinter", "Librería que aporta estilos modernos a Tkinter."),
            ("arp", "Address Resolution Protocol - asocia IP a MAC en LAN."),
        ]
        cur.executemany("INSERT INTO knowledge (keyword, description) VALUES (?, ?)", sample)
    conn.commit()
    conn.close()

def register_user_db(username: str, password: str) -> tuple:
    if not username or not password:
        return False, "Usuario o contraseña vacíos."
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        salt_hex, hash_hex = hash_password(password)
        cur.execute("INSERT INTO users (username, salt, passhash) VALUES (?, ?, ?)", (username, salt_hex, hash_hex))
        conn.commit()
        return True, "Usuario registrado correctamente."
    except sqlite3.IntegrityError:
        return False, "El usuario ya existe."
    finally:
        conn.close()

def check_credentials_db(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT salt, passhash FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if row:
        salt_hex, passhash_hex = row
        return verify_password(salt_hex, passhash_hex, password)
    return False

# Knowledge CRUD
def query_knowledge_db(keyword: str) -> str:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT description FROM knowledge WHERE keyword = ?", (keyword.lower(),))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def list_knowledge_rows():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id, keyword, description FROM knowledge ORDER BY keyword")
    rows = cur.fetchall()
    conn.close()
    return rows

def add_knowledge(keyword: str, description: str) -> tuple:
    if not keyword or not description:
        return False, "Keyword y descripción requeridos."
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO knowledge (keyword, description) VALUES (?, ?)", (keyword.lower(), description))
        conn.commit()
        return True, "Entrada agregada."
    except sqlite3.IntegrityError:
        return False, "La keyword ya existe."
    finally:
        conn.close()

def update_knowledge(row_id: int, keyword: str, description: str) -> tuple:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    try:
        cur.execute("UPDATE knowledge SET keyword = ?, description = ? WHERE id = ?", (keyword.lower(), description, row_id))
        conn.commit()
        if cur.rowcount == 0:
            return False, "No se encontró la entrada."
        return True, "Entrada actualizada."
    except sqlite3.IntegrityError:
        return False, "La keyword ya existe (conflicto)."
    finally:
        conn.close()

def delete_knowledge(row_id: int) -> tuple:
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("DELETE FROM knowledge WHERE id = ?", (row_id,))
    conn.commit()
    affected = cur.rowcount
    conn.close()
    if affected:
        return True, "Entrada eliminada."
    return False, "No se encontró la entrada."

# -----------------------
# GUI
# -----------------------
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Aplicación de Consulta - Integrador")
        self.geometry("900x520")
        self.minsize(900,520)

        # Frames
        self.login_frame = ctk.CTkFrame(self, corner_radius=10)
        self.login_frame.pack(padx=20, pady=20, fill="both", expand=True)
        self.build_login_ui()

    def build_login_ui(self):
        title = ctk.CTkLabel(self.login_frame, text="Iniciar sesión / Registrar", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(10,20))

        self.username_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Usuario")
        self.username_entry.pack(pady=(0,10), ipady=6, padx=40)
        self.password_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Contraseña", show="*")
        self.password_entry.pack(pady=(0,10), ipady=6, padx=40)

        btn_frame = ctk.CTkFrame(self.login_frame, fg_color="transparent")
        btn_frame.pack(pady=10)
        login_btn = ctk.CTkButton(btn_frame, text="Iniciar sesión", command=self.login_action, width=160)
        login_btn.grid(row=0, column=0, padx=8)
        reg_btn = ctk.CTkButton(btn_frame, text="Registrar", command=self.register_action, width=160)
        reg_btn.grid(row=0, column=1, padx=8)

    def register_action(self):
        user = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        ok, msg = register_user_db(user, pwd)
        if ok:
            messagebox.showinfo("Registro", msg)
        else:
            messagebox.showerror("Error", msg)

    def login_action(self):
        user = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        if check_credentials_db(user, pwd):
            self.open_main_window(user)
        else:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

    def open_main_window(self, username):
        self.login_frame.destroy()
        topbar = ctk.CTkFrame(self, corner_radius=0)
        topbar.pack(fill="x")
        lbl = ctk.CTkLabel(topbar, text=f"Usuario: {username}", anchor="w", padx=10)
        lbl.pack(side="left", pady=12)
        logout_btn = ctk.CTkButton(topbar, text="Cerrar sesión", width=120, command=self.restart_app)
        logout_btn.pack(side="right", padx=10, pady=8)

        content = ctk.CTkFrame(self)
        content.pack(expand=True, fill="both", padx=20, pady=20)

        left = ctk.CTkFrame(content)
        left.pack(side="left", fill="both", expand=True, padx=(0,10))
        right = ctk.CTkFrame(content)
        right.pack(side="right", fill="both", expand=True)

        q_label = ctk.CTkLabel(left, text="Ingrese término de consulta", font=ctk.CTkFont(size=16))
        q_label.pack(pady=(10,8))
        self.q_entry = ctk.CTkEntry(left, placeholder_text="Ej: python")
        self.q_entry.pack(pady=(0,12), ipady=6, padx=10)

        q_btn = ctk.CTkButton(left, text="Buscar", command=self.perform_query)
        q_btn.pack(pady=6)
        clear_btn = ctk.CTkButton(left, text="Limpiar", command=lambda: self.q_entry.delete(0, "end"))
        clear_btn.pack(pady=6)

        manage_btn = ctk.CTkButton(left, text="Administrar base de conocimiento", command=self.open_manage_knowledge)
        manage_btn.pack(pady=(12,6))

        res_label = ctk.CTkLabel(right, text="Resultado", font=ctk.CTkFont(size=16))
        res_label.pack(pady=(10,8))
        self.result_text = ctk.CTkTextbox(right, wrap="word", width=420, height=320)
        self.result_text.pack(padx=10, pady=6, fill="both", expand=True)

    def perform_query(self):
        term = self.q_entry.get().strip()
        if not term:
            messagebox.showwarning("Atención", "Ingrese un término para buscar.")
            return
        res = query_knowledge_db(term)
        self.result_text.delete("1.0", "end")
        if res:
            self.result_text.insert("0.0", res)
        else:
            self.result_text.insert("0.0", "No se encontraron resultados para: " + term)

    def open_manage_knowledge(self):
        win = ctk.CTkToplevel(self)
        win.title("Administrar Base de Conocimiento")
        win.geometry("800x420")

        # Treeview (ttk) for listing
        tree_frame = ctk.CTkFrame(win)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        cols = ("id", "keyword", "description")
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        tree.heading("id", text="ID")
        tree.heading("keyword", text="Keyword")
        tree.heading("description", text="Descripción")
        tree.column("id", width=40, anchor="center")
        tree.column("keyword", width=140, anchor="w")
        tree.column("description", width=520, anchor="w")
        tree.pack(fill="both", expand=True, side="left")

        # scrollbar
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        vsb.pack(side="right", fill="y")
        tree.configure(yscroll=vsb.set)

        def refresh_tree():
            for r in tree.get_children():
                tree.delete(r)
            for row in list_knowledge_rows():
                tree.insert("", "end", values=row)

        def add_entry():
            k = simpledialog.askstring("Nueva keyword", "Ingrese la keyword (sin espacios):", parent=win)
            if k is None:
                return
            d = simpledialog.askstring("Descripción", "Ingrese la descripción:", parent=win)
            if d is None:
                return
            ok, msg = add_knowledge(k.strip(), d.strip())
            if ok:
                messagebox.showinfo("Éxito", msg, parent=win)
                refresh_tree()
            else:
                messagebox.showerror("Error", msg, parent=win)

        def edit_entry():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Atención", "Seleccione una entrada para editar.", parent=win)
                return
            item = tree.item(sel)
            row_id, keyword, description = item["values"]
            k = simpledialog.askstring("Editar keyword", "Keyword:", initialvalue=keyword, parent=win)
            if k is None:
                return
            d = simpledialog.askstring("Editar descripción", "Descripción:", initialvalue=description, parent=win)
            if d is None:
                return
            ok, msg = update_knowledge(row_id, k.strip(), d.strip())
            if ok:
                messagebox.showinfo("Éxito", msg, parent=win)
                refresh_tree()
            else:
                messagebox.showerror("Error", msg, parent=win)

        def del_entry():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Atención", "Seleccione una entrada para eliminar.", parent=win)
                return
            item = tree.item(sel)
            row_id = item["values"][0]
            if messagebox.askyesno("Confirmar", "¿Eliminar la entrada seleccionada?", parent=win):
                ok, msg = delete_knowledge(row_id)
                if ok:
                    messagebox.showinfo("Éxito", msg, parent=win)
                    refresh_tree()
                else:
                    messagebox.showerror("Error", msg, parent=win)

        btn_frame = ctk.CTkFrame(win)
        btn_frame.pack(fill="x", padx=10, pady=(0,10))
        c_add = ctk.CTkButton(btn_frame, text="Agregar", width=120, command=add_entry)
        c_add.pack(side="left", padx=6)
        c_edit = ctk.CTkButton(btn_frame, text="Editar", width=120, command=edit_entry)
        c_edit.pack(side="left", padx=6)
        c_del = ctk.CTkButton(btn_frame, text="Eliminar", width=120, command=del_entry)
        c_del.pack(side="left", padx=6)
        c_close = ctk.CTkButton(btn_frame, text="Cerrar", width=120, command=win.destroy)
        c_close.pack(side="right", padx=6)

        refresh_tree()

    def restart_app(self):
        for widget in self.winfo_children():
            widget.destroy()
        self.login_frame = ctk.CTkFrame(self, corner_radius=10)
        self.login_frame.pack(padx=20, pady=20, fill="both", expand=True)
        self.build_login_ui()

if __name__ == "__main__":
    init_db()
    app = App()
    app.mainloop()
