import os
import sqlite3
from datetime import date, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "library.db")
MATERIAL_FOLDER = os.path.join(BASE_DIR, "static", "materials")
ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "ppt", "pptx", "txt", "zip"}

app = Flask(__name__)
app.secret_key = os.environ.get("LIBRARY_SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024
os.makedirs(MATERIAL_FOLDER, exist_ok=True)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            phone TEXT DEFAULT '',
            department TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            isbn TEXT DEFAULT '',
            category TEXT DEFAULT '',
            publisher TEXT DEFAULT '',
            year INTEGER,
            total_copies INTEGER NOT NULL DEFAULT 1,
            available_copies INTEGER NOT NULL DEFAULT 1,
            description TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS borrowings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            book_id INTEGER NOT NULL REFERENCES books(id),
            issue_date TEXT NOT NULL,
            due_date TEXT NOT NULL,
            return_date TEXT,
            fine REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Issued'
        );
        CREATE TABLE IF NOT EXISTS materials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            subject TEXT DEFAULT '',
            year TEXT NOT NULL,
            semester TEXT NOT NULL,
            description TEXT DEFAULT '',
            filename TEXT NOT NULL,
            uploaded_by INTEGER REFERENCES users(id),
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            message TEXT NOT NULL,
            submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        admin = db.execute("SELECT id FROM users WHERE email = ?", ("admin@library.com",)).fetchone()
        if not admin:
            db.execute(
                "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                ("Library Admin", "admin@library.com", generate_password_hash("Admin@123"), "admin")
            )
        count = db.execute("SELECT COUNT(*) AS n FROM books").fetchone()["n"]
        if count == 0:
            examples = [
                ("Introduction to Algorithms", "Thomas H. Cormen", "9780262046305", "Computer Science", "MIT Press", 2022, 4, 4, "A comprehensive introduction to algorithms."),
                ("Python Crash Course", "Eric Matthes", "9781718502703", "Programming", "No Starch Press", 2023, 5, 5, "A hands-on guide to Python programming."),
                ("Database System Concepts", "Abraham Silberschatz", "9780078022159", "Database", "McGraw Hill", 2019, 3, 3, "Core concepts in database systems."),
            ]
            db.executemany("""INSERT INTO books(title,author,isbn,category,publisher,year,total_copies,available_copies,description)
                              VALUES(?,?,?,?,?,?,?,?,?)""", examples)

def current_user():
    if "user_id" not in session:
        return None
    with get_db() as db:
        return db.execute("SELECT id,name,email,role,phone,department FROM users WHERE id=?", (session["user_id"],)).fetchone()

@app.context_processor
def inject_user():
    return {"logged_user": current_user(), "today": date.today().isoformat()}

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped

def role_required(role):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user or user["role"] != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator

def fine_for(row):
    if row["status"] == "Returned":
        return float(row["fine"] or 0)
    due = date.fromisoformat(row["due_date"])
    days_late = max(0, (date.today() - due).days)
    return days_late * 5.0  # Rs. 5 per day after the due date

@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    with get_db() as db:
        if q:
            books = db.execute("""SELECT * FROM books WHERE title LIKE ? OR author LIKE ? OR category LIKE ?
                                  ORDER BY title""", (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
        else:
            books = db.execute("SELECT * FROM books ORDER BY title LIMIT 8").fetchall()
    return render_template("index.html", books=books, q=q)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        department = request.form.get("department", "").strip()
        if not name or not email or len(password) < 8:
            flash("Enter your name and email, and use a password with at least 8 characters.", "danger")
            return render_template("register.html")
        try:
            with get_db() as db:
                db.execute("INSERT INTO users(name,email,password_hash,role,department) VALUES(?,?,?,?,?)",
                           (name, email, generate_password_hash(password), "student", department))
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That email address is already registered.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            flash(f"Welcome, {user['name']}!", "success")
            next_url = request.args.get("next", "")
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("admin_dashboard" if user["role"] == "admin" else "student_dashboard"))
        flash("Invalid email or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))

@app.route("/admin")
@role_required("admin")
def admin_dashboard():
    with get_db() as db:
        stats = {
            "books": db.execute("SELECT COUNT(*) n FROM books").fetchone()["n"],
            "students": db.execute("SELECT COUNT(*) n FROM users WHERE role='student'").fetchone()["n"],
            "issued": db.execute("SELECT COUNT(*) n FROM borrowings WHERE status='Issued'").fetchone()["n"],
            "materials": db.execute("SELECT COUNT(*) n FROM materials").fetchone()["n"],
        }
        recent = db.execute("""SELECT br.*, u.name student_name, b.title book_title
                               FROM borrowings br JOIN users u ON u.id=br.user_id JOIN books b ON b.id=br.book_id
                               ORDER BY br.id DESC LIMIT 8""").fetchall()
        students = db.execute("SELECT id,name,email,department FROM users WHERE role='student' ORDER BY name").fetchall()
    return render_template("admin.html", stats=stats, recent=recent, students=students)

@app.route("/student")
@role_required("student")
def student_dashboard():
    user = current_user()
    with get_db() as db:
        active = db.execute("""SELECT br.*, b.title book_title, b.author FROM borrowings br
                               JOIN books b ON b.id=br.book_id WHERE br.user_id=? AND br.status='Issued'
                               ORDER BY br.due_date""", (user["id"],)).fetchall()
        all_rows = db.execute("SELECT * FROM borrowings WHERE user_id=?", (user["id"],)).fetchall()
        total_fine = sum(fine_for(r) for r in all_rows)
    active_rows = [dict(r, calculated_fine=fine_for(r)) for r in active]
    return render_template("student.html", active=active_rows, total_fine=total_fine)

@app.route("/books")
def books():
    q = request.args.get("q", "").strip()
    with get_db() as db:
        if q:
            rows = db.execute("""SELECT * FROM books WHERE title LIKE ? OR author LIKE ? OR isbn LIKE ? OR category LIKE ?
                                 ORDER BY title""", tuple([f"%{q}%"]*4)).fetchall()
        else:
            rows = db.execute("SELECT * FROM books ORDER BY title").fetchall()
    return render_template("books.html", books=rows, q=q)

@app.route("/books/<int:book_id>")
def book_detail(book_id):
    with get_db() as db:
        book = db.execute("SELECT * FROM books WHERE id=?", (book_id,)).fetchone()
    if not book:
        abort(404)
    return render_template("book_form.html", book=book, detail_only=True)

@app.route("/admin/books/new", methods=["GET", "POST"])
@role_required("admin")
def add_book():
    if request.method == "POST":
        try:
            total = max(0, int(request.form.get("total_copies", 1)))
            year_raw = request.form.get("year", "").strip()
            year = int(year_raw) if year_raw else None
            with get_db() as db:
                db.execute("""INSERT INTO books(title,author,isbn,category,publisher,year,total_copies,available_copies,description)
                              VALUES(?,?,?,?,?,?,?,?,?)""",
                           (request.form["title"].strip(), request.form["author"].strip(),
                            request.form.get("isbn","").strip(), request.form.get("category","").strip(),
                            request.form.get("publisher","").strip(), year, total, total,
                            request.form.get("description","").strip()))
            flash("Book added successfully.", "success")
            return redirect(url_for("books"))
        except (ValueError, KeyError):
            flash("Please provide valid book details.", "danger")
    return render_template("book_form.html", book=None, detail_only=False)

@app.route("/admin/books/<int:book_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def edit_book(book_id):
    with get_db() as db:
        book = db.execute("SELECT * FROM books WHERE id=?", (book_id,)).fetchone()
        if not book:
            abort(404)
        if request.method == "POST":
            try:
                new_total = max(0, int(request.form.get("total_copies", book["total_copies"])))
                year_raw = request.form.get("year", "").strip()
                year = int(year_raw) if year_raw else None
                currently_issued = book["total_copies"] - book["available_copies"]
                if new_total < currently_issued:
                    flash(f"Total copies cannot be less than currently issued copies ({currently_issued}).", "danger")
                    return render_template("book_form.html", book=book, detail_only=False, edit=True)
                db.execute("""UPDATE books SET title=?,author=?,isbn=?,category=?,publisher=?,year=?,total_copies=?,
                              available_copies=?,description=? WHERE id=?""",
                           (request.form["title"].strip(), request.form["author"].strip(),
                            request.form.get("isbn","").strip(), request.form.get("category","").strip(),
                            request.form.get("publisher","").strip(), year, new_total,
                            new_total-currently_issued, request.form.get("description","").strip(), book_id))
                flash("Book updated successfully.", "success")
                return redirect(url_for("books"))
            except (ValueError, KeyError):
                flash("Please provide valid book details.", "danger")
    return render_template("book_form.html", book=book, detail_only=False, edit=True)

@app.route("/admin/books/<int:book_id>/delete", methods=["POST"])
@role_required("admin")
def delete_book(book_id):
    with get_db() as db:
        active = db.execute("SELECT COUNT(*) n FROM borrowings WHERE book_id=? AND status='Issued'", (book_id,)).fetchone()["n"]
        if active:
            flash("This book cannot be deleted while copies are issued.", "danger")
        else:
            db.execute("DELETE FROM books WHERE id=?", (book_id,))
            flash("Book deleted.", "success")
    return redirect(url_for("books"))

@app.route("/admin/issue", methods=["GET", "POST"])
@role_required("admin")
def issue_book():
    with get_db() as db:
        if request.method == "POST":
            try:
                student_id = int(request.form["user_id"])
                book_id = int(request.form["book_id"])
                days = min(90, max(1, int(request.form.get("days", 14))))
                book = db.execute("SELECT * FROM books WHERE id=?", (book_id,)).fetchone()
                student = db.execute("SELECT * FROM users WHERE id=? AND role='student'", (student_id,)).fetchone()
                already = db.execute("SELECT id FROM borrowings WHERE user_id=? AND book_id=? AND status='Issued'", (student_id, book_id)).fetchone()
                if not student or not book:
                    flash("Select a valid student and book.", "danger")
                elif book["available_copies"] < 1:
                    flash("No copies of this book are currently available.", "danger")
                elif already:
                    flash("This student already has this book issued.", "warning")
                else:
                    issue_date = date.today()
                    due_date = issue_date + timedelta(days=days)
                    db.execute("INSERT INTO borrowings(user_id,book_id,issue_date,due_date) VALUES(?,?,?,?)",
                               (student_id, book_id, issue_date.isoformat(), due_date.isoformat()))
                    db.execute("UPDATE books SET available_copies=available_copies-1 WHERE id=?", (book_id,))
                    flash(f"Book issued. Due date: {due_date.isoformat()}.", "success")
                    return redirect(url_for("history"))
            except (ValueError, KeyError):
                flash("Please select a student, book, and valid loan period.", "danger")
        students = db.execute("SELECT id,name,email FROM users WHERE role='student' ORDER BY name").fetchall()
        available_books = db.execute("SELECT id,title,author,available_copies FROM books WHERE available_copies>0 ORDER BY title").fetchall()
    return render_template("issue.html", students=students, books=available_books)

@app.route("/history")
@login_required
def history():
    user = current_user()
    q = request.args.get("user_id", type=int)
    if user["role"] == "admin":
        user_id = q
    else:
        user_id = user["id"]
    with get_db() as db:
        if user_id:
            rows = db.execute("""SELECT br.*, u.name student_name, b.title book_title, b.author FROM borrowings br
                                 JOIN users u ON u.id=br.user_id JOIN books b ON b.id=br.book_id
                                 WHERE br.user_id=? ORDER BY br.id DESC""", (user_id,)).fetchall()
        elif user["role"] == "admin":
            rows = db.execute("""SELECT br.*, u.name student_name, b.title book_title, b.author FROM borrowings br
                                 JOIN users u ON u.id=br.user_id JOIN books b ON b.id=br.book_id
                                 ORDER BY br.id DESC""").fetchall()
        else:
            rows = db.execute("""SELECT br.*, u.name student_name, b.title book_title, b.author FROM borrowings br
                                 JOIN users u ON u.id=br.user_id JOIN books b ON b.id=br.book_id
                                 WHERE br.user_id=? ORDER BY br.id DESC""", (user["id"],)).fetchall()
        students = db.execute("SELECT id,name FROM users WHERE role='student' ORDER BY name").fetchall() if user["role"] == "admin" else []
    enriched = []
    for row in rows:
        d = dict(row)
        d["calculated_fine"] = fine_for(row)
        enriched.append(d)
    return render_template("history.html", rows=enriched, students=students, selected_user=user_id)

@app.route("/admin/return/<int:borrow_id>", methods=["POST"])
@role_required("admin")
def return_book(borrow_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM borrowings WHERE id=? AND status='Issued'", (borrow_id,)).fetchone()
        if not row:
            flash("Borrowing record not found or already returned.", "warning")
        else:
            final_fine = fine_for(row)
            db.execute("UPDATE borrowings SET status='Returned',return_date=?,fine=? WHERE id=?",
                       (date.today().isoformat(), final_fine, borrow_id))
            db.execute("UPDATE books SET available_copies=available_copies+1 WHERE id=?", (row["book_id"],))
            flash(f"Book returned successfully. Fine: ₹{final_fine:.2f}.", "success")
    return redirect(url_for("history"))

@app.route("/materials")
def materials():
    year = request.args.get("year", "").strip()
    semester = request.args.get("semester", "").strip()
    q = request.args.get("q", "").strip()
    sql = "SELECT m.*, u.name uploader FROM materials m LEFT JOIN users u ON u.id=m.uploaded_by WHERE 1=1"
    params = []
    if year:
        sql += " AND m.year=?"; params.append(year)
    if semester:
        sql += " AND m.semester=?"; params.append(semester)
    if q:
        sql += " AND (m.title LIKE ? OR m.subject LIKE ? OR m.description LIKE ?)"
        params.extend([f"%{q}%"]*3)
    sql += " ORDER BY m.year,m.semester,m.title"
    with get_db() as db:
        rows = db.execute(sql, params).fetchall()
    return render_template("materials.html", materials=rows, year=year, semester=semester, q=q)

@app.route("/admin/materials/new", methods=["GET", "POST"])
@role_required("admin")
def add_material():
    if request.method == "POST":
        file = request.files.get("file")
        title = request.form.get("title", "").strip()
        year = request.form.get("year", "").strip()
        semester = request.form.get("semester", "").strip()
        if not title or not year or not semester or not file or not file.filename:
            flash("Fill all required fields and select a file.", "danger")
        elif "." not in file.filename or file.filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
            flash("Allowed files: PDF, DOC, DOCX, PPT, PPTX, TXT, ZIP.", "danger")
        else:
            safe = secure_filename(file.filename)
            stored = f"{date.today().strftime('%Y%m%d')}_{os.urandom(4).hex()}_{safe}"
            file.save(os.path.join(MATERIAL_FOLDER, stored))
            with get_db() as db:
                db.execute("""INSERT INTO materials(title,subject,year,semester,description,filename,uploaded_by)
                              VALUES(?,?,?,?,?,?,?)""",
                           (title, request.form.get("subject","").strip(), year, semester,
                            request.form.get("description","").strip(), stored, session["user_id"]))
            flash("Study material uploaded.", "success")
            return redirect(url_for("materials"))
    return render_template("material_form.html")

@app.route("/admin/materials/<int:material_id>/delete", methods=["POST"])
@role_required("admin")
def delete_material(material_id):
    with get_db() as db:
        item = db.execute("SELECT filename FROM materials WHERE id=?", (material_id,)).fetchone()
        if item:
            try:
                os.remove(os.path.join(MATERIAL_FOLDER, item["filename"]))
            except OSError:
                pass
            db.execute("DELETE FROM materials WHERE id=?", (material_id,))
            flash("Material deleted.", "success")
    return redirect(url_for("materials"))

@app.route("/materials/download/<int:material_id>")
def download_material(material_id):
    with get_db() as db:
        item = db.execute("SELECT filename FROM materials WHERE id=?", (material_id,)).fetchone()
    if not item:
        abort(404)
    return send_from_directory(MATERIAL_FOLDER, item["filename"], as_attachment=True)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        if not name:
            flash("Name cannot be empty.", "danger")
        else:
            with get_db() as db:
                db.execute("UPDATE users SET name=?,phone=?,department=? WHERE id=?",
                           (name, phone, department, user["id"]))
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        message = request.form.get("message", "").strip()
        if name and email and message:
            with get_db() as db:
                db.execute("INSERT INTO contacts(name,email,message) VALUES(?,?,?)", (name,email,message))
            flash("Your message has been sent to the library team.", "success")
            return redirect(url_for("contact"))
        flash("Please complete all contact fields.", "danger")
    return render_template("contact.html")

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", code=403, message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", code=404, message="The page or record could not be found."), 404

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
