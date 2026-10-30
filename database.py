import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

# ==================================================
# DATABASE CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "aimt_complaint.db"

VALID_COURSES = ("BTech", "MBA", "MTech", "BCA")
VALID_ROLES = ("student", "staff", "hod")
VALID_SECTIONS = ("A", "B", "C", "D", "E", "F")


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ==================================================
# ADD MISSING COLUMN
# ==================================================

def add_column_if_missing(conn, table, column, definition):
    columns = {
        row["name"]
        for row in conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }

    if column not in columns:
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


# ==================================================
# INITIALIZE DATABASE
# ==================================================

def init_db():

    conn = get_db()

    try:
        conn.executescript("""

            CREATE TABLE IF NOT EXISTS users (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                mobile TEXT NOT NULL,
                password_hash TEXT NOT NULL,

                role TEXT NOT NULL
                    CHECK (role IN ('student', 'staff', 'hod')),

                course TEXT NOT NULL
                    CHECK (course IN ('BTech', 'MBA', 'MTech', 'BCA')),

                year TEXT,
                branch TEXT,
                department TEXT,
                section TEXT,
                roll_number TEXT,

                approval_status TEXT NOT NULL DEFAULT 'PENDING'
                    CHECK (
                        approval_status IN (
                            'PENDING',
                            'APPROVED',
                            'REJECTED'
                        )
                    ),

                profile_photo TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP

            );


            CREATE TABLE IF NOT EXISTS complaints (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL,
                assigned_staff_id INTEGER,
                assigned_hod_id INTEGER,

                title TEXT NOT NULL,
                description TEXT NOT NULL,

                course TEXT NOT NULL,
                year TEXT NOT NULL,
                branch TEXT NOT NULL,
                department TEXT NOT NULL,

                section TEXT,
                attachment TEXT,

                status TEXT NOT NULL DEFAULT 'SUBMITTED'
                    CHECK (
                        status IN (
                            'SUBMITTED',
                            'IN_PROGRESS',
                            'FORWARDED_TO_HOD',
                            'SOLUTION_SENT_TO_STAFF',
                            'RESOLVED',
                            'REJECTED'
                        )
                    ),

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (student_id) REFERENCES users(id),
                FOREIGN KEY (assigned_staff_id) REFERENCES users(id),
                FOREIGN KEY (assigned_hod_id) REFERENCES users(id)

            );


            CREATE TABLE IF NOT EXISTS complaint_solutions (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                complaint_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                solution TEXT NOT NULL,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (complaint_id)
                    REFERENCES complaints(id) ON DELETE CASCADE,

                FOREIGN KEY (author_id)
                    REFERENCES users(id)

            );


            CREATE TABLE IF NOT EXISTS notifications (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                complaint_id INTEGER,
                message TEXT NOT NULL,

                is_read INTEGER NOT NULL DEFAULT 0,

                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (user_id) REFERENCES users(id),

                FOREIGN KEY (complaint_id)
                    REFERENCES complaints(id) ON DELETE CASCADE

            );

        """)

        # MIGRATION

        add_column_if_missing(conn, "users", "section", "TEXT")
        add_column_if_missing(conn, "users", "roll_number", "TEXT")
        add_column_if_missing(conn, "users", "profile_photo", "TEXT")
        add_column_if_missing(conn, "complaints", "section", "TEXT")

        # DATABASE INDEXES

        conn.executescript("""

            CREATE INDEX IF NOT EXISTS idx_users_course_department
            ON users(course, year, department, role);

            CREATE INDEX IF NOT EXISTS idx_users_course_year_section
            ON users(course, year, section, role, approval_status);

            CREATE INDEX IF NOT EXISTS idx_complaints_student
            ON complaints(student_id);

            CREATE INDEX IF NOT EXISTS idx_complaints_status
            ON complaints(status);

            CREATE INDEX IF NOT EXISTS idx_complaints_section
            ON complaints(course, year, section, status);

            CREATE INDEX IF NOT EXISTS idx_notifications_user
            ON notifications(user_id, is_read);

        """)

        conn.commit()

    finally:
        conn.close()


# ==================================================
# CREATE USER ACCOUNT
# ==================================================

def create_user(
    full_name,
    email,
    mobile,
    password,
    role,
    course,
    year=None,
    branch=None,
    department=None,
    roll_number=None,
    section=None
):

    full_name = (full_name or "").strip()
    email = (email or "").strip().lower()
    mobile = (mobile or "").strip()
    role = (role or "").strip().lower()
    course = (course or "").strip()

    year = (year or "").strip() or None
    section = (section or "").strip().upper() or None
    branch = (branch or "").strip() or None
    department = (department or "").strip() or None
    roll_number = (roll_number or "").strip() or None

    # REQUIRED VALIDATION

    if not full_name:
        raise ValueError("Please enter your full name.")

    if not email:
        raise ValueError("Please enter your email address.")

    if not mobile:
        raise ValueError("Please enter your mobile number.")

    if not password:
        raise ValueError("Please enter your password.")

    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    if role not in VALID_ROLES:
        raise ValueError("Invalid account role.")

    if course not in VALID_COURSES:
        raise ValueError("Please select a valid course.")

    if not mobile.isdigit() or len(mobile) != 10:
        raise ValueError("Enter a valid 10-digit mobile number.")

    if role in ("student", "staff") and not year:
        raise ValueError("Please select your year.")

    # SECTION VALIDATION

    if role == "hod":
        section = None

    elif role in ("student", "staff"):

        if section not in VALID_SECTIONS:
            raise ValueError("Please select a valid section (A-F).")

    # STUDENT ROLL NUMBER

    if role == "student" and not roll_number:
        raise ValueError("Student roll number is required.")

    # ACCOUNT APPROVAL

    if role == "hod":
        approval_status = "APPROVED"
    else:
        approval_status = "PENDING"

    # PASSWORD HASH

    password_hash = generate_password_hash(password)

    # INSERT USER

    conn = get_db()

    try:

        cursor = conn.execute("""

            INSERT INTO users (

                full_name,
                email,
                mobile,
                password_hash,
                role,
                course,
                year,
                branch,
                department,
                section,
                roll_number,
                approval_status

            )

            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

        """, (

            full_name,
            email,
            mobile,
            password_hash,
            role,
            course,
            year,
            branch,
            department,
            section,
            roll_number,
            approval_status

        ))

        conn.commit()

        return cursor.lastrowid

    except sqlite3.IntegrityError as exc:

        if "email" in str(exc).lower():
            raise ValueError(
                "This email is already registered."
            ) from exc

        raise

    finally:
        conn.close()


# ==================================================
# VERIFY PASSWORD
# ==================================================

def verify_password(stored_hash, password):

    if not stored_hash or not password:
        return False

    return check_password_hash(
        stored_hash,
        password
    )


# ==================================================
# CREATE NOTIFICATION
# ==================================================

def create_notification(db, uid, message, cid=None):

    db.execute("""

        INSERT INTO notifications (
            user_id,
            complaint_id,
            message
        )

        VALUES (?, ?, ?)

    """, (uid, cid, message))


# ==================================================
# GET USER BY EMAIL
# ==================================================

def get_user_by_email(email):

    email = (email or "").strip().lower()

    conn = get_db()

    try:

        return conn.execute("""

            SELECT *
            FROM users
            WHERE email = ?

        """, (email,)).fetchone()

    finally:
        conn.close()


# ==================================================
# GET USER BY ID
# ==================================================

def get_user_by_id(user_id):

    conn = get_db()

    try:

        return conn.execute("""

            SELECT *
            FROM users
            WHERE id = ?

        """, (user_id,)).fetchone()

    finally:
        conn.close()


# ==================================================
# SHOW ALL REGISTERED USERS
# ==================================================

def show_all_users():

    conn = get_db()

    try:

        users = conn.execute("""

            SELECT
                id,
                full_name,
                email,
                role,
                course,
                department
            FROM users
            ORDER BY id

        """).fetchall()

        print("\n========== REGISTERED USERS ==========")

        if not users:
            print("No users found in this database.")

        for user in users:

            print(
                f"ID: {user['id']} | "
                f"Name: {user['full_name']} | "
                f"Email: {user['email']} | "
                f"Role: {user['role']} | "
                f"Course: {user['course']} | "
                f"Department: {user['department']}"
            )

    finally:
        conn.close()


# ==================================================
# FIX OLD HOD ACCOUNT
# ==================================================

def fix_old_hod_account(email):

    email = (email or "").strip().lower()

    if not email:
        print("No email entered. No account was changed.")
        return

    conn = get_db()

    try:

        user = conn.execute("""

            SELECT id, full_name, email, role
            FROM users
            WHERE email = ?

        """, (email,)).fetchone()

        if user is None:
            print("HOD email not found. No account was changed.")
            return

        print("\nSelected Account:")
        print("ID:", user["id"])
        print("Name:", user["full_name"])
        print("Email:", user["email"])
        print("Current Role:", user["role"])

        confirm = input(
            "\nIf this is the correct HOD account, type YES: "
        ).strip()

        if confirm != "YES":
            print("Update cancelled.")
            return

        conn.execute("""

            UPDATE users
            SET role = 'hod',
                approval_status = 'APPROVED'
            WHERE id = ?

        """, (user["id"],))

        conn.commit()

        print("\nHOD account updated successfully!")

    finally:
        conn.close()


# ==================================================
# RUN DATABASE FILE DIRECTLY
# ==================================================

if __name__ == "__main__":

    init_db()

    print("\nAIMT database initialized successfully!")
    print(f"Database location: {DATABASE_PATH}")

    show_all_users()

    print("\nEnter the exact registered HOD email.")
    hod_email = input("HOD Email (press Enter to skip): ").strip()

    if hod_email:
        fix_old_hod_account(hod_email)