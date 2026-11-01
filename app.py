import os
import sqlite3
import secrets

from pathlib import Path
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    send_from_directory,
    current_app,
    jsonify,
    g,
)

from werkzeug.utils import secure_filename
from werkzeug.security import (
    check_password_hash,
    generate_password_hash
)

from database import (
    get_db,
    init_db,
    create_user,
    verify_password,
    deactivate_user,
    activate_user,
    create_notification,
    add_complaint_status_history,
    get_complaint_status_history,
)


# =========================================================
# APP CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config["SECRET_KEY"] = os.environ.get(
    "AIMT_SECRET_KEY",
    secrets.token_hex(32)
)

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

UPLOAD_FOLDER = BASE_DIR / "uploads" / "complaints"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)


# =========================================================
# PROFILE PHOTO CONFIGURATION
# =========================================================

PROFILE_PHOTO_FOLDER = BASE_DIR / "uploads" / "profile_photos"
PROFILE_PHOTO_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["PROFILE_PHOTO_FOLDER"] = str(PROFILE_PHOTO_FOLDER)

ALLOWED_PROFILE_PHOTO_EXTENSIONS = {
    "jpg", "jpeg", "png", "webp"
}


# =========================================================
# VALIDATION LISTS
# =========================================================

VALID_COURSES = ["BTech", "MBA", "MTech", "BCA"]

VALID_ROLES = ["student", "staff", "hod"]

VALID_YEARS = [
    "1st Year",
    "2nd Year",
    "3rd Year",
    "4th Year",
]

VALID_SECTIONS = ["A", "B", "C", "D", "E", "F"]

VALID_BRANCHES = [
    "CSE",
    "Data Science",
    "AIML",
    "Mechanical",
]

ALLOWED_EXTENSIONS = {
    "pdf",
    "png",
    "jpg",
    "jpeg",
    "doc",
    "docx",
}

VALID_STATUSES = {
    "SUBMITTED",
    "IN_PROGRESS",
    "FORWARDED_TO_HOD",
    "SOLUTION_SENT_TO_STAFF",
    "RESOLVED",
    "REJECTED",
}


# =========================================================
# DATABASE HELPERS
# =========================================================

@app.before_request
def initialize_database():
    """
    Initialize the database when a request arrives.
    The database function preserves existing records.
    """

    if not getattr(app, "_database_initialized", False):
        init_db()
        app._database_initialized = True


def query_db(query, args=(), one=False):

    db = get_db()

    try:
        rows = db.execute(query, args).fetchall()

        return (rows[0] if rows else None) if one else rows

    finally:
        db.close()


def execute_db(query, args=()):

    db = get_db()

    try:
        cursor = db.execute(query, args)
        db.commit()

        return cursor.lastrowid

    finally:
        db.close()


def get_user_by_id(user_id):

    if not user_id:
        return None

    return query_db(
        "SELECT * FROM users WHERE id = ?",
        (user_id,),
        one=True,
    )


def get_current_user():

    if hasattr(g, "current_user"):
        return g.current_user

    user_id = session.get("user_id")

    if not user_id:
        g.current_user = None
        return None

    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        g.current_user = None
        return None

    g.current_user = user

    return user


@app.context_processor
def inject_current_user():

    return {
        "current_user": get_current_user(),
        "valid_courses": VALID_COURSES,
        "valid_years": VALID_YEARS,
        "valid_sections": VALID_SECTIONS,
    }

# =========================================================
# AUTHORIZATION HELPERS
# =========================================================

def role_required(*roles):

    def decorator(view_function):

        @wraps(view_function)
        def wrapped(*args, **kwargs):

            user = get_current_user()

            if not user:
                flash("Please login to continue.", "warning")
                return redirect(url_for("login"))

            # Check whether account is active
            if not user["is_active"]:
                session.clear()

                flash(
                    "Your account has been deactivated. "
                    "Please contact your department authority.",
                    "danger"
                )

                return redirect(url_for("login"))

            # Check account approval
            if user["approval_status"] != "APPROVED":
                session.clear()

                flash(
                    "Your account is not approved yet.",
                    "warning"
                )

                return redirect(url_for("login"))

            # Check user role
            if user["role"] not in roles:
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped

    return decorator

# =========================================================
# DEPARTMENT AND YEAR HELPERS
# =========================================================

def normalize_department(value):

    if not value:
        return ""

    value = value.strip().lower()

    aliases = {
        "cse": "CSE",
        "computer science": "CSE",
        "computer science and engineering": "CSE",

        "data science": "Data Science",
        "datascience": "Data Science",
        "ds": "Data Science",

        "aiml": "AIML",
        "ai/ml": "AIML",
        "ai and ml": "AIML",
        "artificial intelligence and machine learning": "AIML",

        "mechanical": "Mechanical",
        "mechanical engineering": "Mechanical",
    }

    return aliases.get(value, value.title())


def normalize_year(value):

    if not value:
        return None

    value = value.strip()

    aliases = {
        "1": "1st Year",
        "1st": "1st Year",
        "1st year": "1st Year",

        "2": "2nd Year",
        "2nd": "2nd Year",
        "2nd year": "2nd Year",

        "3": "3rd Year",
        "3rd": "3rd Year",
        "3rd year": "3rd Year",

        "4": "4th Year",
        "4th": "4th Year",
        "4th year": "4th Year",
    }

    return aliases.get(value.lower(), value)


def get_user_department(user):

    if not user:
        return ""

    return normalize_department(
        user["department"] or user["branch"] or ""
    )


# =========================================================
# FILE UPLOAD HELPERS
# =========================================================

def allowed_file(filename):

    if not filename or "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in ALLOWED_EXTENSIONS


def save_attachment(file):

    if not file or not file.filename:
        return None

    if not allowed_file(file.filename):

        raise ValueError(
            "Only PDF, PNG, JPG, JPEG, DOC and DOCX files are allowed."
        )

    original_name = secure_filename(file.filename)

    if not original_name:
        raise ValueError("Invalid attachment filename.")

    extension = original_name.rsplit(".", 1)[1].lower()

    stored_name = (
        secrets.token_hex(16) + "." + extension
    )

    destination = UPLOAD_FOLDER / stored_name

    file.save(destination)

    return stored_name


# =========================================================
# NOTIFICATION HELPERS
# =========================================================

def notify_user(user_id, message, complaint_id=None):

    if not user_id:
        return

    db = get_db()

    try:

        create_notification(
            db,
            user_id,
            message,
            complaint_id,
        )

        db.commit()

    finally:
        db.close()


def notify_complaint_participants(complaint, message):

    user_ids = {
        complaint["student_id"],
        complaint["assigned_staff_id"],
        complaint["assigned_hod_id"],
    }

    for user_id in user_ids:

        if user_id:

            notify_user(
                user_id,
                message,
                complaint["id"],
            )


# =========================================================
# COMPLAINT HELPERS
# =========================================================

def get_complaint(complaint_id):

    return query_db(
        """
        SELECT
            c.*,
            s.full_name AS student_name,
            s.email AS student_email,
            s.roll_number AS student_roll_number,
            s.mobile AS student_mobile,
            st.full_name AS staff_name,
            h.full_name AS hod_name

        FROM complaints c

        JOIN users s ON s.id = c.student_id

        LEFT JOIN users st ON st.id = c.assigned_staff_id

        LEFT JOIN users h ON h.id = c.assigned_hod_id

        WHERE c.id = ?
        """,
        (complaint_id,),
        one=True,
    )


def get_matching_staff(course, year, section, department):

    return query_db(
        """
        SELECT *
        FROM users

        WHERE role = 'staff'
          AND approval_status = 'APPROVED'
          AND course = ?
          AND year = ?
          AND section = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)

        ORDER BY id
        """,
        (
            course,
            normalize_year(year),
            section,
            normalize_department(department),
        ),
    )


def get_matching_hods(course, year, department):

    return query_db(
        """
        SELECT *
        FROM users

        WHERE role = 'hod'
          AND approval_status = 'APPROVED'
          AND course = ?
          AND year = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)

        ORDER BY id
        """,
        (
            course,
            normalize_year(year),
            normalize_department(department),
        ),
    )


def staff_matches_complaint(staff, complaint):

    return (
        staff["role"] == "staff"
        and staff["course"] == complaint["course"]
        and normalize_year(staff["year"])
        == normalize_year(complaint["year"])
        and staff["section"] == complaint["section"]
        and get_user_department(staff)
        == normalize_department(complaint["department"])
    )


def hod_matches_complaint(hod, complaint):

    return (
        hod["role"] == "hod"
        and hod["course"] == complaint["course"]
        and normalize_year(hod["year"])
        == normalize_year(complaint["year"])
        and get_user_department(hod)
        == normalize_department(complaint["department"])
    )


def get_complaint_solutions(complaint_id):

    return query_db(
        """
        SELECT
            cs.*,
            u.full_name AS author_name,
            u.role AS author_role

        FROM complaint_solutions cs

        JOIN users u ON u.id = cs.author_id

        WHERE cs.complaint_id = ?

        ORDER BY cs.id ASC
        """,
        (complaint_id,),
    )


def add_solution(complaint_id, author_id, solution):

    solution = (solution or "").strip()

    if not solution:
        raise ValueError("Please enter a response.")

    execute_db(
        """
        INSERT INTO complaint_solutions (
            complaint_id,
            author_id,
            solution
        )
        VALUES (?, ?, ?)
        """,
        (
            complaint_id,
            author_id,
            solution,
        ),
    )


def update_complaint_status(complaint_id, status):

    if status not in VALID_STATUSES:
        raise ValueError("Invalid complaint status.")

    execute_db(
        """
        UPDATE complaints
        SET status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (
            status,
            complaint_id,
        ),
    )

# =========================================================
# DASHBOARD ANALYTICS HELPER
# =========================================================

def get_dashboard_analytics(scope_sql, params=()):
    """
    Returns complaint statistics for a dashboard.
    scope_sql must contain a trusted SQL condition.
    """

    complaints = query_db(
        f"""
        SELECT status, COUNT(*) AS total
        FROM complaints
        WHERE {scope_sql}
        GROUP BY status
        """,
        params
    )

    status_counts = {
        row["status"]: row["total"]
        for row in complaints
    }

    total = sum(status_counts.values())

    pending = (
        status_counts.get("SUBMITTED", 0)
    )

    in_progress = (
        status_counts.get("IN_PROGRESS", 0)
    )

    forwarded = (
        status_counts.get("FORWARDED_TO_HOD", 0)
        + status_counts.get("SOLUTION_SENT_TO_STAFF", 0)
    )

    resolved = status_counts.get("RESOLVED", 0)
    rejected = status_counts.get("REJECTED", 0)

    # Department-wise complaint count
    department_rows = query_db(
        f"""
        SELECT
            COALESCE(NULLIF(department, ''), 'Not Specified') AS department,
            COUNT(*) AS total
        FROM complaints
        WHERE {scope_sql}
        GROUP BY department
        ORDER BY total DESC
        """,
        params
    )

    # Monthly complaint count - last 6 months
    monthly_rows = query_db(
        f"""
        SELECT
            strftime('%Y-%m', created_at) AS month,
            COUNT(*) AS total
        FROM complaints
        WHERE {scope_sql}
          AND created_at >= date('now', '-5 months', 'start of month')
        GROUP BY strftime('%Y-%m', created_at)
        ORDER BY month
        """,
        params
    )

    return {
        "total": total,
        "pending": pending,
        "in_progress": in_progress,
        "forwarded": forwarded,
        "resolved": resolved,
        "rejected": rejected,
         "status_labels": [
        "Pending",
        "In Progress",
        "Forwarded",
        "Resolved",
        "Rejected"
    ],

    "status_values": [
        pending,
        in_progress,
        forwarded,
        resolved,
        rejected
    ],
        "department_labels": [
            row["department"] for row in department_rows
        ],
        "department_values": [
            row["total"] for row in department_rows
        ],

        "monthly_labels": [
            row["month"] for row in monthly_rows
        ],
        "monthly_values": [
            row["total"] for row in monthly_rows
        ],
    }


# =========================================================
# COMPLAINT ACCESS CONTROL
# =========================================================

def complaint_access_required(complaint, user):

    if not complaint or not user:
        abort(404)

    if user["role"] == "student":

        if complaint["student_id"] != user["id"]:
            abort(403)

    elif user["role"] == "staff":

        if not staff_matches_complaint(user, complaint):
            abort(403)

        if (
            complaint["assigned_staff_id"] is not None
            and complaint["assigned_staff_id"] != user["id"]
        ):
            abort(403)

    elif user["role"] == "hod":

        if not hod_matches_complaint(user, complaint):
            abort(403)

        if (
            complaint["assigned_hod_id"] is not None
            and complaint["assigned_hod_id"] != user["id"]
        ):
            abort(403)

    else:
        abort(403)
# =========================================================
# COMPLAINT TIMELINE HELPER
# =========================================================

def record_complaint_history(
    complaint_id,
    status,
    updated_by=None,
    remarks=None
):
    db = get_db()

    try:
        add_complaint_status_history(
            db,
            complaint_id,
            status,
            updated_by,
            remarks
        )
        db.commit()

    finally:
        db.close()


# =========================================================
# HOME PAGE
# =========================================================

@app.route("/")
def home():

    user = get_current_user()

    if user and user["approval_status"] == "APPROVED":

        if user["role"] == "student":
            return redirect(url_for("student_dashboard"))

        if user["role"] == "staff":
            return redirect(url_for("staff_dashboard"))

        if user["role"] == "hod":
            return redirect(url_for("hod_dashboard"))

    return render_template("home.html")


# =========================================================
# REGISTRATION
# =========================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        role = request.form.get("role", "").strip().lower()
        course = request.form.get("course", "").strip()

        year = normalize_year(
            request.form.get("year", "")
        )

        section = request.form.get(
            "section", ""
        ).strip().upper()

        roll_number = request.form.get(
            "roll_number", ""
        ).strip()

        branch = normalize_department(
            request.form.get("branch", "")
        )

        department = normalize_department(
            request.form.get("department", "")
        )

        try:

            if not all([
                full_name,
                email,
                mobile,
                password,
                confirm_password,
                role,
                course,
            ]):
                raise ValueError(
                    "Please fill in all required fields."
                )

            if role not in VALID_ROLES:
                raise ValueError("Please select a valid role.")

            if course not in VALID_COURSES:
                raise ValueError("Please select a valid course.")

            if password != confirm_password:
                raise ValueError("Passwords do not match.")

            if len(password) < 8:
                raise ValueError(
                    "Password must contain at least 8 characters."
                )

            if not mobile.isdigit() or len(mobile) != 10:
                raise ValueError(
                    "Enter a valid 10-digit mobile number."
                )

            if year not in VALID_YEARS:
                raise ValueError("Please select a valid year.")

            if role in ("student", "staff"):

                if section not in VALID_SECTIONS:
                    raise ValueError(
                        "Please select a section from A to F."
                    )

            else:
                # HOD supervises all sections.
                section = None

            if role == "student":

                if not roll_number:
                    raise ValueError(
                        "Student roll number is required."
                    )

                if branch not in VALID_BRANCHES:
                    raise ValueError(
                        "Please select a valid branch."
                    )

                department = branch

            elif role == "staff":

                if not department:
                    raise ValueError(
                        "Please select the staff department."
                    )

                branch = department

            elif role == "hod":

                if not department:
                    raise ValueError(
                        "Please select the HOD department."
                    )

                branch = department

            create_user(
                full_name=full_name,
                email=email,
                mobile=mobile,
                password=password,
                role=role,
                course=course,
                year=year,
                branch=branch,
                department=department,
                roll_number=roll_number if role == "student" else None,
                section=section,
            )

            if role == "student":

                flash(
                    "Registration successful. You can now login.",
                    "success",
                )

            else:

                flash(
                    "Registration submitted. Your account requires approval.",
                    "info",
                )

            return redirect(url_for("login"))

        except ValueError as exc:
            flash(str(exc), "danger")

        except sqlite3.IntegrityError:
            flash(
                "This email or another unique field is already registered.",
                "danger",
            )

    return render_template("auth/register.html")


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get("password", "")

        user = query_db(
            "SELECT * FROM users WHERE email = ?",
            (email,),
            one=True,
        )

        if not user or not verify_password(
            user["password_hash"],
            password,
        ):

            flash("Invalid email or password.", "danger")

            return render_template("auth/login.html")

        if user["approval_status"] != "APPROVED":

            if user["approval_status"] == "REJECTED":

                flash(
                    "Your account registration was rejected. Contact the authorized college administrator.",
                    "danger",
                )

            else:

                flash(
                    "Your account is awaiting approval.",
                    "warning",
                )

            return render_template("auth/login.html")

        session.clear()

        session["user_id"] = user["id"]
        session["role"] = user["role"]

        flash(
            f"Welcome, {user['full_name']}!",
            "success",
        )

        if user["role"] == "student":
            return redirect(url_for("student_dashboard"))

        if user["role"] == "staff":
            return redirect(url_for("staff_dashboard"))

        if user["role"] == "hod":
            return redirect(url_for("hod_dashboard"))

    return render_template("auth/login.html")


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "info")

    return redirect(url_for("home"))


# =========================================================
# STUDENT DASHBOARD
# =========================================================

@app.route("/student/dashboard")
@role_required("student")
def student_dashboard():

    user = get_current_user()

    complaints = query_db(
        """
        SELECT *
        FROM complaints
        WHERE student_id = ?
        ORDER BY created_at DESC
        """,
        (user["id"],),
    )

    stats = {

        "total": len(complaints),

        "pending": sum(
            c["status"] in ("SUBMITTED", "IN_PROGRESS")
            for c in complaints
        ),

        "forwarded": sum(
            c["status"] in (
                "FORWARDED_TO_HOD",
                "SOLUTION_SENT_TO_STAFF",
            )
            for c in complaints
        ),

        "resolved": sum(
            c["status"] == "RESOLVED"
            for c in complaints
        ),

    }
    analytics = get_dashboard_analytics(
        "student_id = ?",
        (user["id"],)
    )

    return render_template(
        "student/dashboard.html",
        user=user,
        complaints=complaints,
        stats=stats,
        analytics=analytics,
    )


# =========================================================
# CREATE NEW COMPLAINT
# =========================================================

@app.route("/student/new-complaint", methods=["GET", "POST"])
@role_required("student")
def new_complaint():

    user = get_current_user()

    if request.method == "POST":

        title = request.form.get(
            "title", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        if not title or not description:

            flash(
                "Please enter the complaint title and description.",
                "danger",
            )

            return render_template(
                "student/new_complaint.html",
                user=user,
            )

        if not user["year"] or not user["section"]:

            flash(
                "Your profile is missing year or section. Update your profile first.",
                "danger",
            )

            return redirect(url_for("edit_profile"))

        department = get_user_department(user)

        if not department:

            flash(
                "Your profile is missing a branch or department.",
                "danger",
            )

            return redirect(url_for("edit_profile"))

        attachment_name = None

        try:

            attachment = request.files.get("attachment")

            if attachment and attachment.filename:
                attachment_name = save_attachment(attachment)

            complaint_id = execute_db(
                """
                INSERT INTO complaints (
                    student_id,
                    title,
                    description,
                    course,
                    year,
                    branch,
                    department,
                    section,
                    attachment,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'SUBMITTED')
                """,
                (
                    user["id"],
                    title,
                    description,
                    user["course"],
                    normalize_year(user["year"]),
                    user["branch"] or department,
                    department,
                    user["section"],
                    attachment_name,
                ),
            )

            # Timeline: Complaint submitted
            record_complaint_history(
                complaint_id,
                "SUBMITTED",
                user["id"],
                "Complaint submitted by student."
            )

            staff_members = get_matching_staff(
                user["course"],
                user["year"],
                user["section"],
                department,
            )

            if staff_members:

                assigned_staff = staff_members[0]

                execute_db(
                    """
                    UPDATE complaints
                    SET assigned_staff_id = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (
                        assigned_staff["id"],
                        complaint_id,
                    ),
                )

                # Timeline: Assigned to staff
                record_complaint_history(
                    complaint_id,
                    "ASSIGNED_TO_STAFF",
                    assigned_staff["id"],
                    "Complaint assigned to staff."
                )

                notify_user(
                    assigned_staff["id"],
                    f"New complaint assigned: {title}",
                    complaint_id,
                )

            else:

                flash(
                    "Your complaint was submitted, but no approved matching staff member was found.",
                    "warning",
                )

            notify_user(
                user["id"],
                f"Your complaint '{title}' was submitted successfully.",
                complaint_id,
            )

            flash(
                "Complaint submitted successfully.",
                "success",
            )

            return redirect(url_for("my_complaints"))

        except ValueError as exc:
            flash(str(exc), "danger")

    return render_template(
        "student/new_complaint.html",
        user=user,
    )


# =========================================================
# STUDENT COMPLAINT LIST
# =========================================================

@app.route("/student/my-complaints")
@role_required("student")
def my_complaints():

    user = get_current_user()

    complaints = query_db(
        """
        SELECT
            c.*,
            st.full_name AS staff_name,
            h.full_name AS hod_name

        FROM complaints c

        LEFT JOIN users st
            ON st.id = c.assigned_staff_id

        LEFT JOIN users h
            ON h.id = c.assigned_hod_id

        WHERE c.student_id = ?

        ORDER BY c.created_at DESC
        """,
        (user["id"],),
    )

    complaint_trackings = {}

    for complaint in complaints:

        complaint_trackings[complaint["id"]] = get_complaint_solutions(
            complaint["id"]
        )

    return render_template(
        "student/my_complaints.html",
        user=user,
        complaints=complaints,
        complaint_trackings=complaint_trackings
    )


# =========================================================
# STUDENT COMPLAINT DETAILS AND TIMELINE
# =========================================================

@app.route("/student/complaint/<int:complaint_id>")
@role_required("student")
def student_complaint_details(complaint_id):

    user = get_current_user()

    complaint = get_complaint(complaint_id)

    if not complaint:
        abort(404)

    if complaint["student_id"] != user["id"]:
        abort(403)

    timeline = get_complaint_status_history(complaint_id)

    # Older complaints may not have timeline entries.
    if not timeline:

        record_complaint_history(
            complaint_id,
            complaint["status"],
            None,
            "Existing complaint: current status recorded."
        )

        timeline = get_complaint_status_history(complaint_id)

    solutions = get_complaint_solutions(complaint_id)

    return render_template(
    "student/complaint_details.html",
    user=user,
    complaint=complaint,
    solutions=solutions,
    history=get_complaint_status_history(complaint_id)
)
    
# =========================================================
# STAFF DASHBOARD
# =========================================================

@app.route("/staff/dashboard")
@role_required("staff")
def staff_dashboard():

    user = get_current_user()

    department = get_user_department(user)

    complaints = query_db(
        """
        SELECT
            c.*,
            s.full_name AS student_name,
            s.roll_number AS student_roll_number
        FROM complaints c
        JOIN users s ON s.id = c.student_id
        WHERE c.course = ?
          AND c.year = ?
          AND c.section = ?
          AND LOWER(c.department) = LOWER(?)
          AND (
              c.assigned_staff_id = ?
              OR c.assigned_staff_id IS NULL
          )
        ORDER BY c.created_at DESC
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            user["section"],
            department,
            user["id"]
        )
    )

    stats = {
        "total": len(complaints),

        "pending": sum(
            c["status"] == "SUBMITTED"
            for c in complaints
        ),

        "in_progress": sum(
            c["status"] == "IN_PROGRESS"
            for c in complaints
        ),

        "forwarded": sum(
            c["status"] == "FORWARDED_TO_HOD"
            for c in complaints
        ),

        "resolved": sum(
            c["status"] == "RESOLVED"
            for c in complaints
        )
    }

    analytics = get_dashboard_analytics(
        """
        course = ?
        AND year = ?
        AND section = ?
        AND LOWER(department) = LOWER(?)
        AND (
            assigned_staff_id = ?
            OR assigned_staff_id IS NULL
        )
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            user["section"],
            department,
            user["id"]
        )
    )

    return render_template(
        "staff/dashboard.html",
        user=user,
        complaints=complaints,
        stats=stats,
        analytics=analytics
    )

# =========================================================
# STAFF - ACTIVE AND DEACTIVATED STUDENTS
# =========================================================

@app.route("/staff/students")
@role_required("staff")
def staff_students():

    user = get_current_user()

    # ACTIVE STUDENTS
    students = query_db(
        """
        SELECT
            id, full_name, email, mobile, roll_number,
            course, year, branch, department, section,
            approval_status, is_active, created_at
        FROM users
        WHERE LOWER(TRIM(role)) = 'student'
          AND is_active = 1
        ORDER BY created_at DESC
        """
    )

    # DEACTIVATED STUDENTS
    deactivated_students = query_db(
        """
        SELECT
            id, full_name, email, mobile, roll_number,
            course, year, branch, department, section,
            approval_status, is_active, created_at
        FROM users
        WHERE LOWER(TRIM(role)) = 'student'
          AND is_active = 0
        ORDER BY created_at DESC
        """
    )

    return render_template(
        "staff/students.html",
        user=user,
        students=students,
        deactivated_students=deactivated_students
    )

# =========================================================
# STAFF - SEARCH STUDENTS (OLD + NEW STUDENTS)
# =========================================================

@app.route("/staff/student-search")
@role_required("staff")
def staff_student_search():

    user = get_current_user()

    search = request.args.get("q", "").strip()

    department = get_user_department(user)
    normalized_year = str(normalize_year(user["year"])).strip()

    students = []

    if search:

        students = query_db(
            """
            SELECT
                id,
                full_name,
                email,
                mobile,
                roll_number,
                course,
                year,
                branch,
                department,
                section,
                approval_status,
                is_active
            FROM users

            WHERE LOWER(TRIM(role)) = 'student'

              -- Same course
              AND LOWER(TRIM(COALESCE(course, ''))) =
                  LOWER(TRIM(?))

              -- Same department, including legacy blank department
              AND (
                    LOWER(TRIM(
                        COALESCE(
                            NULLIF(TRIM(department), ''),
                            NULLIF(TRIM(branch), ''),
                            ''
                        )
                    )) = LOWER(TRIM(?))

                    OR department IS NULL
                    OR TRIM(department) = ''
                    OR branch IS NULL
                    OR TRIM(branch) = ''
              )

              -- Same year, including legacy blank year
              AND (
                    LOWER(TRIM(CAST(year AS TEXT))) =
                        LOWER(TRIM(?))

                    OR year IS NULL
                    OR TRIM(CAST(year AS TEXT)) = ''
              )

              -- Same section, including legacy blank section
              AND (
                    LOWER(TRIM(COALESCE(section, ''))) =
                        LOWER(TRIM(?))

                    OR section IS NULL
                    OR TRIM(section) = ''
              )

              -- Search by student name or roll number
              AND (
                    LOWER(COALESCE(full_name, '')) LIKE LOWER(?)

                    OR LOWER(COALESCE(roll_number, '')) LIKE LOWER(?)
              )

            ORDER BY full_name ASC
            """,
            (
                user["course"],
                department,
                normalized_year,
                str(user["section"] or ""),
                f"%{search}%",
                f"%{search}%"
            )
        )

    return render_template(
        "staff/student_search.html",
        user=user,
        students=students,
        search=search
    )

# =========================================================
# TEMPORARY - CHECK STAFF AND OLD STUDENT DATA
# =========================================================

@app.route("/staff/debug-student-search")
@role_required("staff")
def debug_student_search():

    user = get_current_user()

    students = query_db("""
        SELECT
            id,
            full_name,
            course,
            year,
            branch,
            department,
            section,
            roll_number,
            is_active
        FROM users
        WHERE LOWER(TRIM(role)) = 'student'
        ORDER BY id DESC
        LIMIT 20
    """)

    return {
        "staff": {
            "course": user["course"],
            "year": user["year"],
            "department": user["department"],
            "branch": user["branch"],
            "section": user["section"]
        },
        "students": [dict(row) for row in students]
    }
# =========================================================
# STAFF - VIEW STUDENT PROFILE WITH COMPLAINTS
# =========================================================

@app.route("/staff/student/<int:user_id>")
@role_required("staff")
def staff_view_student(user_id):

    user = get_current_user()

    department = get_user_department(user)

    student = query_db(
        """
        SELECT *
        FROM users
        WHERE id = ?
          AND LOWER(TRIM(role)) = 'student'
          AND course = ?
          AND LOWER(TRIM(CAST(year AS TEXT))) = LOWER(TRIM(?))
          AND LOWER(TRIM(COALESCE(department, branch, ''))) = LOWER(TRIM(?))
          AND (
                section = ?
                OR section IS NULL
                OR TRIM(section) = ''
          )
        """,
        (
            user_id,
            user["course"],
            str(normalize_year(user["year"])),
            department,
            user["section"]
        ),
        one=True
    )

    if not student:
        abort(404)

    # विद्यार्थी की सभी शिकायतें
    complaints = query_db(
        """
        SELECT
            c.*,
            st.full_name AS staff_name,
            h.full_name AS hod_name
        FROM complaints c
        LEFT JOIN users st
            ON st.id = c.assigned_staff_id
        LEFT JOIN users h
            ON h.id = c.assigned_hod_id
        WHERE c.student_id = ?
        ORDER BY c.created_at DESC
        """,
        (user_id,)
    )

    return render_template(
        "staff/student_profile.html",
        user=user,
        student=student,
        complaints=complaints
    )


# =========================================================
# STAFF STUDENT ACCOUNT ACTIVATE / DEACTIVATE ROUTE
# =========================================================

@app.route("/staff/student-account/<int:user_id>/<action>", methods=["POST"])
@role_required("staff")
def staff_student_account(user_id, action):

    if action not in ("activate", "deactivate"):
        abort(400)

    user = get_current_user()
    department = get_user_department(user)

    student = query_db("""
        SELECT *
        FROM users
        WHERE id = ?
          AND LOWER(TRIM(role)) = 'student'
          AND course = ?
          AND LOWER(TRIM(CAST(year AS TEXT))) = LOWER(TRIM(?))
          AND (
                section = ?
                OR section IS NULL
                OR TRIM(section) = ''
          )
          AND LOWER(TRIM(COALESCE(department, branch, ''))) = LOWER(TRIM(?))
    """, (
        user_id,
        user["course"],
        str(normalize_year(user["year"])),
        user["section"],
        department
    ), one=True)

    if not student:
        flash(
            "Student not found in your assigned department, year or section.",
            "warning"
        )
        return redirect(url_for("staff_students"))

    if action == "deactivate":

        if not deactivate_user(user_id):
            flash("Unable to deactivate student account.", "danger")
        else:
            flash("Student account deactivated successfully.", "success")

    else:

        if not activate_user(user_id):
            flash("Unable to activate student account.", "danger")
        else:
            flash("Student account activated successfully.", "success")

    return redirect(url_for("staff_students"))

# =========================================================
# STAFF CLAIM COMPLAINT
# =========================================================

@app.route("/staff/claim/<int:complaint_id>", methods=["POST"])
@role_required("staff")
def claim_complaint(complaint_id):

    user = get_current_user()
    complaint = get_complaint(complaint_id)

    if not complaint:
        abort(404)

    if not staff_matches_complaint(user, complaint):
        abort(403)

    if complaint["assigned_staff_id"] not in (None, user["id"]):
        flash(
            "This complaint is already assigned to another staff member.",
            "warning"
        )
        return redirect(url_for("staff_dashboard"))

    if complaint["status"] not in ("SUBMITTED", "IN_PROGRESS"):
        flash(
            "This complaint cannot be claimed in its current status.",
            "warning"
        )
        return redirect(url_for("staff_dashboard"))

    execute_db(
        """
        UPDATE complaints
        SET assigned_staff_id = ?,
            status = 'IN_PROGRESS',
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND (
              assigned_staff_id IS NULL
              OR assigned_staff_id = ?
          )
        """,
        (user["id"], complaint_id, user["id"])
    )

    record_complaint_history(
        complaint_id,
        "ASSIGNED_TO_STAFF",
        user["id"],
        "Complaint assigned to staff."
    )

    record_complaint_history(
        complaint_id,
        "IN_PROGRESS",
        user["id"],
        "Staff started working on the complaint."
    )

    notify_user(
        complaint["student_id"],
        "A staff member has started working on your complaint.",
        complaint_id
    )

    flash("Complaint assigned to you.", "success")

    return redirect(
        url_for(
            "staff_complaint_details",
            complaint_id=complaint_id
        )
    )


# =========================================================
# STAFF COMPLAINT DETAILS
# =========================================================

@app.route("/staff/complaint/<int:complaint_id>", methods=["GET", "POST"])
@role_required("staff")
def staff_complaint_details(complaint_id):

    user = get_current_user()
    complaint = get_complaint(complaint_id)

    if not complaint:
        abort(404)

    if not staff_matches_complaint(user, complaint):
        abort(403)

    if (
        complaint["assigned_staff_id"] is not None
        and complaint["assigned_staff_id"] != user["id"]
    ):
        abort(403)

    if request.method == "POST":

        action = request.form.get("action", "").strip().lower()

        if complaint["assigned_staff_id"] is None:
            flash("Claim this complaint before taking action.", "warning")
            return redirect(request.url)

        if action == "claim":
            return redirect(
                url_for(
                    "claim_complaint",
                    complaint_id=complaint_id
                )
            )

        elif action == "forward":

            if complaint["status"] == "RESOLVED":
                flash("A resolved complaint cannot be forwarded.", "warning")
                return redirect(request.url)

            note = request.form.get(
                "solution",
                request.form.get("note", "")
            ).strip()

            if not note:
                flash("Please enter a note before forwarding.", "danger")
                return redirect(request.url)

            hods = get_matching_hods(
                complaint["course"],
                complaint["year"],
                complaint["department"]
            )

            if not hods:
                flash(
                    "No approved HOD matches this course, year and department.",
                    "warning"
                )
                return redirect(request.url)

            hod = hods[0]

            db = get_db()

            try:
                db.execute(
                    """
                    UPDATE complaints
                    SET assigned_hod_id = ?,
                        status = 'FORWARDED_TO_HOD',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (hod["id"], complaint_id)
                )

                db.execute(
                    """
                    INSERT INTO complaint_solutions (
                        complaint_id, author_id, solution
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        complaint_id,
                        user["id"],
                        "Forwarded to HOD: " + note
                    )
                )

                create_notification(
                    db,
                    hod["id"],
                    f"Complaint forwarded to you: {complaint['title']}",
                    complaint_id
                )

                create_notification(
                    db,
                    complaint["student_id"],
                    "Your complaint has been forwarded to the HOD.",
                    complaint_id
                )

                db.commit()

            finally:
                db.close()

            record_complaint_history(
                complaint_id,
                "FORWARDED_TO_HOD",
                user["id"],
                note
            )

            flash("Complaint forwarded to HOD.", "success")

        elif action == "resolve":

            solution = request.form.get("solution", "").strip()

            if not solution:
                flash("Please enter the solution before resolving.", "danger")
                return redirect(request.url)

            add_solution(
                complaint_id,
                user["id"],
                solution
            )

            update_complaint_status(
                complaint_id,
                "RESOLVED"
            )

            record_complaint_history(
                complaint_id,
                "RESOLVED",
                user["id"],
                solution
            )

            notify_user(
                complaint["student_id"],
                "Your complaint has been resolved by staff.",
                complaint_id
            )

            if complaint["assigned_hod_id"]:
                notify_user(
                    complaint["assigned_hod_id"],
                    "The complaint has been resolved by staff.",
                    complaint_id
                )

            flash("Complaint marked as resolved.", "success")

        elif action == "respond":

            solution = request.form.get("solution", "").strip()

            if not solution:
                flash("Please enter your response.", "danger")
                return redirect(request.url)

            add_solution(
                complaint_id,
                user["id"],
                solution
            )

            record_complaint_history(
                complaint_id,
                complaint["status"],
                user["id"],
                solution
            )

            notify_user(
                complaint["student_id"],
                "Staff has added a response to your complaint.",
                complaint_id
            )

            flash("Response added successfully.", "success")

        else:
            flash("Invalid action.", "danger")

        return redirect(
            url_for(
                "staff_complaint_details",
                complaint_id=complaint_id
            )
        )

    complaint = get_complaint(complaint_id)
    solutions = get_complaint_solutions(complaint_id)

    return render_template(
        "staff/complaint_details.html",
        user=user,
        complaint=complaint,
        solutions=solutions
    )

# =========================================================
# HOD DASHBOARD
# =========================================================

@app.route("/hod/dashboard")
@role_required("hod")
def hod_dashboard():

    user = get_current_user()

    # HOD की शिकायतें
    complaints = query_db(
        """
        SELECT
            c.*,
            s.full_name AS student_name,
            s.roll_number AS student_roll_number,
            st.full_name AS staff_name
        FROM complaints c
        JOIN users s ON s.id = c.student_id
        LEFT JOIN users st ON st.id = c.assigned_staff_id
        WHERE c.course = ?
          AND c.year = ?
          AND LOWER(c.department) = LOWER(?)
          AND c.assigned_hod_id = ?
        ORDER BY c.created_at DESC
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            get_user_department(user),
            user["id"]
        )
    )

    # पुराने Statistics
    stats = {
        "total": len(complaints),

        "pending": sum(
            c["status"] == "FORWARDED_TO_HOD"
            for c in complaints
        ),

        "responded": sum(
            c["status"] == "SOLUTION_SENT_TO_STAFF"
            for c in complaints
        ),

        "resolved": sum(
            c["status"] == "RESOLVED"
            for c in complaints
        )
    }

    # Analytics
    analytics = get_dashboard_analytics(
        """
        course = ?
        AND year = ?
        AND LOWER(department) = LOWER(?)
        AND assigned_hod_id = ?
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            get_user_department(user),
            user["id"]
        )
    )

    return render_template(
        "hod/dashboard.html",
        user=user,
        complaints=complaints,
        stats=stats,
        analytics=analytics
    )

# =========================================================
# HOD - ALL STAFF (ACTIVE + DEACTIVATED)
# =========================================================

@app.route("/hod/staff-list")
@role_required("hod")
def hod_staff_list():

    user = get_current_user()
    department = get_user_department(user)

    # Common staff details query
    staff_columns = """
        SELECT
            id,
            full_name,
            email,
            mobile,
            course,
            year,
            branch,
            department,
            section,
            approval_status,
            is_active,
            created_at
        FROM users
        WHERE LOWER(TRIM(role)) = 'staff'
          AND course = ?
          AND year = ?
          AND LOWER(TRIM(COALESCE(department, branch, ''))) = LOWER(TRIM(?))
    """

    # Active Staff
    staff_members = query_db(
        staff_columns + """
          AND is_active = 1
        ORDER BY created_at DESC
        """,
        (
            user["course"],
            user["year"],
            department
        )
    )

    # Deactivated Staff
    deactivated_staff = query_db(
        staff_columns + """
          AND is_active = 0
        ORDER BY created_at DESC
        """,
        (
            user["course"],
            user["year"],
            department
        )
    )

    return render_template(
        "hod/staff_list.html",
        user=user,
        staff_members=staff_members,
        deactivated_staff=deactivated_staff
    )


# =========================================================
# HOD STAFF ACCOUNT ACTIVATE / DEACTIVATE
# =========================================================

@app.route(
    "/hod/staff-account/<int:user_id>/<action>",
    methods=["POST"]
)
@role_required("hod")
def hod_staff_account(user_id, action):

    if action not in ("activate", "deactivate"):
        abort(400)

    user = get_current_user()
    department = get_user_department(user)

    # Check whether staff belongs to this HOD's department
    staff = query_db("""
        SELECT *
        FROM users
        WHERE id = ?
          AND LOWER(TRIM(role)) = 'staff'
          AND course = ?
          AND year = ?
          AND LOWER(TRIM(COALESCE(department, branch, ''))) = LOWER(TRIM(?))
    """, (
        user_id,
        user["course"],
        user["year"],
        department
    ), one=True)

    if not staff:
        abort(404)

    if action == "deactivate":

        if int(staff["is_active"] or 0) == 0:
            flash("This staff account is already deactivated.", "warning")
        else:
            success = deactivate_user(user_id)

            if success:
                flash(
                    "Staff account deactivated successfully.",
                    "success"
                )
            else:
                flash(
                    "Unable to deactivate staff account.",
                    "danger"
                )

    elif action == "activate":

        if int(staff["is_active"] or 0) == 1:
            flash("This staff account is already active.", "warning")
        else:
            success = activate_user(user_id)

            if success:
                flash(
                    "Staff account activated successfully.",
                    "success"
                )
            else:
                flash(
                    "Unable to activate staff account.",
                    "danger"
                )

    return redirect(url_for("hod_staff_list"))

# =========================================================
# HOD COMPLAINT DETAILS
# =========================================================

@app.route("/hod/complaint/<int:complaint_id>", methods=["GET", "POST"])
@role_required("hod")
def hod_complaint_details(complaint_id):

    user = get_current_user()
    complaint = get_complaint(complaint_id)

    if not complaint:
        abort(404)

    if not hod_matches_complaint(user, complaint):
        abort(403)

    if complaint["assigned_hod_id"] != user["id"]:
        abort(403)

    if request.method == "POST":

        action = request.form.get("action", "respond").strip().lower()

        if action != "respond":
            flash("Invalid action.", "danger")
            return redirect(request.url)

        solution = request.form.get("solution", "").strip()

        if not solution:
            flash("Please enter your response.", "danger")
            return redirect(request.url)

        if complaint["status"] != "FORWARDED_TO_HOD":
            flash(
                "This complaint is not awaiting an HOD response.",
                "warning"
            )
            return redirect(request.url)

        db = get_db()

        try:
            db.execute(
                """
                INSERT INTO complaint_solutions (
                    complaint_id, author_id, solution
                )
                VALUES (?, ?, ?)
                """,
                (complaint_id, user["id"], solution)
            )

            db.execute(
                """
                UPDATE complaints
                SET status = 'SOLUTION_SENT_TO_STAFF',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (complaint_id,)
            )

            if complaint["assigned_staff_id"]:
                create_notification(
                    db,
                    complaint["assigned_staff_id"],
                    "HOD has responded. Review the complaint and resolve it.",
                    complaint_id
                )

            create_notification(
                db,
                complaint["student_id"],
                "HOD has responded to your complaint.",
                complaint_id
            )

            db.commit()

        finally:
            db.close()

        record_complaint_history(
            complaint_id,
            "SOLUTION_SENT_TO_STAFF",
            user["id"],
            solution
        )

        flash(
            "Your response has been sent to the assigned staff member.",
            "success"
        )

        return redirect(
            url_for(
                "hod_complaint_details",
                complaint_id=complaint_id
            )
        )

    return render_template(
        "hod/complaint_details.html",
        user=user,
        complaint=complaint,
        solutions=get_complaint_solutions(complaint_id)
    )
    
# =========================================================
# PROFILE PHOTO UPLOAD / REMOVE / DISPLAY
# =========================================================

@app.route("/upload-profile-photo", methods=["POST"])
@role_required("student", "staff", "hod")
def upload_profile_photo():

    user = get_current_user()
    photo = request.files.get("profile_photo")

    if not photo or not photo.filename:
        flash("Please select a photo.", "warning")
        return redirect(url_for("profile"))

    filename = secure_filename(photo.filename)

    if "." not in filename:
        flash("Invalid photo file.", "danger")
        return redirect(url_for("profile"))

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_PROFILE_PHOTO_EXTENSIONS:
        flash("Only JPG, JPEG, PNG and WEBP photos are allowed.", "danger")
        return redirect(url_for("profile"))

    new_filename = secrets.token_hex(16) + "." + extension

    photo.save(
        Path(app.config["PROFILE_PHOTO_FOLDER"]) / new_filename
    )

    old_photo = user["profile_photo"]

    execute_db(
        "UPDATE users SET profile_photo = ? WHERE id = ?",
        (new_filename, user["id"])
    )

    if old_photo:
        old_path = Path(app.config["PROFILE_PHOTO_FOLDER"]) / old_photo

        if old_path.is_file():
            old_path.unlink()

    g.pop("current_user", None)

    flash("Profile photo updated successfully.", "success")
    return redirect(url_for("profile"))


@app.route("/remove-profile-photo", methods=["POST"])
@role_required("student", "staff", "hod")
def remove_profile_photo():

    user = get_current_user()
    old_photo = user["profile_photo"]

    execute_db(
        "UPDATE users SET profile_photo = NULL WHERE id = ?",
        (user["id"],)
    )

    if old_photo:
        old_path = Path(app.config["PROFILE_PHOTO_FOLDER"]) / old_photo

        if old_path.is_file():
            old_path.unlink()

    g.pop("current_user", None)

    flash("Profile photo removed successfully.", "success")
    return redirect(url_for("profile"))


@app.route("/profile-photo/<filename>")
@role_required("student", "staff", "hod")
def profile_photo(filename):

    return send_from_directory(
        current_app.config["PROFILE_PHOTO_FOLDER"],
        filename
    )


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile")
@role_required("student", "staff", "hod")
def profile():

    user = get_current_user()
    role = (user["role"] or "").strip().lower()

    if role == "hod":
        template = "hod/profile.html"
    elif role == "staff":
        template = "staff/profile.html"
    else:
        template = "student/profile.html"

    return render_template(template, user=user)


# =========================================================
# CHANGE PASSWORD
# =========================================================

@app.route("/change-password", methods=["GET", "POST"])
@role_required("student", "staff", "hod")
def change_password():

    user = get_current_user()

    if request.method == "POST":

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not verify_password(user["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))

        if len(new_password) < 8:
            flash("New password must be at least 8 characters long.", "warning")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("New password and confirm password do not match.", "danger")
            return redirect(url_for("change_password"))

        if verify_password(user["password_hash"], new_password):
            flash("New password must be different from your current password.", "warning")
            return redirect(url_for("change_password"))

        new_password_hash = generate_password_hash(new_password)

        execute_db(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (new_password_hash, user["id"])
        )

        session.clear()

        flash("Password changed successfully. Please login again.", "success")
        return redirect(url_for("login"))

    return render_template("change_password.html")



# =========================================================
# EDIT PROFILE
# =========================================================

@app.route("/edit-profile", methods=["GET", "POST"])
@role_required("student", "staff", "hod")
def edit_profile():

    user = get_current_user()

    if request.method == "POST":

        full_name = request.form.get("full_name", "").strip()
        mobile = request.form.get("mobile", "").strip()

        if not full_name:
            flash("Name is required.", "danger")
            return redirect(url_for("profile"))

        if not mobile.isdigit() or len(mobile) != 10:
            flash("Enter a valid 10-digit mobile number.", "danger")
            return redirect(url_for("profile"))

        # Student-only profile fields
        if (user["role"] or "").strip().lower() == "student":

            roll_number = request.form.get("roll_number", "").strip()
            section = request.form.get("section", "").strip()

            if len(roll_number) > 30:
                flash("Roll number must not exceed 30 characters.", "danger")
                return redirect(url_for("profile"))

            if len(section) > 20:
                flash("Section must not exceed 20 characters.", "danger")
                return redirect(url_for("profile"))

            execute_db(
                """
                UPDATE users
                SET full_name = ?,
                    mobile = ?,
                    roll_number = ?,
                    section = ?
                WHERE id = ?
                """,
                (
                    full_name,
                    mobile,
                    roll_number or None,
                    section or None,
                    user["id"]
                )
            )

        else:

            execute_db(
                """
                UPDATE users
                SET full_name = ?, mobile = ?
                WHERE id = ?
                """,
                (full_name, mobile, user["id"])
            )

        # Refresh current user data
        g.pop("current_user", None)

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template(
        "edit_profile.html",
        user=user
    )

# =========================================================
# ACCOUNT APPROVAL SYSTEM - STUDENT APPROVALS
# =========================================================

@app.route("/staff/student-approvals")
@role_required("staff")
def student_approvals():

    user = get_current_user()

    students = query_db(
        """
        SELECT
            id, full_name, email, mobile,
            course, year, branch, department,
            section, roll_number, approval_status
        FROM users
        WHERE role = 'student'
          AND approval_status = 'PENDING'
          AND course = ?
          AND year = ?
          AND section = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)
        ORDER BY created_at DESC
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            user["section"],
            get_user_department(user)
        )
    )

    return render_template(
        "staff/student_approvals.html",
        user=user,
        students=students
    )


@app.route(
    "/staff/student-approvals/<int:user_id>/<action>",
    methods=["POST"]
)
@role_required("staff")
def approve_student(user_id, action):

    user = get_current_user()

    if action not in ("approve", "reject"):
        abort(400)

    student = query_db(
        """
        SELECT *
        FROM users
        WHERE id = ?
          AND role = 'student'
          AND approval_status = 'PENDING'
          AND course = ?
          AND year = ?
          AND section = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)
        """,
        (
            user_id,
            user["course"],
            normalize_year(user["year"]),
            user["section"],
            get_user_department(user)
        ),
        one=True
    )

    if not student:
        flash("Student not found or not eligible for your approval.", "danger")
        return redirect(url_for("student_approvals"))

    new_status = "APPROVED" if action == "approve" else "REJECTED"

    execute_db(
        """
        UPDATE users
        SET approval_status = ?
        WHERE id = ?
          AND role = 'student'
          AND approval_status = 'PENDING'
        """,
        (new_status, user_id)
    )

    flash(f"Student account {new_status.lower()} successfully.", "success")
    return redirect(url_for("student_approvals"))


# =========================================================
# ACCOUNT APPROVAL SYSTEM - STAFF APPROVALS
# =========================================================

@app.route("/hod/staff-approvals")
@role_required("hod")
def staff_approvals():

    user = get_current_user()

    staff_members = query_db(
        """
        SELECT
            id, full_name, email, mobile,
            course, year, branch, department,
            section, approval_status
        FROM users
        WHERE role = 'staff'
          AND approval_status = 'PENDING'
          AND course = ?
          AND year = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)
        ORDER BY created_at DESC
        """,
        (
            user["course"],
            normalize_year(user["year"]),
            get_user_department(user)
        )
    )

    return render_template(
        "hod/staff_approvals.html",
        user=user,
        staff_members=staff_members
    )


@app.route(
    "/hod/staff-approvals/<int:user_id>/<action>",
    methods=["POST"]
)
@role_required("hod")
def approve_staff(user_id, action):

    user = get_current_user()

    if action not in ("approve", "reject"):
        abort(400)

    staff = query_db(
        """
        SELECT *
        FROM users
        WHERE id = ?
          AND role = 'staff'
          AND approval_status = 'PENDING'
          AND course = ?
          AND year = ?
          AND LOWER(COALESCE(department, '')) = LOWER(?)
        """,
        (
            user_id,
            user["course"],
            normalize_year(user["year"]),
            get_user_department(user)
        ),
        one=True
    )

    if not staff:
        flash("Staff account not found or not eligible for your approval.", "danger")
        return redirect(url_for("staff_approvals"))

    new_status = "APPROVED" if action == "approve" else "REJECTED"

    execute_db(
        """
        UPDATE users
        SET approval_status = ?
        WHERE id = ?
          AND role = 'staff'
          AND approval_status = 'PENDING'
        """,
        (new_status, user_id)
    )

    flash(f"Staff account {new_status.lower()} successfully.", "success")
    return redirect(url_for("staff_approvals"))


# =========================================================
# NOTIFICATIONS
# =========================================================

@app.route("/notifications")
@role_required("student", "staff", "hod")
def notifications():

    user = get_current_user()

    items = query_db(
        """
        SELECT *
        FROM notifications
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user["id"],)
    )

    return render_template(
        "student/notifications.html",
        user=user,
        notifications=items
    )


@app.route("/notifications/read/<int:notification_id>", methods=["POST"])
@role_required("student", "staff", "hod")
def mark_notification_read(notification_id):

    user = get_current_user()

    execute_db(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE id = ?
          AND user_id = ?
        """,
        (notification_id, user["id"])
    )

    return redirect(url_for("notifications"))


@app.route("/notifications/read-all", methods=["POST"])
@role_required("student", "staff", "hod")
def mark_all_notifications_read():

    user = get_current_user()

    execute_db(
        """
        UPDATE notifications
        SET is_read = 1
        WHERE user_id = ?
        """,
        (user["id"],)
    )

    flash("All notifications marked as read.", "success")
    return redirect(url_for("notifications"))


# =========================================================
# ATTACHMENT DOWNLOAD
# =========================================================

@app.route("/complaint-attachment/<int:complaint_id>")
@role_required("student", "staff", "hod")
def complaint_attachment(complaint_id):

    user = get_current_user()
    complaint = get_complaint(complaint_id)

    if not complaint:
        abort(404)

    complaint_access_required(complaint, user)

    if not complaint["attachment"]:
        abort(404)

    return send_from_directory(
        current_app.config["UPLOAD_FOLDER"],
        complaint["attachment"],
        as_attachment=True
    )



# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(403)
def forbidden(error):

    return (
        render_template(
            "error.html",
            error_code=403,
            error_message="You do not have permission to access this page."
        ),
        403
    )


@app.errorhandler(404)
def not_found(error):

    return (
        render_template(
            "error.html",
            error_code=404,
            error_message="The requested page or complaint was not found."
        ),
        404
    )


@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum allowed size is 5 MB.",
        "danger"
    )

    return redirect(request.referrer or url_for("home"))


# =========================================================
# RUN SERVER
# =========================================================

if __name__ == "__main__":

    init_db()

    print("=" * 50)
    print("AIMT COMPLAINT SOLVING SYSTEM")
    print("=" * 50)
    print("Local URL: http://127.0.0.1:5000")
    print("Database initialized successfully.")
    print("=" * 50)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
