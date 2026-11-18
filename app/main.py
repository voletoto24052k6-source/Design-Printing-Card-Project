from __future__ import annotations

import os
import base64
from typing import Any
from dotenv import load_dotenv
from functools import wraps
from typing import Any, Callable, TypeVar
from flask import abort, flash, redirect, session, url_for
import hashlib
import hmac
import re
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from pathlib import Path, PurePosixPath
from math import ceil
from flask import Blueprint, current_app, abort, render_template, request
import json
from flask import Blueprint, current_app, abort, jsonify, render_template, request, session
from decimal import Decimal
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, abort, url_for
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for, abort
from datetime import date, datetime, timedelta
from flask import Flask
from flask_wtf.csrf import CSRFProtect
import secrets
from urllib.parse import urlparse
import unicodedata
from contextlib import contextmanager
from flask import g

def render_page(page: str, **context: Any):
    return render_template("page.html", page=page, **context)

# --- app/database/connection.py ---
load_dotenv()

def _connection_value(value: str) -> str:
    """Escape a value for an ODBC-style SQL Server connection string."""
    return "{" + value.replace("}", "}}") + "}"

def get_connection() -> Any:
    """Open SQL Server through Microsoft's mssql-python DB-API driver.

    Configure DB_SERVER and DB_NAME plus either DB_TRUSTED_CONNECTION=true
    or DB_USER/DB_PASSWORD in the process environment or a local .env file.
    The caller owns and must close the returned connection.
    """
    try:
        import mssql_python
    except ImportError as exc:
        raise RuntimeError(
            "The mssql-python driver is unavailable or Windows blocked one of "
            "its native files. Install requirements.txt and inspect CodeIntegrity "
            "events if Smart App Control blocks it."
        ) from exc

    server = os.getenv("DB_SERVER", "").strip()
    database = os.getenv("DB_NAME", "PrintCardDB").strip()
    trusted = os.getenv("DB_TRUSTED_CONNECTION", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if not server or not database:
        raise ValueError("Set DB_SERVER and DB_NAME in the environment or .env.")

    parts = [
        f"Server={_connection_value(server)}",
        f"Database={_connection_value(database)}",
        "Encrypt=" + os.getenv("DB_ENCRYPT", "yes").strip(),
        "TrustServerCertificate="
        + os.getenv("DB_TRUST_SERVER_CERTIFICATE", "no").strip(),
    ]
    if trusted:
        parts.append("Trusted_Connection=yes")
    else:
        username = os.getenv("DB_USER", "")
        password = os.getenv("DB_PASSWORD", "")
        if not username or not password:
            raise ValueError(
                "Set DB_USER and DB_PASSWORD, or enable DB_TRUSTED_CONNECTION."
            )
        parts.extend(
            (f"UID={_connection_value(username)}", f"PWD={_connection_value(password)}")
        )

    try:
        timeout = int(os.getenv("DB_CONNECTION_TIMEOUT", "5"))
    except ValueError as exc:
        raise ValueError("DB_CONNECTION_TIMEOUT must be a positive integer.") from exc
    if timeout < 1:
        raise ValueError("DB_CONNECTION_TIMEOUT must be a positive integer.")

    return mssql_python.connect(";".join(parts), timeout=timeout)

def check_connection() -> dict[str, Any]:
    """Connect and return the SQL Server and database names."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(128)), DB_NAME()"
            ).fetchone()
            return {"server": row[0], "database": row[1]}
        finally:
            cursor.close()
    finally:
        connection.close()

# --- app/auth/permissions.py ---
F = TypeVar("F", bound=Callable[..., Any])

def login_required(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if not (session.get("account_id") or session.get("customer_email")):
            flash("Vui lòng đăng nhập để tiếp tục.", "info")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]

def role_required(*allowed_roles: str) -> Callable[[F], F]:
    """Fail-closed role check; only roles minted by server-side auth are trusted."""
    def decorate(view: F) -> F:
        @wraps(view)
        @login_required
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if str(session.get("role", "")).lower() not in {role.lower() for role in allowed_roles}:
                abort(403)
            return view(*args, **kwargs)

        return wrapped  # type: ignore[return-value]

    return decorate

# --- app/auth/service.py ---
_LEGACY_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

_VALID_ROLES = {"customer": "Customer", "employee": "Employee", "admin": "Admin"}

def _password_matches(password: str, stored_password: str) -> tuple[bool, bool]:
    """Return (matches, needs_upgrade), supporting the SQL seed's plain passwords."""
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_password, password), False
        except (ValueError, TypeError):
            return False, False
    if _LEGACY_SHA256.fullmatch(stored_password):
        calculated = hashlib.sha256(password.encode("utf-8")).hexdigest()
        return hmac.compare_digest(calculated.lower(), stored_password.lower()), True
    # PrintCardData.sql currently seeds the ACCOUNT table with plain test passwords.
    return hmac.compare_digest(password.encode("utf-8"), stored_password.encode("utf-8")), True

def create_account(
    *, username: str, email: str, full_name: str, phone: str | None,
    address: str | None, position: str | None, password: str, role: str,
) -> bool:
    """Create ACCOUNT and its matching role profile in one transaction."""
    canonical_role = _VALID_ROLES.get(role.lower())
    if canonical_role is None:
        raise ValueError("Invalid account role")

    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            duplicate = cursor.execute(
                "SELECT 1 FROM ACCOUNT WHERE email = ? OR username = ?",
                (email, username),
            ).fetchone()
            if duplicate is not None:
                return False

            password_hash = generate_password_hash(password, method="scrypt")
            account_row = cursor.execute(
                "INSERT INTO ACCOUNT (username, [password], email, role) "
                "OUTPUT INSERTED.accountID VALUES (?, ?, ?, ?)",
                (username, password_hash, email, canonical_role),
            ).fetchone()
            account_id = int(account_row[0])

            if canonical_role == "Customer":
                cursor.execute(
                    "INSERT INTO CUSTOMER (accountID, fullName, phone, address) "
                    "VALUES (?, ?, ?, ?)",
                    (account_id, full_name, phone, address),
                )
            elif canonical_role == "Employee":
                cursor.execute(
                    "INSERT INTO EMPLOYEE (accountID, fullName, phone, address, position) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (account_id, full_name, phone, address, position),
                )
            else:
                cursor.execute(
                    "INSERT INTO ADMIN (accountID, fullName, phone) VALUES (?, ?, ?)",
                    (account_id, full_name, phone),
                )

            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

def authenticate_account(login_name: str, password: str) -> dict[str, Any] | None:
    """Authenticate an active account and require its matching role profile."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT TOP (1) a.accountID, a.username, a.email, a.[password], a.role, "
                "a.isActive, COALESCE(c.fullName, e.fullName, ad.fullName), "
                "c.customerID, e.employeeID, ad.adminID "
                "FROM ACCOUNT AS a "
                "LEFT JOIN CUSTOMER AS c ON c.accountID = a.accountID "
                "LEFT JOIN EMPLOYEE AS e ON e.accountID = a.accountID "
                "LEFT JOIN ADMIN AS ad ON ad.accountID = a.accountID "
                "WHERE a.email = ? OR a.username = ? "
                "ORDER BY CASE WHEN a.email = ? THEN 0 ELSE 1 END",
                (login_name, login_name, login_name),
            ).fetchone()
            if row is None or not bool(row[5]):
                return None

            canonical_role = str(row[4]).strip()
            role = canonical_role.lower()
            profile_ids = {"customer": row[7], "employee": row[8], "admin": row[9]}
            if role not in profile_ids or profile_ids[role] is None:
                return None

            matches, needs_upgrade = _password_matches(password, str(row[3]))
            if not matches:
                return None
            if needs_upgrade:
                upgraded_hash = generate_password_hash(password, method="scrypt")
                cursor.execute(
                    "UPDATE ACCOUNT SET [password] = ? WHERE accountID = ?",
                    (upgraded_hash, row[0]),
                )
                connection.commit()

            return {
                "account_id": int(row[0]),
                "profile_id": int(profile_ids[role]),
                "username": row[1],
                "email": row[2],
                "full_name": row[6] or row[1],
                "role": role,
            }
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

# --- app/auth/routes.py ---
auth = Blueprint("auth", __name__, url_prefix="/auth")

_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

_USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,50}$")

# Password policy: 8–128 characters with at least one letter, one digit and one special character.
PASSWORD_RULE_MESSAGE = (
    "Mật khẩu cần từ 8 đến 128 ký tự, gồm ít nhất một chữ cái, một chữ số và một ký tự đặc biệt "
    "(ví dụ: ! @ # $ %)."
)


def password_policy_error(password: str) -> str | None:
    """Return an error message when the password breaks the policy, otherwise None."""
    if not 8 <= len(password) <= 128:
        return PASSWORD_RULE_MESSAGE
    has_letter = any(ch.isalpha() for ch in password)
    has_digit = any(ch in "0123456789" for ch in password)
    has_special = any(not ch.isalnum() and not ch.isspace() for ch in password)
    if not (has_letter and has_digit and has_special):
        return PASSWORD_RULE_MESSAGE
    return None


_ROLE_NAMES = {"customer": "Khách hàng", "employee": "Nhân viên", "admin": "Quản trị viên"}

_ROLE_HOME = {
    "customer": "dashboard",
    "employee": "auth.employee_home",
    "admin": "auth.admin_home",
}

def _form_value(name: str) -> str:
    return request.form.get(name, "").strip()

def _registration_code_is_valid(role: str, code: str) -> bool:
    if role == "customer":
        return True
    required_code = current_app.config.get(f"{role.upper()}_REGISTRATION_CODE", "")
    return bool(required_code) and hmac.compare_digest(code.encode("utf-8"), required_code.encode("utf-8"))

def _sign_in(account: dict) -> None:
    session.clear()
    session.permanent = True
    session["account_id"] = account["account_id"]
    session["profile_id"] = account["profile_id"]
    session["username"] = account["username"]
    session["email"] = account["email"]
    session["full_name"] = account["full_name"]
    session["role"] = account["role"]
    # Preserve the customer keys used by existing customer-only modules.
    if account["role"] == "customer":
        session["customer_email"] = account["email"]
        session["customer_name"] = account["full_name"]

def _redirect_by_role(role: str):
    return redirect(url_for(_ROLE_HOME[role]))

@auth.route("/register", methods=["GET", "POST"])
def register():
    values = {
        "username": _form_value("username"),
        "full_name": _form_value("full_name"),
        "email": _form_value("email").lower(),
        "phone": _form_value("phone"),
        "address": _form_value("address"),
        "position": _form_value("position"),
        "role": _form_value("role").lower() or "customer",
    }
    if request.method == "POST":
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")
        registration_code = request.form.get("registration_code", "")
        errors: list[str] = []

        if values["role"] not in _ROLE_NAMES:
            errors.append("Vai trò đăng ký không hợp lệ.")
        if not _USERNAME.fullmatch(values["username"]):
            errors.append("Tên đăng nhập cần 3–50 ký tự: chữ không dấu, số, dấu chấm, gạch dưới hoặc gạch ngang.")
        if not values["full_name"] or len(values["full_name"]) > 100:
            errors.append("Họ tên là bắt buộc và tối đa 100 ký tự.")
        if len(values["email"]) > 100 or not _EMAIL.fullmatch(values["email"]):
            errors.append("Email không hợp lệ hoặc vượt quá 100 ký tự.")
        if len(values["phone"]) > 15:
            errors.append("Số điện thoại tối đa 15 ký tự.")
        if values["role"] == "employee" and not values["phone"]:
            errors.append("Số điện thoại là bắt buộc với tài khoản nhân viên.")
        address_limit = 255 if values["role"] == "employee" else 300
        if len(values["address"]) > address_limit:
            errors.append(f"Địa chỉ tối đa {address_limit} ký tự.")
        if len(values["position"]) > 50:
            errors.append("Chức vụ tối đa 50 ký tự.")
        password_error = password_policy_error(password)
        if password_error:
            errors.append(password_error)
        if password != confirmation:
            errors.append("Mật khẩu xác nhận không khớp.")
        if values["role"] in {"employee", "admin"} and not _registration_code_is_valid(values["role"], registration_code):
            errors.append("Mã đăng ký nội bộ không hợp lệ hoặc chưa được cấu hình.")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_page("auth_register", values=values), 400

        try:
            created = create_account(
                username=values["username"],
                email=values["email"],
                full_name=values["full_name"],
                phone=values["phone"] or None,
                address=values["address"] or None,
                position=values["position"] or None,
                password=password,
                role=values["role"],
            )
        except Exception:
            current_app.logger.exception("Account registration failed")
            flash("Chưa thể tạo tài khoản lúc này. Vui lòng thử lại sau.", "error")
            return render_page("auth_register", values=values), 503

        if not created:
            flash("Email hoặc tên đăng nhập này đã được sử dụng.", "error")
            return render_page("auth_register", values=values), 409

        # Sign in the newly created account using the same DB-backed profile data.
        try:
            account = authenticate_account(values["email"], password)
        except Exception:
            current_app.logger.exception("New account sign-in failed")
            flash("Tài khoản đã tạo nhưng chưa thể đăng nhập. Hãy đăng nhập lại.", "error")
            return redirect(url_for("auth.login"))
        if account is None:
            flash("Tài khoản đã tạo nhưng chưa thể đăng nhập. Hãy đăng nhập lại.", "error")
            return redirect(url_for("auth.login"))

        _sign_in(account)
        flash("Đăng ký thành công.", "success")
        return _redirect_by_role(account["role"])

    return render_page("auth_register", values=values)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        login_name = _form_value("login_name")
        password = request.form.get("password", "")
        if not login_name or not password:
            flash("Email/tên đăng nhập và mật khẩu là bắt buộc.", "error")
            return render_page("auth_login", login_name=login_name), 400

        try:
            account = authenticate_account(login_name, password)
        except Exception:
            current_app.logger.exception("Account login database operation failed")
            flash("Chưa thể đăng nhập lúc này. Vui lòng thử lại sau.", "error")
            return render_page("auth_login", login_name=login_name), 503

        if account is None:
            flash("Thông tin đăng nhập không đúng hoặc tài khoản đã bị khóa.", "error")
            return render_page("auth_login", login_name=login_name), 401

        _sign_in(account)
        flash("Đăng nhập thành công.", "success")
        return _redirect_by_role(account["role"])

    return render_page("auth_login", login_name="")

@auth.post("/logout")
def logout():
    session.clear()
    flash("Bạn đã đăng xuất.", "success")
    return redirect(url_for("auth.login"))

@auth.get("/me")
@role_required("customer", "employee", "admin")
def me():
    return {
        "account_id": session["account_id"],
        "profile_id": session["profile_id"],
        "username": session["username"],
        "email": session["email"],
        "full_name": session["full_name"],
        "role": session["role"],
    }

@auth.get("/employee")
@role_required("employee")
def employee_home():
    return render_page("role_dashboard", role_name=_ROLE_NAMES["employee"], **_dashboard_context("employee"))

@auth.get("/admin")
@role_required("admin")
def admin_home():
    return render_page("role_dashboard", role_name=_ROLE_NAMES["admin"], **_dashboard_context("admin"))

# --- app/catalog/service.py ---
ALLOWED_PRODUCT_NAMES = ("Card visit", "Name tag", "Thiệp mời")

_NORMALIZED_PRODUCT_NAMES = tuple(name.lower() for name in ALLOWED_PRODUCT_NAMES)

PAGE_SIZE = 12

_PREVIEW_STEM_RE = re.compile(r"^[A-Za-z0-9_-]+$")

def _preview_image_path(image_url: str | None) -> str | None:
    """Map a database template URL to an existing local static image safely."""
    if not image_url or not image_url.startswith("/img/templates/"):
        return None
    image_path = PurePosixPath(image_url)
    stem = image_path.stem
    if not _PREVIEW_STEM_RE.fullmatch(stem):
        return None

    allowed_extensions = {".jpg", ".jpeg", ".png", ".webp", ".svg"}
    requested_extension = image_path.suffix.lower()
    if requested_extension not in allowed_extensions:
        return None
    extensions = [requested_extension]
    extensions.extend(ext for ext in (".png", ".jpg", ".jpeg", ".webp", ".svg") if ext not in extensions)
    asset_root = Path(__file__).resolve().parent / "static" / "img" / "templates"
    for extension in extensions:
        if (asset_root / f"{stem}{extension}").is_file():
            return f"img/templates/{stem}{extension}"
    return None

def _preview_image_version(preview_image: str | None) -> int:
    if not preview_image:
        return 0
    asset_path = Path(__file__).resolve().parent / "static" / preview_image
    try:
        return asset_path.stat().st_mtime_ns
    except OSError:
        return 0

def _base_filters(category_name: str | None, search: str) -> tuple[str, list[Any]]:
    product_key = "LOWER(LTRIM(RTRIM(p.productName)))"
    clauses = [f"{product_key} IN (?, ?, ?)", "t.approvalState = 'Approved'"]
    params: list[Any] = list(_NORMALIZED_PRODUCT_NAMES)
    if category_name:
        clauses.append(f"{product_key} = ?")
        params.append(category_name.lower())
    if search:
        clauses.append("(t.designName LIKE ? OR t.info LIKE ?)")
        pattern = f"%{search}%"
        params.extend((pattern, pattern))
    return " AND ".join(clauses), params

def list_product_types() -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT MIN(productID), MIN(productName), MIN(info) "
                "FROM PRODUCT_TYPE "
                "WHERE LOWER(LTRIM(RTRIM(productName))) IN (?, ?, ?) "
                "GROUP BY LOWER(LTRIM(RTRIM(productName))) "
                "ORDER BY MIN(productID)",
                _NORMALIZED_PRODUCT_NAMES,
            ).fetchall()
            return [
                {"id": str(row[1]).strip(), "name": str(row[1]).strip(), "info": row[2]}
                for row in rows
            ]
        finally:
            cursor.close()
    finally:
        connection.close()

def count_templates(category_name: str | None, search: str) -> int:
    where_sql, params = _base_filters(category_name, search)
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT COUNT(*) FROM ("
                "SELECT LOWER(LTRIM(RTRIM(p.productName))) AS product_key, "
                "LOWER(LTRIM(RTRIM(t.designName))) AS template_key "
                "FROM TEMPLATE AS t "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                f"WHERE {where_sql} "
                "GROUP BY LOWER(LTRIM(RTRIM(p.productName))), "
                "LOWER(LTRIM(RTRIM(t.designName)))"
                ") AS unique_templates",
                params,
            ).fetchone()
            return int(row[0])
        finally:
            cursor.close()
    finally:
        connection.close()

def list_templates(
    category_name: str | None, search: str, page: int
) -> list[dict[str, Any]]:
    where_sql, params = _base_filters(category_name, search)
    params.extend(((page - 1) * PAGE_SIZE, PAGE_SIZE))
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT designID, designName, imageUrl, basePrice, info, productID, productName "
                "FROM ("
                "SELECT t.designID, t.designName, t.imageUrl, t.basePrice, t.info, "
                "p.productID, p.productName, "
                "ROW_NUMBER() OVER ("
                "PARTITION BY LOWER(LTRIM(RTRIM(p.productName))), "
                "LOWER(LTRIM(RTRIM(t.designName))) "
                "ORDER BY t.designID) AS duplicate_number "
                "FROM TEMPLATE AS t "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                f"WHERE {where_sql}"
                ") AS ranked_templates "
                "WHERE duplicate_number = 1 "
                "ORDER BY designName, designID "
                "OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
                params,
            ).fetchall()
            result = []
            for row in rows:
                preview_image = _preview_image_path(row[2])
                result.append({
                    "id": row[0], "name": row[1], "image_url": row[2],
                    "preview_image": preview_image,
                    "preview_version": _preview_image_version(preview_image),
                    "base_price": row[3], "info": row[4],
                    "product_id": row[5], "product_name": row[6],
                })
            return result
        finally:
            cursor.close()
    finally:
        connection.close()

def get_template(template_id: int) -> dict[str, Any] | None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT t.designID, t.designName, t.imageUrl, t.content, "
                "t.basePrice, t.info, p.productID, p.productName "
                "FROM TEMPLATE AS t "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                "WHERE t.designID = ? AND t.approvalState = 'Approved' "
                "AND LOWER(LTRIM(RTRIM(p.productName))) IN (?, ?, ?)",
                (template_id, *_NORMALIZED_PRODUCT_NAMES),
            ).fetchone()
            if row is None:
                return None
            preview_image = _preview_image_path(row[2])
            return {
                "id": row[0], "name": row[1], "image_url": row[2],
                "preview_image": preview_image,
                "preview_version": _preview_image_version(preview_image),
                "content": row[3], "base_price": row[4], "info": row[5],
                "product_id": row[6], "product_name": row[7],
            }
        finally:
            cursor.close()
    finally:
        connection.close()

# --- app/catalog/routes.py ---
catalog = Blueprint("catalog", __name__, url_prefix="/catalog")

def _category_filter(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    value = raw_value.strip().casefold()
    for name in ALLOWED_PRODUCT_NAMES:
        if value == name.casefold():
            return name
    abort(404)

@catalog.get("/")
def index():
    search = request.args.get("q", "").strip()[:100]
    try:
        categories = list_product_types()
    except Exception:
        current_app.logger.exception("Catalog category query failed")
        return render_page("catalog_error"), 503

    selected_category = _category_filter(request.args.get("category"))
    category_names = {item["name"].casefold() for item in categories}
    if selected_category and selected_category.casefold() not in category_names:
        abort(404)

    try:
        total = count_templates(selected_category, search)
        pages = max(1, ceil(total / PAGE_SIZE))
        try:
            page = max(1, int(request.args.get("page", "1")))
        except ValueError:
            page = 1
        page = min(page, pages)
        templates = list_templates(selected_category, search, page) if total else []
    except Exception:
        current_app.logger.exception("Catalog template query failed")
        return render_page("catalog_error"), 503

    return render_page(
        "catalog_index",
        categories=categories,
        selected_category=selected_category,
        search=search,
        templates=templates,
        page_number=page,
        pages=pages,
        total=total,
    )

@catalog.get("/templates/<int:template_id>")
def template_detail(template_id: int):
    try:
        item = get_template(template_id)
    except Exception:
        current_app.logger.exception("Template detail query failed")
        return render_page("catalog_error"), 503
    if item is None:
        abort(404)
    return render_page("catalog_detail", item=item)

# --- app/account/service.py ---
# One profile + password flow shared by customers, employees and admins.
_PROFILE_QUERIES = {
    "customer": (
        "SELECT a.username, a.email, p.fullName, p.phone, p.address, CAST(NULL AS nvarchar(50)) "
        "FROM CUSTOMER AS p JOIN ACCOUNT AS a ON a.accountID = p.accountID WHERE p.customerID = ?"
    ),
    "employee": (
        "SELECT a.username, a.email, p.fullName, p.phone, p.address, p.position "
        "FROM EMPLOYEE AS p JOIN ACCOUNT AS a ON a.accountID = p.accountID WHERE p.employeeID = ?"
    ),
    "admin": (
        "SELECT a.username, a.email, p.fullName, p.phone, CAST(NULL AS nvarchar(300)), CAST(NULL AS nvarchar(50)) "
        "FROM ADMIN AS p JOIN ACCOUNT AS a ON a.accountID = p.accountID WHERE p.adminID = ?"
    ),
}

_PROFILE_UPDATES = {
    "customer": "UPDATE CUSTOMER SET fullName = ?, phone = ?, address = ? WHERE customerID = ?",
    "employee": "UPDATE EMPLOYEE SET fullName = ?, phone = ?, address = ? WHERE employeeID = ?",
}

_ADDRESS_LIMITS = {"customer": 300, "employee": 255}


def get_profile(role: str, profile_id: int) -> dict[str, Any] | None:
    query = _PROFILE_QUERIES.get(role)
    if query is None:
        return None
    with _cursor() as cursor:
        row = cursor.execute(query, (profile_id,)).fetchone()
    if row is None:
        return None
    return {
        "role": role, "username": row[0], "email": row[1], "full_name": row[2] or "",
        "phone": row[3] or "", "address": row[4] or "", "position": row[5] or "",
    }


def update_profile(
    role: str, profile_id: int, *, full_name: str, phone: str | None, address: str | None
) -> None:
    """Self-service edit. Email, username and position stay read-only (position grants staff rights)."""
    with _cursor(commit=True) as cursor:
        if role == "admin":
            cursor.execute(
                "UPDATE ADMIN SET fullName = ?, phone = ? WHERE adminID = ?",
                (full_name, phone, profile_id),
            )
        else:
            cursor.execute(_PROFILE_UPDATES[role], (full_name, phone, address, profile_id))
        if cursor.rowcount != 1:
            raise LookupError("Profile not found")


def change_password(account_id: int, current_password: str, new_password: str) -> bool:
    """Return False when the current password is wrong; raise LookupError for a missing/locked account."""
    with _cursor(commit=True) as cursor:
        row = cursor.execute(
            "SELECT [password] FROM ACCOUNT WITH (UPDLOCK, ROWLOCK) WHERE accountID = ? AND isActive = 1",
            (account_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Account not found")
        matches, _ = _password_matches(current_password, str(row[0]))
        if not matches:
            return False
        cursor.execute(
            "UPDATE ACCOUNT SET [password] = ? WHERE accountID = ?",
            (generate_password_hash(new_password, method="scrypt"), account_id),
        )
    return True


# --- app/account/routes.py ---
account_bp = Blueprint("account", __name__, url_prefix="/account")


def _profile_unavailable():
    session.clear()
    flash("Không tìm thấy tài khoản. Vui lòng đăng nhập lại.", "error")
    return redirect(url_for("auth.login"))


@account_bp.route("/profile", methods=["GET", "POST"])
@role_required("customer", "employee", "admin")
def profile():
    role = str(session["role"]).lower()
    profile_id = session["profile_id"]
    try:
        current = get_profile(role, profile_id)
    except Exception:
        current_app.logger.exception("Profile query failed")
        return render_page("catalog_error"), 503
    if current is None:
        return _profile_unavailable()

    if request.method == "POST":
        values = {
            "full_name": request.form.get("full_name", "").strip(),
            "phone": request.form.get("phone", "").strip(),
            "address": "" if role == "admin" else request.form.get("address", "").strip(),
        }
        errors = []
        if not values["full_name"] or len(values["full_name"]) > 100:
            errors.append("Họ tên là bắt buộc và tối đa 100 ký tự.")
        if len(values["phone"]) > 15:
            errors.append("Số điện thoại tối đa 15 ký tự.")
        if role == "employee" and not values["phone"]:
            errors.append("Số điện thoại là bắt buộc với tài khoản nhân viên.")
        limit = _ADDRESS_LIMITS.get(role)
        if limit and len(values["address"]) > limit:
            errors.append(f"Địa chỉ tối đa {limit} ký tự.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_page("account_profile", profile={**current, **values}, role_name=_ROLE_NAMES[role]), 400
        try:
            update_profile(
                role, profile_id, full_name=values["full_name"],
                phone=values["phone"] or None, address=values["address"] or None,
            )
        except LookupError:
            return _profile_unavailable()
        except Exception:
            current_app.logger.exception("Profile update failed")
            flash("Chưa thể lưu hồ sơ. Vui lòng thử lại sau.", "error")
            return render_page("account_profile", profile={**current, **values}, role_name=_ROLE_NAMES[role]), 503
        session["full_name"] = values["full_name"]
        if role == "customer":
            session["customer_name"] = values["full_name"]
        flash("Đã cập nhật hồ sơ.", "success")
        return redirect(url_for("account.profile"))

    return render_page("account_profile", profile=current, role_name=_ROLE_NAMES[role])


@account_bp.route("/password", methods=["GET", "POST"])
@role_required("customer", "employee", "admin")
def password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        errors = []
        if not current_password:
            errors.append("Vui lòng nhập mật khẩu hiện tại.")
        new_password_error = password_policy_error(new_password)
        if new_password_error:
            errors.append(new_password_error)
        elif new_password != confirmation:
            errors.append("Mật khẩu xác nhận không khớp.")
        elif current_password and new_password == current_password:
            errors.append("Mật khẩu mới phải khác mật khẩu hiện tại.")
        if errors:
            for error in errors:
                flash(error, "error")
            return render_page("account_password"), 400
        try:
            changed = change_password(session["account_id"], current_password, new_password)
        except LookupError:
            return _profile_unavailable()
        except Exception:
            current_app.logger.exception("Password change failed")
            flash("Chưa thể đổi mật khẩu. Vui lòng thử lại sau.", "error")
            return render_page("account_password"), 503
        if not changed:
            flash("Mật khẩu hiện tại không đúng.", "error")
            return render_page("account_password"), 400
        flash("Đã đổi mật khẩu.", "success")
        return redirect(url_for("account.profile"))
    return render_page("account_password")


# --- app/designs/service.py ---
def create_design(template_id: int, customer_id: int, content: dict[str, Any]) -> int:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "INSERT INTO CUSTOM_DESIGN (content, imageUrl, templateID, customerID) "
                "OUTPUT INSERTED.designID VALUES (?, NULL, ?, ?)",
                (json.dumps(content, ensure_ascii=False, separators=(",", ":")), template_id, customer_id),
            ).fetchone()
            connection.commit()
            return int(row[0])
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

_DESIGN_IMAGE_RE = re.compile(r"^/img/custom/cd\d+\.png$")

_DESIGN_IMAGE_DIR = Path(__file__).resolve().parent / "static" / "img" / "custom"

_MAX_IMAGE_BYTES = 2_000_000

_PNG_PREFIX = "data:image/png;base64,"

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

def design_image_info(design_id: int, image_url: str | None) -> tuple[str | None, int]:
    """Return (static path, cache version) of a saved customer design image, if present."""
    if not image_url or not _DESIGN_IMAGE_RE.fullmatch(image_url):
        return None, 0
    try:
        version = (_DESIGN_IMAGE_DIR / f"cd{int(design_id)}.png").stat().st_mtime_ns
    except OSError:
        return None, 0
    return f"img/custom/cd{int(design_id)}.png", version

def design_thumbnail(
    design_id: int, custom_url: str | None, template_url: str | None
) -> tuple[str | None, int]:
    """Prefer the customer's rendered design; fall back to the template preview."""
    path, version = design_image_info(design_id, custom_url)
    if path:
        return path, version
    fallback = _preview_image_path(template_url)
    return fallback, _preview_image_version(fallback)

def decode_design_png(data_url: object) -> bytes | None:
    """Validate and decode a PNG data URL exported from the editor canvas."""
    if not isinstance(data_url, str) or not data_url.startswith(_PNG_PREFIX):
        return None
    if len(data_url) > _MAX_IMAGE_BYTES * 4 // 3 + 100:
        return None
    try:
        raw = base64.b64decode(data_url[len(_PNG_PREFIX):], validate=True)
    except ValueError:
        return None
    if len(raw) > _MAX_IMAGE_BYTES or not raw.startswith(_PNG_SIGNATURE):
        return None
    return raw

def save_design_image(design_id: int, customer_id: int, png: bytes) -> None:
    """Write the rendered design PNG and record its URL in CUSTOM_DESIGN.imageUrl."""
    _DESIGN_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    target = _DESIGN_IMAGE_DIR / f"cd{int(design_id)}.png"
    temporary = target.with_suffix(".tmp")
    temporary.write_bytes(png)
    temporary.replace(target)
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                "UPDATE CUSTOM_DESIGN SET imageUrl = ? WHERE designID = ? AND customerID = ?",
                (f"/img/custom/cd{int(design_id)}.png", design_id, customer_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

def update_design(design_id: int, customer_id: int, content: dict[str, Any]) -> bool:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            cursor.execute(
                "UPDATE CUSTOM_DESIGN SET content = ? "
                "WHERE designID = ? AND customerID = ?",
                (json.dumps(content, ensure_ascii=False, separators=(",", ":")), design_id, customer_id),
            )
            changed = cursor.rowcount == 1
            if changed:
                connection.commit()
            else:
                connection.rollback()
            return changed
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

def get_design(design_id: int, customer_id: int) -> dict[str, Any] | None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT cd.designID, cd.templateID, cd.content, t.designName, p.productName, t.content, t.imageUrl "
                "FROM CUSTOM_DESIGN AS cd "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                "WHERE cd.designID = ? AND cd.customerID = ?",
                (design_id, customer_id),
            ).fetchone()
            if row is None:
                return None
            preview_image = _preview_image_path(row[6])
            return {
                "id": row[0], "template_id": row[1],
                "content": json.loads(row[2]) if row[2] else {"version": 1, "elements": []},
                "template_name": row[3], "product_name": row[4],
                "template_content": json.loads(row[5]) if row[5] else {},
                "preview_image": preview_image,
                "preview_version": _preview_image_version(preview_image),
            }
        finally:
            cursor.close()
    finally:
        connection.close()

def list_designs(customer_id: int) -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT cd.designID, t.designName, p.productName, cd.imageUrl, t.imageUrl "
                "FROM CUSTOM_DESIGN AS cd "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                "WHERE cd.customerID = ? ORDER BY cd.designID DESC",
                (customer_id,),
            ).fetchall()
            result = []
            for row in rows:
                image, version = design_thumbnail(row[0], row[3], row[4])
                result.append({
                    "id": row[0], "template_name": row[1], "product_name": row[2],
                    "image": image, "image_version": version,
                })
            return result
        finally:
            cursor.close()
    finally:
        connection.close()

# --- app/designs/routes.py ---
designs = Blueprint("designs", __name__, url_prefix="/designs")

_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")

_MAX_ELEMENTS = 30

_MAX_TEXT = 500

_MAX_UPLOAD_BYTES = 3_000_000

_FONTS = {"Arial", "Georgia", "Courier New", "Times New Roman", "Verdana", "Tahoma", "Trebuchet MS"}

_ALIGNS = {"left", "center", "right"}

_ORIGINS_Y = {"top", "center", "bottom"}

def _num(value: object, low: float, high: float) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and low <= value <= high

def _validated_content(payload: object, template_content: object) -> dict | None:
    """Validate the Fabric.js text objects sent by the editor (whitelisted properties only)."""
    if not isinstance(payload, dict):
        return None
    canvas = payload.get("canvas")
    objects = payload.get("objects")
    if not isinstance(canvas, dict) or not isinstance(objects, list) or len(objects) > _MAX_ELEMENTS:
        return None
    width, height = canvas.get("width"), canvas.get("height")
    if not _num(width, 50, 2000) or not _num(height, 50, 2000):
        return None
    clean = []
    for item in objects:
        if not isinstance(item, dict):
            return None
        text = item.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > _MAX_TEXT:
            return None
        left, top = item.get("left"), item.get("top")
        if not _num(left, -width, 2 * width) or not _num(top, -height, 2 * height):
            return None
        font_size = item.get("fontSize")
        if not _num(font_size, 8, 200):
            return None
        fill = item.get("fill")
        if not isinstance(fill, str) or not _COLOR.fullmatch(fill):
            return None
        family = item.get("fontFamily", "Arial")
        weight, style = item.get("fontWeight", "normal"), item.get("fontStyle", "normal")
        text_align, origin_x = item.get("textAlign", "left"), item.get("originX", "left")
        origin_y = item.get("originY", "top")
        if family not in _FONTS or weight not in {"normal", "bold"} or style not in {"normal", "italic"}:
            return None
        if text_align not in _ALIGNS or origin_x not in _ALIGNS or origin_y not in _ORIGINS_Y:
            return None
        angle, scale_x, scale_y = item.get("angle", 0), item.get("scaleX", 1), item.get("scaleY", 1)
        spacing = item.get("charSpacing", 0)
        if not _num(angle, 0, 360) or not _num(scale_x, 0.05, 20) or not _num(scale_y, 0.05, 20):
            return None
        if not _num(spacing, -200, 3000):
            return None
        clean.append({
            "text": text, "left": float(left), "top": float(top), "originX": origin_x,
            "originY": origin_y, "fontSize": float(font_size), "fill": fill,
            "fontFamily": family, "fontWeight": weight, "fontStyle": style,
            "textAlign": text_align, "angle": float(angle), "scaleX": float(scale_x),
            "scaleY": float(scale_y), "charSpacing": float(spacing),
        })
    if not isinstance(template_content, dict):
        template_content = {}
    return {
        "version": 2, "template": template_content,
        "canvas": {"width": int(width), "height": int(height)}, "objects": clean,
    }

def _editor_objects(content: dict) -> list:
    """Saved text objects: Fabric (v2) or the legacy normalised 'elements' (v1)."""
    if content.get("version") == 2 and isinstance(content.get("objects"), list):
        return content["objects"]
    legacy = content.get("elements")
    return legacy if isinstance(legacy, list) else []

def _template(template_id: int):
    try:
        item = get_template(template_id)
    except Exception:
        current_app.logger.exception("Design template query failed")
        return None
    return item

@designs.get("/mine")
@role_required("customer")
def mine():
    try:
        items = list_designs(session["profile_id"])
    except Exception:
        current_app.logger.exception("Customer designs query failed")
        return render_page("catalog_error"), 503
    return render_page("designs_mine", designs=items)

@designs.get("/new/<int:template_id>")
@role_required("customer")
def new(template_id: int):
    item = _template(template_id)
    if item is None:
        abort(404)
    try:
        template_content = json.loads(item["content"]) if item["content"] else {}
    except (TypeError, json.JSONDecodeError):
        template_content = {}
    return render_page(
        "designs_editor", item=item, design_id=None,
        elements=[], saved_canvas=None, template_content=template_content,
        background=item.get("preview_image"), background_version=item.get("preview_version", 0),
    )

def _request_image(payload: object) -> tuple[bool, bytes | None]:
    """Return (valid, png). A missing image is allowed; a malformed one is not."""
    if not isinstance(payload, dict) or payload.get("image") in (None, ""):
        return True, None
    png = decode_design_png(payload["image"])
    return png is not None, png

def _store_image(design_id: int, png: bytes | None) -> None:
    if png is None:
        return
    try:
        save_design_image(design_id, session["profile_id"], png)
    except Exception:
        current_app.logger.exception("Custom design image save failed")

@designs.post("/new/<int:template_id>")
@role_required("customer")
def save_new(template_id: int):
    if request.content_length and request.content_length > _MAX_UPLOAD_BYTES:
        return jsonify(error="Nội dung thiết kế vượt giới hạn."), 413
    item = _template(template_id)
    if item is None:
        abort(404)
    try:
        template_content = json.loads(item["content"]) if item["content"] else {}
    except (TypeError, json.JSONDecodeError):
        template_content = {}
    payload = request.get_json(silent=True)
    content = _validated_content(payload, template_content)
    image_ok, png = _request_image(payload)
    if content is None or not image_ok:
        return jsonify(error="Dữ liệu thiết kế không hợp lệ."), 400
    try:
        design_id = create_design(template_id, session["profile_id"], content)
    except Exception:
        current_app.logger.exception("Custom design save failed")
        return jsonify(error="Chưa thể lưu thiết kế. Vui lòng thử lại."), 503
    _store_image(design_id, png)
    return jsonify(id=design_id, redirect=f"/designs/{design_id}/edit"), 201

@designs.get("/<int:design_id>/edit")
@role_required("customer")
def edit(design_id: int):
    try:
        item = get_design(design_id, session["profile_id"])
    except Exception:
        current_app.logger.exception("Custom design query failed")
        return render_page("catalog_error"), 503
    if item is None:
        abort(404)
    return render_page(
        "designs_editor", item={"id": item["template_id"], "name": item["template_name"], "product_name": item["product_name"]},
        design_id=item["id"], elements=_editor_objects(item["content"]),
        saved_canvas=item["content"].get("canvas") if isinstance(item["content"].get("canvas"), dict) else None,
        template_content=item.get("template_content", {}),
        background=item.get("preview_image"), background_version=item.get("preview_version", 0),
    )

@designs.post("/<int:design_id>/edit")
@role_required("customer")
def save_edit(design_id: int):
    if request.content_length and request.content_length > _MAX_UPLOAD_BYTES:
        return jsonify(error="Nội dung thiết kế vượt giới hạn."), 413
    try:
        item = get_design(design_id, session["profile_id"])
    except Exception:
        current_app.logger.exception("Custom design ownership check failed")
        return jsonify(error="Chưa thể lưu thiết kế. Vui lòng thử lại."), 503
    if item is None:
        abort(404)
    payload = request.get_json(silent=True)
    content = _validated_content(payload, item.get("template_content"))
    image_ok, png = _request_image(payload)
    if content is None or not image_ok:
        return jsonify(error="Dữ liệu thiết kế không hợp lệ."), 400
    try:
        saved = update_design(design_id, session["profile_id"], content)
    except Exception:
        current_app.logger.exception("Custom design update failed")
        return jsonify(error="Chưa thể lưu thiết kế. Vui lòng thử lại."), 503
    if not saved:
        abort(404)
    _store_image(design_id, png)
    return jsonify(id=design_id, redirect=f"/designs/{design_id}/edit")

# --- app/orders/service.py ---
class CheckoutError(ValueError):
    pass

def customer_address(customer_id: int) -> str:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute("SELECT address FROM CUSTOMER WHERE customerID = ?", (customer_id,)).fetchone()
            return (row[0] or "") if row else ""
        finally:
            cursor.close()
    finally:
        connection.close()

def owns_design(customer_id: int, design_id: int) -> bool:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            return cursor.execute(
                "SELECT 1 FROM CUSTOM_DESIGN AS cd "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                "WHERE cd.designID = ? AND cd.customerID = ? "
                "AND p.productName IN (N'Card visit', N'Name tag', N'Thiệp mời')",
                (design_id, customer_id),
            ).fetchone() is not None
        finally:
            cursor.close()
    finally:
        connection.close()

def shipping_options() -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT method, fee FROM SHIPMENT GROUP BY method, fee ORDER BY fee, method"
            ).fetchall()
            return [{"method": row[0], "fee": row[1]} for row in rows]
        finally:
            cursor.close()
    finally:
        connection.close()

def cart_items(customer_id: int, quantities: dict[int, int]) -> list[dict[str, Any]]:
    if not quantities:
        return []
    design_ids = list(quantities)
    marks = ", ".join("?" for _ in design_ids)
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT cd.designID, t.designName, p.productName, t.basePrice, cd.imageUrl, t.imageUrl "
                "FROM CUSTOM_DESIGN AS cd "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                f"WHERE cd.customerID = ? AND cd.designID IN ({marks}) "
                "AND p.productName IN (N'Card visit', N'Name tag', N'Thiệp mời')",
                [customer_id, *design_ids],
            ).fetchall()
            result = []
            for row in rows:
                quantity = quantities[int(row[0])]
                unit_price = Decimal(str(row[3]))
                image, version = design_thumbnail(int(row[0]), row[4], row[5])
                result.append({
                    "design_id": int(row[0]), "template_name": row[1],
                    "product_name": row[2], "quantity": quantity,
                    "unit_price": unit_price, "total": unit_price * quantity,
                    "image": image, "image_version": version,
                })
            return result
        finally:
            cursor.close()
    finally:
        connection.close()

def create_order(
    customer_id: int, quantities: dict[int, int], address: str,
    shipping_method: str, shipping_fee: Decimal, payment_method: str,
) -> int:
    if not quantities:
        raise CheckoutError("Giỏ hàng đang trống.")
    if not address or len(address) > 300:
        raise CheckoutError("Địa chỉ nhận hàng không hợp lệ.")
    if payment_method != "Thanh toán khi nhận hàng (COD)":
        raise CheckoutError("Hiện chỉ hỗ trợ ghi nhận COD, chưa có cổng thanh toán trực tuyến.")

    design_ids = list(quantities)
    marks = ", ".join("?" for _ in design_ids)
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT cd.designID, t.basePrice "
                "FROM CUSTOM_DESIGN AS cd "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                f"WHERE cd.customerID = ? AND cd.designID IN ({marks}) "
                "AND p.productName IN (N'Card visit', N'Name tag', N'Thiệp mời')",
                [customer_id, *design_ids],
            ).fetchall()
            if len(rows) != len(design_ids):
                raise CheckoutError("Một thiết kế không còn hợp lệ hoặc không thuộc tài khoản của bạn.")

            products = []
            subtotal = Decimal("0")
            max_total = Decimal("999999999999999999")
            for row in rows:
                design_id = int(row[0])
                quantity = quantities[design_id]
                if not isinstance(quantity, int) or quantity < 1 or quantity > 2147483647:
                    raise CheckoutError("Số lượng không hợp lệ.")
                price = Decimal(str(row[1]))
                line_total = price * quantity
                if line_total > max_total:
                    raise CheckoutError("Tổng tiền vượt giới hạn cho phép của một đơn hàng.")
                subtotal += line_total
                products.append((design_id, quantity, price))
            if subtotal > max_total:
                raise CheckoutError("Tổng tiền vượt giới hạn cho phép của một đơn hàng.")

            configured = cursor.execute(
                "SELECT 1 FROM SHIPMENT WHERE method = ? AND fee = ?",
                (shipping_method, shipping_fee),
            ).fetchone()
            if configured is None:
                raise CheckoutError("Phương thức giao hàng không hợp lệ.")
            fee = shipping_fee
            total = subtotal + fee
            if total > max_total:
                raise CheckoutError("Tổng tiền vượt giới hạn cho phép của một đơn hàng.")

            order_row = cursor.execute(
                "INSERT INTO [ORDER] (address, state, basePrice, customerID) "
                "OUTPUT INSERTED.orderID VALUES (?, 'Pending', ?, ?)",
                (address, subtotal, customer_id),
            ).fetchone()
            order_id = int(order_row[0])
            for design_id, quantity, price in products:
                cursor.execute(
                    "INSERT INTO ORDER_DETAILS (orderID, designID, quantity, basePrice) "
                    "VALUES (?, ?, ?, ?)",
                    (order_id, design_id, quantity, price),
                )
            cursor.execute(
                "INSERT INTO PAYMENT (orderID, method, state, time, total) "
                "VALUES (?, ?, 'Pending', NULL, ?)",
                (order_id, payment_method, total),
            )
            cursor.execute(
                "INSERT INTO SHIPMENT (orderID, method, fee) VALUES (?, ?, ?)",
                (order_id, shipping_method, fee),
            )
            cursor.execute(
                "INSERT INTO ORDER_STATUS_HISTORY (orderID, newState) VALUES (?, 'Pending')",
                (order_id,),
            )
            connection.commit()
            return order_id
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

def list_orders(customer_id: int) -> list[dict[str, Any]]:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            rows = cursor.execute(
                "SELECT o.orderID, o.orderDate, o.state, o.basePrice, "
                "s.method, s.fee, p.state, p.total "
                "FROM [ORDER] AS o "
                "LEFT JOIN SHIPMENT AS s ON s.orderID = o.orderID "
                "LEFT JOIN PAYMENT AS p ON p.orderID = o.orderID "
                "WHERE o.customerID = ? ORDER BY o.orderDate DESC, o.orderID DESC",
                (customer_id,),
            ).fetchall()
            return [{
                "id": row[0], "date": row[1], "state": row[2],
                "subtotal": row[3], "shipping_method": row[4], "shipping_fee": row[5],
                "payment_state": row[6], "payment_total": row[7],
            } for row in rows]
        finally:
            cursor.close()
    finally:
        connection.close()

def get_order(customer_id: int, order_id: int) -> dict[str, Any] | None:
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            header = cursor.execute(
                "SELECT o.orderID, o.orderDate, o.state, o.address, o.basePrice, "
                "s.method, s.fee, p.method, p.state, p.total "
                "FROM [ORDER] AS o "
                "LEFT JOIN SHIPMENT AS s ON s.orderID = o.orderID "
                "LEFT JOIN PAYMENT AS p ON p.orderID = o.orderID "
                "WHERE o.orderID = ? AND o.customerID = ?",
                (order_id, customer_id),
            ).fetchone()
            if header is None:
                return None
            details = cursor.execute(
                "SELECT d.orderDetailsID, d.quantity, d.basePrice, d.total, "
                "t.designName, p.productName, r.design, r.quality, "
                "cd.designID, cd.imageUrl, t.imageUrl "
                "FROM ORDER_DETAILS AS d "
                "JOIN CUSTOM_DESIGN AS cd ON cd.designID = d.designID "
                "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
                "JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "
                "LEFT JOIN REVIEW AS r ON r.orderDetailsID = d.orderDetailsID "
                "WHERE d.orderID = ? ORDER BY d.orderDetailsID",
                (order_id,),
            ).fetchall()
            history = cursor.execute(
                "SELECT newState, changedTime FROM ORDER_STATUS_HISTORY "
                "WHERE orderID = ? ORDER BY changedTime, historyID",
                (order_id,),
            ).fetchall()
            return {
                "id": header[0], "date": header[1], "state": header[2],
                "address": header[3], "subtotal": header[4],
                "shipping_method": header[5], "shipping_fee": header[6],
                "payment_method": header[7], "payment_state": header[8], "total": header[9],
                "details": [{"detail_id": r[0], "quantity": r[1], "unit_price": r[2],
                             "total": r[3], "design_name": r[4], "product_name": r[5],
                             "design_score": r[6], "quality_score": r[7],
                             "image": design_thumbnail(r[8], r[9], r[10])[0],
                             "image_version": design_thumbnail(r[8], r[9], r[10])[1]}
                            for r in details],
                "history": [{"state": r[0], "time": r[1]} for r in history],
            }
        finally:
            cursor.close()
    finally:
        connection.close()

def submit_review(
    customer_id: int, order_id: int, detail_id: int, design_score: int, quality_score: int
) -> bool:
    if not 1 <= design_score <= 5 or not 1 <= quality_score <= 5:
        raise ValueError("Điểm đánh giá phải từ 1 đến 5.")
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            eligible = cursor.execute(
                "SELECT 1 FROM [ORDER] AS o "
                "JOIN ORDER_DETAILS AS d ON d.orderID = o.orderID "
                "LEFT JOIN REVIEW AS r ON r.orderDetailsID = d.orderDetailsID "
                "WHERE o.orderID = ? AND o.customerID = ? "
                "AND o.state = 'Delivered' AND d.orderDetailsID = ? "
                "AND r.orderDetailsID IS NULL",
                (order_id, customer_id, detail_id),
            ).fetchone()
            if eligible is None:
                return False
            cursor.execute(
                "INSERT INTO REVIEW (orderDetailsID, customerID, design, quality) "
                "VALUES (?, ?, ?, ?)",
                (detail_id, customer_id, design_score, quality_score),
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()

# --- app/orders/routes.py ---
orders = Blueprint("orders", __name__, url_prefix="/orders")

@orders.get("/")
@role_required("customer")
def history():
    try:
        items = list_orders(session["profile_id"])
    except Exception:
        current_app.logger.exception("Order history query failed")
        return render_page("catalog_error"), 503
    return render_page("orders_index", orders=items)

@orders.get("/<int:order_id>")
@role_required("customer")
def detail(order_id: int):
    try:
        item = get_order(session["profile_id"], order_id)
    except Exception:
        current_app.logger.exception("Order detail query failed")
        return render_page("catalog_error"), 503
    if item is None:
        abort(404)
    return render_page("orders_detail", item=item)

@orders.post("/<int:order_id>/review/<int:detail_id>")
@role_required("customer")
def review(order_id: int, detail_id: int):
    try:
        design_score = int(request.form.get("design", "0"))
        quality_score = int(request.form.get("quality", "0"))
        if not 1 <= design_score <= 5 or not 1 <= quality_score <= 5:
            raise ValueError
    except ValueError:
        flash("Điểm đánh giá phải từ 1 đến 5.", "error")
        return redirect(url_for("orders.detail", order_id=order_id))
    try:
        saved = submit_review(
            session["profile_id"], order_id, detail_id,
            design_score, quality_score,
        )
    except Exception:
        current_app.logger.exception("Order review save failed")
        flash("Chưa thể lưu đánh giá. Vui lòng thử lại.", "error")
        return redirect(url_for("orders.detail", order_id=order_id))
    if not saved:
        abort(404)
    flash("Đã lưu đánh giá.", "success")
    return redirect(url_for("orders.detail", order_id=order_id))

# --- app/cart/routes.py ---
cart = Blueprint("cart", __name__, url_prefix="/cart")

MAX_SQL_INT = 2_147_483_647

def _quantities() -> dict[int, int]:
    raw = session.get("cart", {})
    if not isinstance(raw, dict):
        return {}
    result = {}
    for key, value in raw.items():
        try:
            design_id, quantity = int(key), int(value)
        except (TypeError, ValueError):
            continue
        if design_id > 0 and 1 <= quantity <= MAX_SQL_INT:
            result[design_id] = quantity
    return result

def _checkout_context(customer_id: int, quantities: dict[int, int], address: str):
    items = cart_items(customer_id, quantities)
    options = shipping_options()
    subtotal = sum((item["total"] for item in items), Decimal("0"))
    return items, options, subtotal, address

@cart.get("/")
@role_required("customer")
def index():
    quantities = _quantities()
    try:
        items = cart_items(session["profile_id"], quantities)
    except Exception:
        current_app.logger.exception("Cart query failed")
        return render_page("catalog_error"), 503
    subtotal = sum((item["total"] for item in items), Decimal("0"))
    return render_page("cart_index", items=items, subtotal=subtotal)

@cart.post("/add/<int:design_id>")
@role_required("customer")
def add(design_id: int):
    try:
        owned = owns_design(session["profile_id"], design_id)
    except Exception:
        current_app.logger.exception("Cart ownership check failed")
        return render_page("catalog_error"), 503
    if not owned:
        abort(404)
    quantities = _quantities()
    try:
        quantity = int(request.form.get("quantity", "1"))
    except ValueError:
        quantity = 0
    if quantity < 1 or quantity > MAX_SQL_INT:
        flash("Số lượng không hợp lệ.", "error")
        return redirect(url_for("designs.edit", design_id=design_id))
    new_quantity = quantities.get(design_id, 0) + quantity
    if new_quantity > MAX_SQL_INT:
        flash("Số lượng vượt giới hạn.", "error")
        return redirect(url_for("designs.edit", design_id=design_id))
    quantities[design_id] = new_quantity
    session["cart"] = {str(key): value for key, value in quantities.items()}
    flash("Đã thêm thiết kế vào giỏ hàng.", "success")
    return redirect(url_for("cart.index"))

@cart.post("/update/<int:design_id>")
@role_required("customer")
def update(design_id: int):
    quantities = _quantities()
    if design_id not in quantities:
        abort(404)
    try:
        quantity = int(request.form.get("quantity", ""))
    except ValueError:
        quantity = 0
    if quantity < 1 or quantity > MAX_SQL_INT:
        flash("Số lượng không hợp lệ.", "error")
    else:
        quantities[design_id] = quantity
        session["cart"] = {str(key): value for key, value in quantities.items()}
        flash("Đã cập nhật số lượng.", "success")
    return redirect(url_for("cart.index"))

@cart.post("/remove/<int:design_id>")
@role_required("customer")
def remove(design_id: int):
    quantities = _quantities()
    quantities.pop(design_id, None)
    session["cart"] = {str(key): value for key, value in quantities.items()}
    return redirect(url_for("cart.index"))

@cart.route("/checkout", methods=["GET", "POST"])
@role_required("customer")
def checkout():
    customer_id = session["profile_id"]
    quantities = _quantities()
    address = request.form.get("address", "").strip() if request.method == "POST" else ""
    try:
        items, options, subtotal, _ = _checkout_context(customer_id, quantities, address)
        if request.method == "GET":
            address = customer_address(customer_id)
    except Exception:
        current_app.logger.exception("Checkout preparation failed")
        return render_page("catalog_error"), 503
    if not items or len(items) != len(quantities):
        flash("Giỏ hàng trống hoặc có thiết kế không còn hợp lệ.", "error")
        return redirect(url_for("cart.index"))
    if not options:
        flash("Hiện chưa có phương thức giao hàng khả dụng.", "error")
        return redirect(url_for("cart.index"))

    if request.method == "POST":
        try:
            selected_index = int(request.form.get("shipping_option", "-1"))
            selected = options[selected_index] if 0 <= selected_index < len(options) else None
            if selected is None:
                raise CheckoutError("Vui lòng chọn phương thức giao hàng hợp lệ.")
            order_id = create_order(
                customer_id, quantities, address, selected["method"],
                Decimal(str(selected["fee"])),
                request.form.get("payment_method", ""),
            )
        except CheckoutError as error:
            flash(str(error), "error")
            return render_page(
                "cart_checkout", items=items, options=options,
                address=address, subtotal=subtotal,
            ), 400
        except Exception:
            current_app.logger.exception("Order checkout failed")
            flash("Chưa thể tạo đơn. Vui lòng thử lại sau.", "error")
            return render_page(
                "cart_checkout", items=items, options=options,
                address=address, subtotal=subtotal,
            ), 503
        session.pop("cart", None)
        flash("Đặt hàng thành công.", "success")
        return redirect(url_for("orders.detail", order_id=order_id))

    return render_page(
        "cart_checkout", items=items, options=options, address=address,
        subtotal=subtotal,
    )

# --- app/staff/service.py ---
ORDER_STATES = ("Pending", "Processing", "Shipping", "Delivered", "Cancelled")

ORDER_STATE_LABELS = {
    "Pending": "Đơn mới – chờ xác nhận",
    "Processing": "Đang xử lý / in ấn",
    "Shipping": "Đang giao",
    "Delivered": "Đã giao",
    "Cancelled": "Đã hủy",
}

ORDER_TRANSITIONS = {
    "Pending": ("Processing", "Cancelled"),
    "Processing": ("Shipping", "Cancelled"),
    "Shipping": ("Delivered", "Cancelled"),
    "Delivered": (),
    "Cancelled": (),
}

PAYMENT_LABELS = {
    "Pending": "Chưa thanh toán", "Paid": "Đã thanh toán",
    "Failed": "Thất bại", "Refunded": "Đã hoàn tiền",
}

PAYMENT_TRANSITIONS = {
    "Pending": ("Paid", "Failed"),
    "Failed": ("Paid",),
    "Paid": ("Refunded",),
    "Refunded": (),
}

APPROVAL_LABELS = {"Pending": "Chờ duyệt", "Approved": "Đã duyệt", "Rejected": "Từ chối / ẩn"}

STAFF_PAGE_SIZE = 20

_TEMPLATE_IMAGE_DIR = Path(__file__).resolve().parent / "static" / "img" / "templates"

_MAX_TEMPLATE_IMAGE_BYTES = 2_000_000

_MAX_MONEY = 999_999_999_999_999_999


class StaffError(ValueError):
    """A business-rule violation whose message is safe to show to staff."""


@contextmanager
def _cursor(commit: bool = False):
    """Open a cursor; commit on success when asked, roll back on any error."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            yield cursor
            if commit:
                connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()
    finally:
        connection.close()


def _nfc(text: str | None) -> str:
    return unicodedata.normalize("NFC", text or "").casefold()


def capabilities_for(role: str, position: str | None) -> frozenset[str]:
    """Which staff areas a signed-in account may use (see the report's tables 3-6).

    The EMPLOYEE.position text acts as the employee type: design staff manage
    templates, customer-care staff look things up read-only, and every other
    position (in ấn, giao hàng, kho, xử lý đơn...) processes orders and payments.
    """
    if role == "admin":
        return frozenset({"orders_view", "orders_manage", "templates", "customers"})
    text = _nfc(position)
    if "thiết kế" in text:
        return frozenset({"templates"})
    if "chăm sóc" in text:
        return frozenset({"orders_view", "customers"})
    return frozenset({"orders_view", "orders_manage"})


def employee_position(employee_id: int) -> str:
    with _cursor() as cursor:
        row = cursor.execute(
            "SELECT position FROM EMPLOYEE WHERE employeeID = ?", (employee_id,)
        ).fetchone()
    return (row[0] or "") if row else ""


def _like(text: str) -> str:
    escaped = text.replace("[", "[[]").replace("%", "[%]").replace("_", "[_]")
    return f"%{escaped}%"


# ---- orders ---------------------------------------------------------------
_ORDER_FROM = (
    "FROM [ORDER] AS o "
    "JOIN CUSTOMER AS c ON c.customerID = o.customerID "
    "JOIN ACCOUNT AS a ON a.accountID = c.accountID "
    "LEFT JOIN PAYMENT AS p ON p.orderID = o.orderID "
)


def _order_filters(state: str, q: str) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if state in ORDER_STATES:
        clauses.append("o.state = ?")
        params.append(state)
    if q:
        parts = ["c.fullName LIKE ?", "c.phone LIKE ?", "a.email LIKE ?"]
        values: list[Any] = [_like(q)] * 3
        if q.isdigit() and len(q) <= 9:
            parts.insert(0, "o.orderID = ?")
            values.insert(0, int(q))
        clauses.append("(" + " OR ".join(parts) + ")")
        params.extend(values)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def count_staff_orders(state: str, q: str) -> int:
    where, params = _order_filters(state, q)
    with _cursor() as cursor:
        return int(cursor.execute(f"SELECT COUNT(*) {_ORDER_FROM}{where}", params).fetchone()[0])


def list_staff_orders(state: str, q: str, page: int) -> list[dict[str, Any]]:
    where, params = _order_filters(state, q)
    params.extend(((page - 1) * STAFF_PAGE_SIZE, STAFF_PAGE_SIZE))
    with _cursor() as cursor:
        rows = cursor.execute(
            "SELECT o.orderID, o.orderDate, o.state, o.basePrice, c.fullName, c.phone, "
            f"p.state, p.total {_ORDER_FROM}{where} "
            "ORDER BY o.orderDate DESC, o.orderID DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            params,
        ).fetchall()
    return [{
        "id": r[0], "date": r[1], "state": r[2], "subtotal": r[3], "customer": r[4],
        "phone": r[5], "payment_state": r[6], "payment_total": r[7],
    } for r in rows]


def order_state_counts() -> dict[str, int]:
    with _cursor() as cursor:
        rows = cursor.execute("SELECT state, COUNT(*) FROM [ORDER] GROUP BY state").fetchall()
    return {str(r[0]): int(r[1]) for r in rows}


def get_staff_order(order_id: int) -> dict[str, Any] | None:
    with _cursor() as cursor:
        header = cursor.execute(
            "SELECT o.orderID, o.orderDate, o.state, o.address, o.basePrice, "
            "c.customerID, c.fullName, c.phone, a.email, s.method, s.fee, "
            "p.method, p.state, p.time, p.total "
            "FROM [ORDER] AS o "
            "JOIN CUSTOMER AS c ON c.customerID = o.customerID "
            "JOIN ACCOUNT AS a ON a.accountID = c.accountID "
            "LEFT JOIN SHIPMENT AS s ON s.orderID = o.orderID "
            "LEFT JOIN PAYMENT AS p ON p.orderID = o.orderID "
            "WHERE o.orderID = ?",
            (order_id,),
        ).fetchone()
        if header is None:
            return None
        details = cursor.execute(
            "SELECT d.orderDetailsID, d.quantity, d.basePrice, d.total, t.designName, "
            "pt.productName, t.content, cd.designID, cd.imageUrl, t.imageUrl "
            "FROM ORDER_DETAILS AS d "
            "JOIN CUSTOM_DESIGN AS cd ON cd.designID = d.designID "
            "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
            "JOIN PRODUCT_TYPE AS pt ON pt.productID = t.productID "
            "WHERE d.orderID = ? ORDER BY d.orderDetailsID",
            (order_id,),
        ).fetchall()
        history = cursor.execute(
            "SELECT h.newState, h.changedTime, e.fullName "
            "FROM ORDER_STATUS_HISTORY AS h "
            "LEFT JOIN EMPLOYEE AS e ON e.employeeID = h.employeeID "
            "WHERE h.orderID = ? ORDER BY h.changedTime, h.historyID",
            (order_id,),
        ).fetchall()

    lines = []
    for r in details:
        try:
            size = (json.loads(r[6]) if r[6] else {}).get("size", "")
        except (TypeError, ValueError, AttributeError):
            size = ""
        own_image, _ = design_image_info(int(r[7]), r[8])
        image, version = design_thumbnail(int(r[7]), r[8], r[9])
        lines.append({
            "detail_id": r[0], "quantity": r[1], "unit_price": r[2], "total": r[3],
            "design_name": r[4], "product_name": r[5], "size": size, "design_id": r[7],
            "image": image, "image_version": version, "has_custom_image": own_image is not None,
        })
    return {
        "id": header[0], "date": header[1], "state": header[2], "address": header[3],
        "subtotal": header[4], "customer_id": header[5], "customer": header[6],
        "phone": header[7], "email": header[8], "shipping_method": header[9],
        "shipping_fee": header[10] or 0, "payment_method": header[11],
        "payment_state": header[12], "payment_time": header[13], "total": header[14],
        "details": lines,
        "history": [{"state": r[0], "time": r[1], "employee": r[2]} for r in history],
    }


def update_order_state(order_id: int, new_state: str, employee_id: int | None) -> None:
    with _cursor(commit=True) as cursor:
        row = cursor.execute(
            "SELECT state FROM [ORDER] WITH (UPDLOCK, ROWLOCK) WHERE orderID = ?", (order_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Order not found")
        current = str(row[0]).strip()
        if new_state not in ORDER_TRANSITIONS.get(current, ()):
            raise StaffError(
                f"Không thể chuyển đơn từ “{ORDER_STATE_LABELS.get(current, current)}” "
                f"sang “{ORDER_STATE_LABELS.get(new_state, new_state)}”."
            )
        cursor.execute("UPDATE [ORDER] SET state = ? WHERE orderID = ?", (new_state, order_id))
        cursor.execute(
            "INSERT INTO ORDER_STATUS_HISTORY (orderID, newState, employeeID) VALUES (?, ?, ?)",
            (order_id, new_state, employee_id),
        )


def update_payment_state(order_id: int, new_state: str) -> None:
    with _cursor(commit=True) as cursor:
        row = cursor.execute(
            "SELECT p.state, o.state FROM PAYMENT AS p WITH (UPDLOCK, ROWLOCK) "
            "JOIN [ORDER] AS o ON o.orderID = p.orderID WHERE p.orderID = ?",
            (order_id,),
        ).fetchone()
        if row is None:
            raise LookupError("Payment not found")
        current, order_state = str(row[0]).strip(), str(row[1]).strip()
        if new_state not in PAYMENT_TRANSITIONS.get(current, ()):
            raise StaffError(
                f"Không thể chuyển thanh toán từ “{PAYMENT_LABELS.get(current, current)}” "
                f"sang “{PAYMENT_LABELS.get(new_state, new_state)}”."
            )
        if new_state == "Paid" and order_state == "Cancelled":
            raise StaffError("Đơn đã hủy nên không thể ghi nhận đã thanh toán.")
        if new_state == "Paid":
            cursor.execute(
                "UPDATE PAYMENT SET state = 'Paid', time = SYSDATETIME() WHERE orderID = ?",
                (order_id,),
            )
        else:
            cursor.execute("UPDATE PAYMENT SET state = ? WHERE orderID = ?", (new_state, order_id))


# ---- customers (read-only lookup) ----------------------------------------
def _customer_filters(q: str) -> tuple[str, list[Any]]:
    if not q:
        return "", []
    parts = ["c.fullName LIKE ?", "c.phone LIKE ?", "a.email LIKE ?"]
    values: list[Any] = [_like(q)] * 3
    if q.isdigit() and len(q) <= 9:
        parts.insert(0, "c.customerID = ?")
        values.insert(0, int(q))
    return " WHERE (" + " OR ".join(parts) + ")", values


_CUSTOMER_FROM = "FROM CUSTOMER AS c JOIN ACCOUNT AS a ON a.accountID = c.accountID "


def count_customers(q: str) -> int:
    where, params = _customer_filters(q)
    with _cursor() as cursor:
        return int(cursor.execute(f"SELECT COUNT(*) {_CUSTOMER_FROM}{where}", params).fetchone()[0])


def list_customers(q: str, page: int) -> list[dict[str, Any]]:
    where, params = _customer_filters(q)
    params.extend(((page - 1) * STAFF_PAGE_SIZE, STAFF_PAGE_SIZE))
    with _cursor() as cursor:
        rows = cursor.execute(
            "SELECT c.customerID, c.fullName, a.email, c.phone, c.address, a.isActive, a.createdAt, "
            "(SELECT COUNT(*) FROM [ORDER] AS o WHERE o.customerID = c.customerID) "
            f"{_CUSTOMER_FROM}{where} ORDER BY c.customerID DESC "
            "OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            params,
        ).fetchall()
    return [{
        "id": r[0], "name": r[1], "email": r[2], "phone": r[3] or "", "address": r[4] or "",
        "active": bool(r[5]), "created": r[6], "orders": int(r[7]),
    } for r in rows]


# ---- templates ------------------------------------------------------------
def product_type_options() -> list[dict[str, Any]]:
    with _cursor() as cursor:
        rows = cursor.execute(
            "SELECT MIN(productID), MIN(productName) FROM PRODUCT_TYPE "
            "WHERE LOWER(LTRIM(RTRIM(productName))) IN (?, ?, ?) "
            "GROUP BY LOWER(LTRIM(RTRIM(productName))) ORDER BY MIN(productID)",
            _NORMALIZED_PRODUCT_NAMES,
        ).fetchall()
    return [{"id": int(r[0]), "name": str(r[1]).strip()} for r in rows]


def _template_filters(status: str, product_id: int | None, q: str) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if status in APPROVAL_LABELS:
        clauses.append("t.approvalState = ?")
        params.append(status)
    if product_id:
        clauses.append("t.productID = ?")
        params.append(product_id)
    if q:
        clauses.append("(t.designName LIKE ? OR t.info LIKE ?)")
        params.extend((_like(q), _like(q)))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


_TEMPLATE_FROM = "FROM TEMPLATE AS t JOIN PRODUCT_TYPE AS p ON p.productID = t.productID "


def count_staff_templates(status: str, product_id: int | None, q: str) -> int:
    where, params = _template_filters(status, product_id, q)
    with _cursor() as cursor:
        return int(cursor.execute(f"SELECT COUNT(*) {_TEMPLATE_FROM}{where}", params).fetchone()[0])


def list_staff_templates(status: str, product_id: int | None, q: str, page: int) -> list[dict[str, Any]]:
    where, params = _template_filters(status, product_id, q)
    params.extend(((page - 1) * STAFF_PAGE_SIZE, STAFF_PAGE_SIZE))
    with _cursor() as cursor:
        rows = cursor.execute(
            "SELECT t.designID, t.designName, t.imageUrl, t.basePrice, t.info, "
            f"t.approvalState, p.productName {_TEMPLATE_FROM}{where} "
            "ORDER BY t.designID DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            params,
        ).fetchall()
    result = []
    for r in rows:
        preview = _preview_image_path(r[2])
        result.append({
            "id": r[0], "name": r[1], "preview_image": preview,
            "preview_version": _preview_image_version(preview), "price": r[3],
            "info": r[4] or "", "approval": r[5], "product_name": r[6],
        })
    return result


def count_pending_templates() -> int:
    with _cursor() as cursor:
        return int(cursor.execute(
            "SELECT COUNT(*) FROM TEMPLATE WHERE approvalState = 'Pending'"
        ).fetchone()[0])


def get_staff_template(template_id: int) -> dict[str, Any] | None:
    with _cursor() as cursor:
        r = cursor.execute(
            "SELECT t.designID, t.designName, t.imageUrl, t.content, t.basePrice, t.info, "
            "t.productID, t.approvalState "
            "FROM TEMPLATE AS t WHERE t.designID = ?",
            (template_id,),
        ).fetchone()
    if r is None:
        return None
    try:
        content = json.loads(r[3]) if r[3] else {}
    except (TypeError, ValueError):
        content = {}
    if not isinstance(content, dict):
        content = {}
    preview = _preview_image_path(r[2])
    return {
        "id": r[0], "name": r[1], "image_url": r[2], "content": content, "price": r[4],
        "info": r[5] or "", "product_id": r[6], "approval": r[7],
        "preview_image": preview, "preview_version": _preview_image_version(preview),
    }


def save_template(
    template_id: int | None, *, name: str, product_id: int, price: int, info: str,
    image_url: str | None, content: dict[str, Any], approval: str,
) -> int:
    payload = json.dumps(content, ensure_ascii=False, separators=(",", ":"))
    with _cursor(commit=True) as cursor:
        if template_id is None:
            row = cursor.execute(
                "INSERT INTO TEMPLATE (designName, imageUrl, content, basePrice, info, productID, approvalState) "
                "OUTPUT INSERTED.designID VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, image_url, payload, price, info or None, product_id, approval),
            ).fetchone()
            return int(row[0])
        cursor.execute(
            "UPDATE TEMPLATE SET designName = ?, imageUrl = ?, content = ?, basePrice = ?, "
            "info = ?, productID = ?, approvalState = ? WHERE designID = ?",
            (name, image_url, payload, price, info or None, product_id, approval, template_id),
        )
        if cursor.rowcount != 1:
            raise LookupError("Template not found")
        return template_id


def delete_template(template_id: int) -> None:
    with _cursor(commit=True) as cursor:
        used = cursor.execute(
            "SELECT COUNT(*) FROM CUSTOM_DESIGN WHERE templateID = ?", (template_id,)
        ).fetchone()[0]
        if used:
            raise StaffError(
                "Mẫu đã được khách hàng dùng để thiết kế nên không thể xóa. "
                "Hãy chuyển sang “Từ chối / ẩn” để ngừng hiển thị."
            )
        cursor.execute("DELETE FROM TEMPLATE WHERE designID = ?", (template_id,))
        if cursor.rowcount != 1:
            raise LookupError("Template not found")


def review_template(template_id: int, decision: str) -> None:
    state = {"approve": "Approved", "reject": "Rejected"}.get(decision)
    if state is None:
        raise StaffError("Quyết định duyệt không hợp lệ.")
    with _cursor(commit=True) as cursor:
        cursor.execute("UPDATE TEMPLATE SET approvalState = ? WHERE designID = ?", (state, template_id))
        if cursor.rowcount != 1:
            raise LookupError("Template not found")


def update_template_price(template_id: int, price: int) -> None:
    with _cursor(commit=True) as cursor:
        cursor.execute("UPDATE TEMPLATE SET basePrice = ? WHERE designID = ?", (price, template_id))
        if cursor.rowcount != 1:
            raise LookupError("Template not found")


def _image_extension(raw: bytes) -> str | None:
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if raw.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return ".webp"
    return None


def store_template_image(raw: bytes) -> str:
    """Save a validated template image and return its /img/templates/... URL."""
    extension = _image_extension(raw)
    if extension is None:
        raise StaffError("Ảnh mẫu chỉ hỗ trợ PNG, JPG hoặc WEBP hợp lệ.")
    if len(raw) > _MAX_TEMPLATE_IMAGE_BYTES:
        raise StaffError("Ảnh mẫu vượt quá 2 MB.")
    _TEMPLATE_IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"tpl_{secrets.token_hex(8)}{extension}"
    (_TEMPLATE_IMAGE_DIR / filename).write_bytes(raw)
    return f"/img/templates/{filename}"


def remove_template_image(image_url: str | None) -> None:
    """Delete a just-uploaded image when the database write failed."""
    if image_url and re.fullmatch(r"/img/templates/tpl_[0-9a-f]{16}\.(png|jpg|webp)", image_url):
        try:
            (_TEMPLATE_IMAGE_DIR / PurePosixPath(image_url).name).unlink()
        except OSError:
            pass


# ---- accounts (admin) -----------------------------------------------------
_ACCOUNT_FROM = (
    "FROM ACCOUNT AS a "
    "LEFT JOIN CUSTOMER AS c ON c.accountID = a.accountID "
    "LEFT JOIN EMPLOYEE AS e ON e.accountID = a.accountID "
    "LEFT JOIN ADMIN AS ad ON ad.accountID = a.accountID "
)


def _account_filters(role: str, status: str, q: str) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if role in {"Customer", "Employee", "Admin"}:
        clauses.append("a.role = ?")
        params.append(role)
    if status == "active":
        clauses.append("a.isActive = 1")
    elif status == "locked":
        clauses.append("a.isActive = 0")
    if q:
        clauses.append(
            "(a.username LIKE ? OR a.email LIKE ? OR COALESCE(c.fullName, e.fullName, ad.fullName) LIKE ?)"
        )
        params.extend((_like(q),) * 3)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def count_accounts(role: str, status: str, q: str) -> int:
    where, params = _account_filters(role, status, q)
    with _cursor() as cursor:
        return int(cursor.execute(f"SELECT COUNT(*) {_ACCOUNT_FROM}{where}", params).fetchone()[0])


def _account_row(r: Any) -> dict[str, Any]:
    return {
        "id": r[0], "username": r[1], "email": r[2], "role": r[3], "active": bool(r[4]),
        "created": r[5], "full_name": r[6] or "", "phone": r[7] or "", "position": r[8] or "",
        "address": r[9] if len(r) > 9 and r[9] else "",
    }


def list_accounts(role: str, status: str, q: str, page: int) -> list[dict[str, Any]]:
    where, params = _account_filters(role, status, q)
    params.extend(((page - 1) * STAFF_PAGE_SIZE, STAFF_PAGE_SIZE))
    with _cursor() as cursor:
        rows = cursor.execute(
            "SELECT a.accountID, a.username, a.email, a.role, a.isActive, a.createdAt, "
            "COALESCE(c.fullName, e.fullName, ad.fullName), COALESCE(c.phone, e.phone, ad.phone), e.position "
            f"{_ACCOUNT_FROM}{where} ORDER BY a.accountID DESC OFFSET ? ROWS FETCH NEXT ? ROWS ONLY",
            params,
        ).fetchall()
    return [_account_row(r) for r in rows]


def get_account(account_id: int) -> dict[str, Any] | None:
    with _cursor() as cursor:
        r = cursor.execute(
            "SELECT a.accountID, a.username, a.email, a.role, a.isActive, a.createdAt, "
            "COALESCE(c.fullName, e.fullName, ad.fullName), COALESCE(c.phone, e.phone, ad.phone), "
            "e.position, COALESCE(c.address, e.address) "
            f"{_ACCOUNT_FROM}WHERE a.accountID = ?",
            (account_id,),
        ).fetchone()
    return _account_row(r) if r else None


def update_account(
    account_id: int, *, full_name: str, phone: str | None, address: str | None,
    position: str | None, new_password: str,
) -> None:
    with _cursor(commit=True) as cursor:
        row = cursor.execute(
            "SELECT role FROM ACCOUNT WITH (UPDLOCK, ROWLOCK) WHERE accountID = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Account not found")
        role = str(row[0]).strip()
        if role == "Customer":
            cursor.execute(
                "UPDATE CUSTOMER SET fullName = ?, phone = ?, address = ? WHERE accountID = ?",
                (full_name, phone, address, account_id),
            )
        elif role == "Employee":
            cursor.execute(
                "UPDATE EMPLOYEE SET fullName = ?, phone = ?, address = ?, position = ? WHERE accountID = ?",
                (full_name, phone, address, position, account_id),
            )
        else:
            cursor.execute(
                "UPDATE ADMIN SET fullName = ?, phone = ? WHERE accountID = ?",
                (full_name, phone, account_id),
            )
        if new_password:
            cursor.execute(
                "UPDATE ACCOUNT SET [password] = ? WHERE accountID = ?",
                (generate_password_hash(new_password, method="scrypt"), account_id),
            )


def set_account_active(account_id: int, active: bool, actor_account_id: int) -> None:
    if account_id == actor_account_id and not active:
        raise StaffError("Bạn không thể tự khóa tài khoản đang đăng nhập.")
    with _cursor(commit=True) as cursor:
        cursor.execute("UPDATE ACCOUNT SET isActive = ? WHERE accountID = ?", (1 if active else 0, account_id))
        if cursor.rowcount != 1:
            raise LookupError("Account not found")


def delete_account(account_id: int, actor_account_id: int) -> None:
    if account_id == actor_account_id:
        raise StaffError("Bạn không thể tự xóa tài khoản đang đăng nhập.")
    blocked = StaffError("Tài khoản đã phát sinh dữ liệu (thiết kế, đơn hàng hoặc lịch sử xử lý) nên không thể xóa. Hãy khóa tài khoản.")
    with _cursor(commit=True) as cursor:
        row = cursor.execute(
            "SELECT role FROM ACCOUNT WITH (UPDLOCK, ROWLOCK) WHERE accountID = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise LookupError("Account not found")
        role = str(row[0]).strip()
        if role == "Customer":
            used = cursor.execute(
                "SELECT (SELECT COUNT(*) FROM CUSTOM_DESIGN AS cd JOIN CUSTOMER AS c ON c.customerID = cd.customerID WHERE c.accountID = ?) "
                "+ (SELECT COUNT(*) FROM [ORDER] AS o JOIN CUSTOMER AS c ON c.customerID = o.customerID WHERE c.accountID = ?) "
                "+ (SELECT COUNT(*) FROM REVIEW AS r JOIN CUSTOMER AS c ON c.customerID = r.customerID WHERE c.accountID = ?)",
                (account_id, account_id, account_id),
            ).fetchone()[0]
            if used:
                raise blocked
            cursor.execute("DELETE FROM CUSTOMER WHERE accountID = ?", (account_id,))
        elif role == "Employee":
            used = cursor.execute(
                "SELECT COUNT(*) FROM ORDER_STATUS_HISTORY AS h "
                "JOIN EMPLOYEE AS e ON e.employeeID = h.employeeID WHERE e.accountID = ?",
                (account_id,),
            ).fetchone()[0]
            if used:
                raise blocked
            cursor.execute("DELETE FROM EMPLOYEE WHERE accountID = ?", (account_id,))
        else:
            cursor.execute("DELETE FROM ADMIN WHERE accountID = ?", (account_id,))
        cursor.execute("DELETE FROM ACCOUNT WHERE accountID = ?", (account_id,))


# ---- reports (admin) ------------------------------------------------------
def _months(start: date, end: date) -> list[tuple[int, int]]:
    result, year, month = [], start.year, start.month
    while (year, month) <= (end.year, end.month):
        result.append((year, month))
        month += 1
        if month > 12:
            year, month = year + 1, 1
    return result


def build_report(start: date, end: date) -> dict[str, Any]:
    lower = datetime.combine(start, datetime.min.time())
    upper = datetime.combine(end + timedelta(days=1), datetime.min.time())
    window = (lower, upper)
    order_value = "CASE WHEN o.state <> 'Cancelled' THEN COALESCE(p.total, o.basePrice) ELSE 0 END"
    paid_value = "CASE WHEN p.state = 'Paid' THEN p.total ELSE 0 END"
    order_from = "FROM [ORDER] AS o LEFT JOIN PAYMENT AS p ON p.orderID = o.orderID "
    in_range = "o.orderDate >= ? AND o.orderDate < ?"
    with _cursor() as cursor:
        totals = cursor.execute(
            f"SELECT COUNT(*), COALESCE(SUM({order_value}), 0), COALESCE(SUM({paid_value}), 0) "
            f"{order_from}WHERE {in_range}", window,
        ).fetchone()
        by_state = cursor.execute(
            f"SELECT o.state, COUNT(*) {order_from}WHERE {in_range} GROUP BY o.state", window,
        ).fetchall()
        monthly = cursor.execute(
            f"SELECT YEAR(o.orderDate), MONTH(o.orderDate), COUNT(*), SUM({order_value}), SUM({paid_value}) "
            f"{order_from}WHERE {in_range} GROUP BY YEAR(o.orderDate), MONTH(o.orderDate)", window,
        ).fetchall()
        customers = cursor.execute(
            "SELECT YEAR(createdAt), MONTH(createdAt), COUNT(*) FROM ACCOUNT "
            "WHERE role = 'Customer' AND createdAt >= ? AND createdAt < ? "
            "GROUP BY YEAR(createdAt), MONTH(createdAt)", window,
        ).fetchall()
        top = cursor.execute(
            "SELECT TOP (10) t.designName, pt.productName, SUM(d.quantity), COUNT(DISTINCT o.orderID), "
            "SUM(d.total), AVG(CAST(r.design AS FLOAT)), AVG(CAST(r.quality AS FLOAT)) "
            "FROM ORDER_DETAILS AS d "
            "JOIN [ORDER] AS o ON o.orderID = d.orderID "
            "JOIN CUSTOM_DESIGN AS cd ON cd.designID = d.designID "
            "JOIN TEMPLATE AS t ON t.designID = cd.templateID "
            "JOIN PRODUCT_TYPE AS pt ON pt.productID = t.productID "
            "LEFT JOIN REVIEW AS r ON r.orderDetailsID = d.orderDetailsID "
            f"WHERE o.state <> 'Cancelled' AND {in_range} "
            "GROUP BY t.designID, t.designName, pt.productName "
            "ORDER BY SUM(d.quantity) DESC, SUM(d.total) DESC", window,
        ).fetchall()
        staff_rows = cursor.execute(
            "SELECT e.fullName, e.position, COUNT(*), COUNT(DISTINCT h.orderID), "
            "SUM(CASE WHEN h.newState = 'Delivered' THEN 1 ELSE 0 END) "
            "FROM ORDER_STATUS_HISTORY AS h JOIN EMPLOYEE AS e ON e.employeeID = h.employeeID "
            "WHERE h.changedTime >= ? AND h.changedTime < ? "
            "GROUP BY e.employeeID, e.fullName, e.position ORDER BY COUNT(*) DESC", window,
        ).fetchall()
        ratings = cursor.execute(
            "SELECT COUNT(*), AVG(CAST(r.design AS FLOAT)), AVG(CAST(r.quality AS FLOAT)) "
            "FROM REVIEW AS r JOIN ORDER_DETAILS AS d ON d.orderDetailsID = r.orderDetailsID "
            "JOIN [ORDER] AS o ON o.orderID = d.orderID "
            f"WHERE {in_range}", window,
        ).fetchone()

    month_map = {(int(r[0]), int(r[1])): r for r in monthly}
    customer_map = {(int(r[0]), int(r[1])): int(r[2]) for r in customers}
    rows = []
    for year, month in _months(start, end):
        m = month_map.get((year, month))
        rows.append({
            "label": f"{month:02d}/{year}", "orders": int(m[2]) if m else 0,
            "value": Decimal(m[3] or 0) if m else Decimal(0),
            "paid": Decimal(m[4] or 0) if m else Decimal(0),
            "new_customers": customer_map.get((year, month), 0),
        })
    peak = max((row["value"] for row in rows), default=Decimal(0))
    for row in rows:
        row["bar"] = int(row["value"] * 100 / peak) if peak else 0
    return {
        "orders": int(totals[0]), "value": Decimal(totals[1] or 0), "paid": Decimal(totals[2] or 0),
        "new_customers": sum(customer_map.values()),
        "by_state": {str(r[0]): int(r[1]) for r in by_state},
        "months": rows,
        "top": [{
            "name": r[0], "product": r[1], "quantity": int(r[2]), "orders": int(r[3]),
            "total": Decimal(r[4] or 0), "design": r[5], "quality": r[6],
        } for r in top],
        "staff": [{
            "name": r[0], "position": r[1] or "", "changes": int(r[2]),
            "orders": int(r[3]), "delivered": int(r[4] or 0),
        } for r in staff_rows],
        "reviews": int(ratings[0]), "avg_design": ratings[1], "avg_quality": ratings[2],
    }


# --- app/staff/routes.py ---
staff = Blueprint("staff", __name__, url_prefix="/staff")

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

_TEMPLATE_SIZE = re.compile(r"^(?:\d{1,4}(?:\.\d)?x\d{1,4}(?:\.\d)?mm|A5)$")

_LAYOUT = re.compile(r"^[A-Za-z0-9_-]{1,50}$")

_STANDARD_POSITIONS = (
    "Nhân viên thiết kế", "Nhân viên xử lý đơn hàng", "Nhân viên chăm sóc khách hàng",
)


def _staff_caps() -> frozenset[str]:
    if "staff_caps" not in g:
        role = session.get("role", "")
        position = employee_position(session["profile_id"]) if role == "employee" else ""
        g.staff_caps = capabilities_for(role, position)
    return g.staff_caps


def staff_required(capability: str) -> Callable[[F], F]:
    """Employee/admin only, and the employee's position must grant `capability`."""
    def decorate(view: F) -> F:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            try:
                allowed = capability in _staff_caps()
            except Exception:
                current_app.logger.exception("Staff capability lookup failed")
                abort(503)
            if not allowed:
                abort(403)
            return view(*args, **kwargs)

        return role_required("employee", "admin")(wrapped)  # type: ignore[return-value]

    return decorate


def _employee_id() -> int | None:
    return int(session["profile_id"]) if session.get("role") == "employee" else None


def _arg(name: str) -> str:
    return request.args.get(name, "").strip()[:100]


def _int_arg(name: str) -> int | None:
    try:
        value = int(request.args.get(name, ""))
    except ValueError:
        return None
    return value if 0 < value <= 2_147_483_647 else None


def _paginate(total: int) -> tuple[int, int]:
    pages = max(1, ceil(total / STAFF_PAGE_SIZE))
    try:
        page = int(request.args.get("page", "1"))
    except ValueError:
        page = 1
    return min(max(1, page), pages), pages


def _clean_args(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value not in ("", None)}


def _back(default: str):
    """Redirect to the page the form came from, only when it is on this site."""
    referrer = request.referrer or ""
    parsed = urlparse(referrer)
    if parsed.netloc == request.host and parsed.path.startswith("/"):
        return redirect(parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    return redirect(default)


def _db_error(message: str):
    current_app.logger.exception(message)
    return render_page("catalog_error"), 503


def _dashboard_context(role: str) -> dict[str, Any]:
    menu: list[dict[str, str]] = []
    counts: dict[str, int] = {}
    pending_templates = 0
    failed = False
    try:
        caps = _staff_caps()
        if "orders_view" in caps:
            counts = order_state_counts()
        if role == "admin":
            pending_templates = count_pending_templates()
    except Exception:
        current_app.logger.exception("Dashboard data failed")
        caps, failed = frozenset(), True
    if "orders_view" in caps:
        menu.append({"title": "Đơn hàng", "desc": "Tiếp nhận, kiểm tra và theo dõi đơn.", "url": url_for("staff.order_list")})
    if "templates" in caps:
        menu.append({"title": "Quản lý mẫu", "desc": "Tạo, sửa, xóa mẫu thiết kế.", "url": url_for("staff.templates")})
    if "customers" in caps:
        menu.append({"title": "Tra cứu khách hàng", "desc": "Tìm hồ sơ để hỗ trợ (chỉ xem).", "url": url_for("staff.customers")})
    if role == "admin":
        menu = [
            {"title": "Tài khoản", "desc": "Tạo, sửa, khóa, xóa; phân loại nhân viên.", "url": url_for("admin.accounts")},
            {"title": "Duyệt mẫu", "desc": f"{pending_templates} mẫu đang chờ duyệt.", "url": url_for("staff.templates", status="Pending")},
            {"title": "Bảng giá", "desc": "Điều chỉnh giá theo mẫu.", "url": url_for("admin.prices")},
            {"title": "Thống kê", "desc": "Doanh thu, đơn hàng, khách mới, hiệu suất.", "url": url_for("admin.stats")},
        ] + menu
    return {"menu": menu, "order_counts": counts, "dashboard_failed": failed}


# ---- staff: orders ----
@staff.get("/orders")
@staff_required("orders_view")
def order_list():
    state, q = _arg("state"), _arg("q")
    if state not in ORDER_STATES:
        state = ""
    try:
        total = count_staff_orders(state, q)
        page, pages = _paginate(total)
        items = list_staff_orders(state, q, page) if total else []
    except Exception:
        return _db_error("Staff order list failed")
    return render_page(
        "staff_orders", items=items, state=state, q=q, total=total, page_number=page,
        pages=pages, args=_clean_args(state=state, q=q), pager_endpoint="staff.order_list",
    )


@staff.get("/orders/<int:order_id>")
@staff_required("orders_view")
def order_detail(order_id: int):
    try:
        item = get_staff_order(order_id)
    except Exception:
        return _db_error("Staff order detail failed")
    if item is None:
        abort(404)
    return render_page(
        "staff_order_detail", item=item, can_manage="orders_manage" in _staff_caps(),
        order_next=ORDER_TRANSITIONS.get(item["state"], ()),
        payment_next=PAYMENT_TRANSITIONS.get(item["payment_state"], ()),
    )


@staff.post("/orders/<int:order_id>/state")
@staff_required("orders_manage")
def order_set_state(order_id: int):
    try:
        update_order_state(order_id, request.form.get("new_state", ""), _employee_id())
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Order state update failed")
        flash("Chưa thể cập nhật trạng thái. Vui lòng thử lại.", "error")
    else:
        flash(f"Đã cập nhật trạng thái đơn #{order_id}.", "success")
    return redirect(url_for("staff.order_detail", order_id=order_id))


@staff.post("/orders/<int:order_id>/payment")
@staff_required("orders_manage")
def order_set_payment(order_id: int):
    try:
        update_payment_state(order_id, request.form.get("new_state", ""))
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Payment state update failed")
        flash("Chưa thể cập nhật thanh toán. Vui lòng thử lại.", "error")
    else:
        flash(f"Đã cập nhật thanh toán đơn #{order_id}.", "success")
    return redirect(url_for("staff.order_detail", order_id=order_id))


# ---- staff: customers ----
@staff.get("/customers")
@staff_required("customers")
def customers():
    q = _arg("q")
    try:
        total = count_customers(q)
        page, pages = _paginate(total)
        items = list_customers(q, page) if total else []
    except Exception:
        return _db_error("Customer lookup failed")
    return render_page(
        "staff_customers", items=items, q=q, total=total, page_number=page, pages=pages,
        args=_clean_args(q=q), pager_endpoint="staff.customers",
    )


# ---- staff: templates ----
def _template_values(source: Any) -> dict[str, str]:
    return {
        "name": source.get("name", "").strip(), "product_id": source.get("product_id", "").strip(),
        "price": source.get("price", "").strip(), "info": source.get("info", "").strip(),
        "layout": source.get("layout", "").strip(), "size": source.get("size", "").strip(),
    }


def _validate_template(values: dict[str, str], products: list[dict[str, Any]]) -> list[str]:
    errors = []
    if not values["name"] or len(values["name"]) > 100:
        errors.append("Tên mẫu là bắt buộc và tối đa 100 ký tự.")
    if not values["product_id"].isdigit() or int(values["product_id"]) not in {p["id"] for p in products}:
        errors.append("Vui lòng chọn loại sản phẩm hợp lệ.")
    if not values["price"].isdigit() or int(values["price"]) > 999_999_999_999:
        errors.append("Giá cơ bản phải là số nguyên không âm (VNĐ).")
    if len(values["info"]) > 500:
        errors.append("Mô tả tối đa 500 ký tự.")
    if values["layout"] and not _LAYOUT.fullmatch(values["layout"]):
        errors.append("Mã bố cục chỉ gồm chữ không dấu, số, gạch dưới hoặc gạch ngang.")
    if values["size"] and not _TEMPLATE_SIZE.fullmatch(values["size"]):
        errors.append("Kích thước phải có dạng 90x54mm hoặc A5.")
    return errors


def _template_form(template_id: int | None):
    try:
        products = product_type_options()
        existing = get_staff_template(template_id) if template_id else None
    except Exception:
        return _db_error("Template form load failed")
    if template_id and existing is None:
        abort(404)
    is_admin = session.get("role") == "admin"

    def show(values: dict[str, str], status: int = 200):
        return render_page(
            "staff_template_form", values=values, item=existing, products=products,
            is_admin=is_admin,
        ), status

    if request.method == "GET":
        content = existing["content"] if existing else {}
        return show({
            "name": existing["name"] if existing else "",
            "product_id": str(existing["product_id"]) if existing else "",
            "price": str(int(existing["price"])) if existing else "0",
            "info": existing["info"] if existing else "",
            "layout": str(content.get("layout", "")), "size": str(content.get("size", "")),
        })

    values = _template_values(request.form)
    errors = _validate_template(values, products)
    upload = request.files.get("image")
    new_image = None
    if not errors and upload is not None and upload.filename:
        try:
            raw = upload.stream.read(_MAX_TEMPLATE_IMAGE_BYTES + 1)
            new_image = store_template_image(raw)
        except StaffError as error:
            errors.append(str(error))
        except OSError:
            current_app.logger.exception("Template image write failed")
            errors.append("Chưa thể lưu ảnh mẫu. Vui lòng thử lại.")
    if errors:
        for error in errors:
            flash(error, "error")
        return show(values, 400)

    content = dict(existing["content"]) if existing else {}
    for key in ("layout", "size"):
        if values[key]:
            content[key] = values[key]
        else:
            content.pop(key, None)
    if existing is None:
        approval = "Approved" if is_admin else "Pending"
    else:
        approval = existing["approval"] if is_admin else "Pending"
    try:
        saved_id = save_template(
            template_id, name=values["name"], product_id=int(values["product_id"]),
            price=int(values["price"]), info=values["info"],
            image_url=new_image or (existing["image_url"] if existing else None),
            content=content, approval=approval,
        )
    except LookupError:
        remove_template_image(new_image)
        abort(404)
    except Exception:
        remove_template_image(new_image)
        current_app.logger.exception("Template save failed")
        flash("Chưa thể lưu mẫu. Vui lòng thử lại sau.", "error")
        return show(values, 503)
    if approval == "Pending":
        flash(f"Đã lưu mẫu #{saved_id}. Mẫu sẽ hiển thị cho khách sau khi quản trị viên duyệt.", "success")
    else:
        flash(f"Đã lưu mẫu #{saved_id}.", "success")
    return redirect(url_for("staff.templates"))


@staff.get("/templates")
@staff_required("templates")
def templates():
    status, q, product_id = _arg("status"), _arg("q"), _int_arg("product")
    if status not in APPROVAL_LABELS:
        status = ""
    try:
        products = product_type_options()
        total = count_staff_templates(status, product_id, q)
        page, pages = _paginate(total)
        items = list_staff_templates(status, product_id, q, page) if total else []
    except Exception:
        return _db_error("Staff template list failed")
    return render_page(
        "staff_templates", items=items, products=products, status=status, product_id=product_id,
        q=q, total=total, page_number=page, pages=pages, is_admin=session.get("role") == "admin",
        args=_clean_args(status=status, product=product_id, q=q), pager_endpoint="staff.templates",
    )


@staff.route("/templates/new", methods=["GET", "POST"])
@staff_required("templates")
def template_new():
    return _template_form(None)


@staff.route("/templates/<int:template_id>/edit", methods=["GET", "POST"])
@staff_required("templates")
def template_edit(template_id: int):
    return _template_form(template_id)


@staff.post("/templates/<int:template_id>/delete")
@staff_required("templates")
def template_delete(template_id: int):
    try:
        delete_template(template_id)
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Template delete failed")
        flash("Chưa thể xóa mẫu. Vui lòng thử lại.", "error")
    else:
        flash("Đã xóa mẫu.", "success")
    return redirect(url_for("staff.templates"))


# ---- admin: template review ----
@admin_bp.post("/templates/<int:template_id>/review")
@role_required("admin")
def template_review(template_id: int):
    try:
        review_template(template_id, request.form.get("decision", ""))
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Template review failed")
        flash("Chưa thể lưu quyết định duyệt. Vui lòng thử lại.", "error")
    else:
        flash("Đã lưu quyết định duyệt mẫu.", "success")
    return redirect(url_for("staff.templates", status="Pending"))


# ---- admin: prices ----
@admin_bp.get("/prices")
@role_required("admin")
def prices():
    product_id, q = _int_arg("product"), _arg("q")
    try:
        products = product_type_options()
        total = count_staff_templates("", product_id, q)
        page, pages = _paginate(total)
        items = list_staff_templates("", product_id, q, page) if total else []
    except Exception:
        return _db_error("Price list failed")
    return render_page(
        "admin_prices", items=items, products=products, product_id=product_id, q=q, total=total,
        page_number=page, pages=pages, args=_clean_args(product=product_id, q=q),
        pager_endpoint="admin.prices",
    )


@admin_bp.post("/prices/<int:template_id>")
@role_required("admin")
def price_update(template_id: int):
    raw = request.form.get("price", "").strip()
    if not raw.isdigit() or int(raw) > 999_999_999_999:
        flash("Giá phải là số nguyên không âm (VNĐ).", "error")
    else:
        try:
            update_template_price(template_id, int(raw))
        except LookupError:
            abort(404)
        except Exception:
            current_app.logger.exception("Price update failed")
            flash("Chưa thể lưu giá. Vui lòng thử lại.", "error")
        else:
            flash(f"Đã cập nhật giá mẫu #{template_id}.", "success")
    return _back(url_for("admin.prices"))


# ---- admin: accounts ----
@admin_bp.get("/accounts")
@role_required("admin")
def accounts():
    role, status, q = _arg("role"), _arg("status"), _arg("q")
    if role not in {"Customer", "Employee", "Admin"}:
        role = ""
    if status not in {"active", "locked"}:
        status = ""
    try:
        total = count_accounts(role, status, q)
        page, pages = _paginate(total)
        items = list_accounts(role, status, q, page) if total else []
    except Exception:
        return _db_error("Account list failed")
    return render_page(
        "admin_accounts", items=items, role=role, status=status, q=q, total=total,
        page_number=page, pages=pages, args=_clean_args(role=role, status=status, q=q),
        pager_endpoint="admin.accounts", me=session["account_id"],
    )


def _account_errors(values: dict[str, str], role: str, creating: bool) -> list[str]:
    errors = []
    if not values["full_name"] or len(values["full_name"]) > 100:
        errors.append("Họ tên là bắt buộc và tối đa 100 ký tự.")
    if len(values["phone"]) > 15:
        errors.append("Số điện thoại tối đa 15 ký tự.")
    if role == "employee" and not values["phone"]:
        errors.append("Số điện thoại là bắt buộc với nhân viên.")
    if len(values["address"]) > (255 if role == "employee" else 300):
        errors.append("Địa chỉ vượt quá độ dài cho phép.")
    if len(values["position"]) > 50:
        errors.append("Chức vụ tối đa 50 ký tự.")
    if creating:
        if not _USERNAME.fullmatch(values["username"]):
            errors.append("Tên đăng nhập cần 3–50 ký tự: chữ không dấu, số, dấu chấm, gạch dưới hoặc gạch ngang.")
        if len(values["email"]) > 100 or not _EMAIL.fullmatch(values["email"]):
            errors.append("Email không hợp lệ hoặc vượt quá 100 ký tự.")
    password = values["password"]
    if creating or password:
        password_error = password_policy_error(password)
        if password_error:
            errors.append(password_error)
    return errors


@admin_bp.route("/accounts/new", methods=["GET", "POST"])
@role_required("admin")
def account_new():
    values = {k: "" for k in ("username", "full_name", "email", "phone", "address", "position", "password")}
    values["role"] = "employee"
    if request.method == "POST":
        for key in values:
            values[key] = request.form.get(key, "") if key == "password" else request.form.get(key, "").strip()
        values["role"] = values["role"].lower()
        values["email"] = values["email"].lower()
        errors = _account_errors(values, values["role"], creating=True)
        if values["role"] not in _VALID_ROLES:
            errors.append("Vai trò không hợp lệ.")
        if errors:
            for error in errors:
                flash(error, "error")
            values["password"] = ""
            return render_page("admin_account_form", values=values, account=None, positions=_STANDARD_POSITIONS), 400
        try:
            created = create_account(
                username=values["username"], email=values["email"], full_name=values["full_name"],
                phone=values["phone"] or None, address=values["address"] or None,
                position=values["position"] or None, password=values["password"], role=values["role"],
            )
        except Exception:
            current_app.logger.exception("Admin account creation failed")
            flash("Chưa thể tạo tài khoản. Vui lòng thử lại sau.", "error")
            values["password"] = ""
            return render_page("admin_account_form", values=values, account=None, positions=_STANDARD_POSITIONS), 503
        if not created:
            flash("Email hoặc tên đăng nhập này đã được sử dụng.", "error")
            values["password"] = ""
            return render_page("admin_account_form", values=values, account=None, positions=_STANDARD_POSITIONS), 409
        flash("Đã tạo tài khoản.", "success")
        return redirect(url_for("admin.accounts"))
    return render_page("admin_account_form", values=values, account=None, positions=_STANDARD_POSITIONS)


@admin_bp.route("/accounts/<int:account_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def account_edit(account_id: int):
    try:
        account = get_account(account_id)
    except Exception:
        return _db_error("Account load failed")
    if account is None:
        abort(404)
    role = account["role"].lower()
    values = {
        "full_name": account["full_name"], "phone": account["phone"], "address": account["address"],
        "position": account["position"], "password": "",
    }
    if request.method == "POST":
        for key in values:
            values[key] = request.form.get(key, "") if key == "password" else request.form.get(key, "").strip()
        errors = _account_errors(values, role, creating=False)
        if errors:
            for error in errors:
                flash(error, "error")
            values["password"] = ""
            return render_page("admin_account_form", values=values, account=account, positions=_STANDARD_POSITIONS), 400
        try:
            update_account(
                account_id, full_name=values["full_name"], phone=values["phone"] or None,
                address=values["address"] or None, position=values["position"] or None,
                new_password=values["password"],
            )
        except LookupError:
            abort(404)
        except Exception:
            current_app.logger.exception("Account update failed")
            flash("Chưa thể lưu tài khoản. Vui lòng thử lại.", "error")
            values["password"] = ""
            return render_page("admin_account_form", values=values, account=account, positions=_STANDARD_POSITIONS), 503
        flash("Đã cập nhật tài khoản.", "success")
        return redirect(url_for("admin.accounts"))
    return render_page("admin_account_form", values=values, account=account, positions=_STANDARD_POSITIONS)


@admin_bp.post("/accounts/<int:account_id>/active")
@role_required("admin")
def account_active(account_id: int):
    active = request.form.get("active") == "1"
    try:
        set_account_active(account_id, active, session["account_id"])
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Account lock toggle failed")
        flash("Chưa thể đổi trạng thái tài khoản. Vui lòng thử lại.", "error")
    else:
        flash("Đã mở khóa tài khoản." if active else "Đã khóa tài khoản.", "success")
    return _back(url_for("admin.accounts"))


@admin_bp.post("/accounts/<int:account_id>/delete")
@role_required("admin")
def account_delete(account_id: int):
    try:
        delete_account(account_id, session["account_id"])
    except LookupError:
        abort(404)
    except StaffError as error:
        flash(str(error), "error")
    except Exception:
        current_app.logger.exception("Account delete failed")
        flash("Chưa thể xóa tài khoản. Hãy khóa tài khoản thay vì xóa.", "error")
    else:
        flash("Đã xóa tài khoản.", "success")
    return redirect(url_for("admin.accounts"))


# ---- admin: reports ----
def _date_arg(name: str) -> date | None:
    try:
        return date.fromisoformat(request.args.get(name, ""))
    except ValueError:
        return None


@admin_bp.get("/stats")
@role_required("admin")
def stats():
    today = date.today()
    year, month = today.year, today.month - 11
    if month < 1:
        year, month = year - 1, month + 12
    start = _date_arg("from") or date(year, month, 1)
    end = _date_arg("to") or today
    if start > end:
        start, end = end, start
    if (end - start).days > 1100:
        start = end - timedelta(days=1100)
    try:
        report = build_report(start, end)
    except Exception:
        return _db_error("Report build failed")
    return render_page("admin_stats", report=report, start=start, end=end)

# --- Application setup ---
csrf = CSRFProtect()

def _as_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}

def create_app() -> Flask:
    load_dotenv()
    secret_key = os.getenv("FLASK_SECRET_KEY", "").strip()
    if len(secret_key) < 32 or secret_key.lower() in {"change-me", "replace-with-random-value", "development"}:
        raise RuntimeError("Set FLASK_SECRET_KEY to a random secret of at least 32 characters in .env.")
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_as_bool("SESSION_COOKIE_SECURE", False),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=6_000_000,
        WTF_CSRF_ENABLED=True,
        EMPLOYEE_REGISTRATION_CODE=os.getenv("EMPLOYEE_REGISTRATION_CODE", "").strip(),
        ADMIN_REGISTRATION_CODE=os.getenv("ADMIN_REGISTRATION_CODE", "").strip(),
    )
    csrf.init_app(app)
    app.jinja_env.globals.update(
        ORDER_STATE_LABELS=ORDER_STATE_LABELS, PAYMENT_LABELS=PAYMENT_LABELS,
        APPROVAL_LABELS=APPROVAL_LABELS, ORDER_STATES=ORDER_STATES,
    )
    app.jinja_env.filters["money"] = lambda value: "{:,.0f} ₫".format(value or 0)
    app.jinja_env.filters["dt"] = lambda value: value.strftime("%d/%m/%Y %H:%M") if hasattr(value, "strftime") else (value or "")
    for blueprint in (auth, catalog, account_bp, designs, cart, orders, staff, admin_bp):
        app.register_blueprint(blueprint)

    @app.get("/")
    def index():
        if session.get("role") == "customer":
            return redirect(url_for("dashboard"))
        if session.get("role") == "employee":
            return redirect(url_for("auth.employee_home"))
        if session.get("role") == "admin":
            return redirect(url_for("auth.admin_home"))
        return redirect(url_for("catalog.index"))

    @app.get("/dashboard")
    @role_required("customer")
    def dashboard():
        return render_page(
            "dashboard",
            customer_name=session.get("customer_name", "Kh\u00e1ch h\u00e0ng"),
            customer_email=session["customer_email"],
        )

    @app.errorhandler(403)
    def forbidden(_error):
        return render_page("error_403"), 403

    return app