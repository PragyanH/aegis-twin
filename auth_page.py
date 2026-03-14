"""auth_page.py — Login / registration screen."""

import streamlit as st
from auth import create_user, has_users, verify_user


def render_login_page() -> None:
    """Render login/register form. Calls st.stop() if not authenticated."""
    email = st.text_input("Email", value=st.session_state.get("login_email", ""), placeholder="you@example.com")
    pw_type = "default" if st.session_state.password_visible else "password"
    password = st.text_input("Password", type=pw_type)
    st.session_state.password_visible = st.checkbox("Show password", value=st.session_state.password_visible)

    is_register = st.session_state.register_mode
    if not is_register and not has_users():
        st.info("No users exist yet. This will create the first admin account.")
    elif is_register:
        st.info("Create a new account. Passwords are stored securely.")

    confirm_password = st.text_input("Confirm Password", type=pw_type) if is_register else None

    if st.button("Create account" if is_register else "Sign in"):
        st.session_state.login_email = email
        if not email:
            st.session_state.login_error = "Email is required."
        elif is_register:
            if not password or not confirm_password:
                st.session_state.login_error = "Password and confirmation are required."
            elif password != confirm_password:
                st.session_state.login_error = "Passwords do not match."
            else:
                try:
                    create_user(email, password)
                    _set_authenticated(email)
                    st.rerun()
                except Exception as exc:
                    st.session_state.login_error = str(exc)
        else:
            if verify_user(email, password):
                _set_authenticated(email)
                st.rerun()
            else:
                st.session_state.login_error = "Invalid email or password."

    if st.session_state.login_error:
        st.error(st.session_state.login_error)

    toggle_label = "Already have an account? Sign in" if is_register else "Don't have an account? Register"
    if st.button(toggle_label):
        st.session_state.register_mode = not is_register
        st.session_state.login_error = None
        st.rerun()

    if not st.session_state.authenticated:
        st.stop()


def _set_authenticated(email: str):
    st.session_state.authenticated = True
    st.session_state.user_email = email.strip().lower()
    st.session_state.page = "fleet"
    st.session_state.login_error = None
    st.success("Login successful." if not st.session_state.register_mode else "Account created.")