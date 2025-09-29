# apps/cli/auth.py
import click
from services.auth_service import AuthService
from backend.core.firebase import firebase_admin, auth as firebase_auth

auth_service = AuthService()


@click.group()
def cli():
    """Authentication CLI for Firebase-backed scanner backend"""
    pass


# -------------------------------
# Register a new user
# -------------------------------
@cli.command()
@click.argument("email")
@click.argument("password")
def register(email, password):
    """Register a new user in Firebase"""
    try:
        result = auth_service.register_user(email, password)
        click.echo(f"✅ User registered: {result['email']} (UID: {result['uid']})")
    except Exception as e:
        click.echo(f"❌ Registration failed: {str(e)}")


# -------------------------------
# Login (verify ID token)
# -------------------------------
@cli.command()
@click.argument("id_token")
def login(id_token):
    """Login using a Firebase ID token"""
    try:
        user = auth_service.authenticate(id_token)
        click.echo(f"✅ Login successful for {user['user']['email']}")
        click.echo(f"User UID: {user['user']['uid']}")
        click.echo(f"Role: {user['user'].get('role', 'user')}")
    except Exception as e:
        click.echo(f"❌ Login failed: {str(e)}")


# -------------------------------
# CLI entry point
# -------------------------------
if __name__ == "__main__":
    cli()
