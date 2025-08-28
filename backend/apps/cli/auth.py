import argparse
from auth.session import SessionManager
from auth.strategies.form_login import FormLogin
from auth.strategies.token_bearer import TokenBearer

def parse_args():
    parser = argparse.ArgumentParser(
        description="Authentication CLI for web app scanning system"
    )
    parser.add_argument(
        "action",
        type=str,
        choices=["login", "validate_token", "logout"],
        help="Action to perform: login, validate_token, or logout"
    )
    parser.add_argument(
        "--url",
        type=str,
        help="Target login URL for form-based authentication"
    )
    parser.add_argument(
        "--username",
        type=str,
        help="Username for login"
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password for login"
    )
    parser.add_argument(
        "--token",
        type=str,
        help="Bearer token for validation"
    )
    parser.add_argument(
        "--strategy",
        type=str,
        default="form",
        choices=["form", "token"],
        help="Authentication strategy to use"
    )
    return parser.parse_args()

def main():
    args = parse_args()
    
    session_mgr = SessionManager()
    
    if args.action == "login":
        if args.strategy == "form":
            if not all([args.url, args.username, args.password]):
                print("[!] URL, username, and password are required for form login")
                return
            auth = FormLogin(url=args.url, username=args.username, password=args.password)
            success, cookies = auth.perform_login()
            if success:
                print(f"[+] Login successful. Session cookies: {cookies}")
                session_mgr.save_session(args.url, cookies)
            else:
                print("[!] Login failed.")
        elif args.strategy == "token":
            if not args.token:
                print("[!] Token is required for token-based auth")
                return
            auth = TokenBearer(token=args.token)
            valid = auth.validate_token()
            print(f"[+] Token valid: {valid}")
    
    elif args.action == "validate_token":
        if not args.token:
            print("[!] Token is required")
            return
        auth = TokenBearer(token=args.token)
        valid = auth.validate_token()
        print(f"[+] Token valid: {valid}")
    
    elif args.action == "logout":
        if not args.url:
            print("[!] URL is required to clear session")
            return
        session_mgr.clear_session(args.url)
        print(f"[+] Session cleared for {args.url}")

if __name__ == "__main__":
    main()
