import pyotp

class MFA_TOTP:
    def __init__(self, secret: str):
        self.totp = pyotp.TOTP(secret)

    def generate_code(self) -> str:
        return self.totp.now()
