import secrets
import string

SPECIAL_CHARS = '!@#$%^&*()_'


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS
    lower_set = set(string.ascii_lowercase)
    upper_set = set(string.ascii_uppercase)
    digits_set = set(string.digits)
    special_set = set(SPECIAL_CHARS)
    while True:
        password = [secrets.choice(alphabet) for _ in range(length)]
        password_set = set(password)
        if (
            upper_set.intersection(password_set)
            and lower_set.intersection(password_set)
            and special_set.intersection(password_set)
            and digits_set.intersection(password_set)
        ):
            return ''.join(password)
