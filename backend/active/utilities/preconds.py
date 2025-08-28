from typing import Callable, Any

class Preconditions:
    """
    Provides utility functions to assert preconditions before
    performing scans or operations.
    """

    @staticmethod
    def require_not_none(value: Any, message: str = "Value cannot be None"):
        if value is None:
            raise ValueError(message)

    @staticmethod
    def require_callable(func: Any, message: str = "Value must be callable"):
        if not callable(func):
            raise TypeError(message)

    @staticmethod
    def require_positive(value: int, message: str = "Value must be positive"):
        if value <= 0:
            raise ValueError(message)

    @staticmethod
    def require_in(value: Any, valid_list: list, message: str = None):
        if value not in valid_list:
            raise ValueError(message or f"{value} not in allowed list: {valid_list}")
