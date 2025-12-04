from __future__ import annotations

import random
import string

from dataclasses import dataclass


@dataclass
class PasswordGenerator:
    """Generate random passwords based on configurable rules."""

    length: int = 12
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_special: bool = False

    def generate_password(self) -> str:
        """
        Return a randomly generated password.

        Raises:
            ValueError: If no character sets are enabled.
        """
        characters = ''

        if self.use_upper:
            characters += string.ascii_uppercase
        if self.use_lower:
            characters += string.ascii_lowercase
        if self.use_digits:
            characters += string.digits
        if self.use_special:
            characters += '!@#$%^&*()-_=+[]{};:,.?/'

        if not characters:
            msg = 'At least one character set must be enabled.'
            raise ValueError(msg)

        rng = random.SystemRandom()
        return ''.join(rng.choice(characters) for _ in range(self.length))
