import os
import json

def load_settings(path: str = "config/settings.json"):
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    # Replace ${VAR} placeholders with env values
    resolved = {}
    for key, value in raw.items():
        if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
            env_var = value.strip("${}")
            resolved[key] = os.getenv(env_var, f"changeme-{env_var.lower()}")
        else:
            resolved[key] = value

    return resolved

# Example usage:
# settings = load_settings()
# print(settings["jwt_secret"])
