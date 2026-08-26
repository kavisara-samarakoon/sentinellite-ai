from pathlib import Path

from sentinellite.config.loader import ConfigError

DEFAULT_CONFIG_TEMPLATE = """config_version = 1

[reporting]
output_dir = "reports"
include_explanations = false

[modules]
authentication = true
process = true
network = true
file_integrity = true

[rules]
disabled_ids = []
"""


def write_default_config(path: str | Path) -> Path:
    """Create a default TOML config without overwriting or creating directories."""
    output_path = Path(path)
    try:
        with output_path.open("x", encoding="utf-8") as file:
            file.write(DEFAULT_CONFIG_TEMPLATE)
    except FileExistsError as error:
        raise ConfigError(f"Config file already exists: {output_path}") from error
    except FileNotFoundError as error:
        raise ConfigError(
            f"Config parent directory does not exist: {output_path.parent}"
        ) from error
    except OSError as error:
        raise ConfigError(f"Could not write config file '{output_path}': {error}") from error

    return output_path
