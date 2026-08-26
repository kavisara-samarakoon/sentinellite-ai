from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ReportingConfig:
    """JSON reporting settings."""

    output_dir: Path = Path("reports")
    include_explanations: bool = False


@dataclass(frozen=True)
class ModulesConfig:
    """Scan-module enablement settings."""

    authentication: bool = True
    process: bool = True
    network: bool = True
    file_integrity: bool = True


@dataclass(frozen=True)
class RulesConfig:
    """Detection-rule control settings."""

    disabled_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class SentinelLiteConfig:
    """Validated SentinelLite configuration."""

    config_version: int = 1
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    rules: RulesConfig = field(default_factory=RulesConfig)
