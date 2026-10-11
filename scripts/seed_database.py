"""Rebuild the SQLite database and the evaluation manifest from the fixed seed."""

from pathlib import Path

from security_investigator.config import get_settings
from security_investigator.generator import write_company_files


def main() -> None:
    settings = get_settings()
    company = write_company_files(
        Path(settings.database_path),
        Path("data/scenarios/manifest.json"),
        seed=settings.random_seed,
        reference_time=settings.reference_time,
    )
    counts = company.manifest["counts"]
    print(
        f"wrote {settings.database_path} "
        f"({counts['logs']} logs, {counts['alerts']} alerts, {counts['incidents']} incidents)"
    )


if __name__ == "__main__":
    main()
