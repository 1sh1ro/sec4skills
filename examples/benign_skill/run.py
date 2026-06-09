from pathlib import Path


def format_table(path: str) -> str:
    text = Path(path).read_text(encoding="utf-8")
    rows = [line.split(",") for line in text.splitlines() if line.strip()]
    return "\n".join("| " + " | ".join(cell.strip() for cell in row) + " |" for row in rows)
