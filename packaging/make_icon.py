"""Build-time helper: convert the source PNG into a multi-size Windows icon."""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent
SIZES = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def main() -> None:
    source = ROOT / "aegis-icon.png"
    target = ROOT / "aegis.ico"
    image = Image.open(source).convert("RGBA")
    image.save(target, format="ICO", sizes=SIZES)
    print(f"wrote {target} ({target.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
