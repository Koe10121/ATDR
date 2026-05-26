from pathlib import Path
from playwright.sync_api import sync_playwright
import argparse


def render(input_path: str, output_path: str, print_mode: bool = False) -> None:
    p = Path(input_path).resolve()
    if not p.exists():
        raise SystemExit(f"Input file not found: {p}")
    uri = p.as_uri()
    if print_mode:
        # Append the Reveal.js print query for full-slide PDF export
        uri = uri + ("?print-pdf" if "?" not in uri else "&print-pdf")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(uri, wait_until="networkidle")
        try:
            page.emulate_media(media="print")
        except Exception:
            pass
        page.pdf(path=output_path, format="A4", print_background=True)
        browser.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Render HTML to PDF using Playwright Chromium")
    parser.add_argument("input", help="Input HTML file path")
    parser.add_argument("output", help="Output PDF path")
    parser.add_argument("--print", action="store_true", help="Enable print styles (Reveal.js print-pdf)")
    args = parser.parse_args()
    render(args.input, args.output, print_mode=args.print)
    print(f"Wrote {args.output}")
