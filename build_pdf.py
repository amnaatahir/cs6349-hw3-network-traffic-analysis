#!/usr/bin/env python3
"""Render a Markdown report to a styled PDF with headless Chromium.
usage: build_pdf.py report.md out.pdf
Images are referenced relative to the markdown file's folder."""
import sys, pathlib, markdown, asyncio
from playwright.async_api import async_playwright

CSS = """
@page { size: Letter; margin: 0.7in 0.75in 0.8in 0.75in; }
body { font-family: 'DejaVu Sans', Arial, sans-serif; font-size: 10.3pt; line-height: 1.45; color: #1b1b1b; }
h1 { font-size: 18pt; margin: 0 0 2px 0; color: #0b3d63; }
.sub { color: #555; font-size: 9.5pt; margin-bottom: 14px; border-bottom: 2px solid #0b3d63; padding-bottom: 8px; }
h2 { font-size: 13pt; color: #0b3d63; border-bottom: 1px solid #c9d6e2; padding-bottom: 2px; margin-top: 18px; }
h3 { font-size: 11pt; margin: 12px 0 4px 0; color: #222; }
code { font-family: 'DejaVu Sans Mono', monospace; font-size: 8.6pt; background: #f2f4f7; padding: 0 3px; border-radius: 3px; }
pre { background: #f5f7fa; border: 1px solid #dde3ea; border-left: 3px solid #0b3d63; padding: 7px 9px; font-size: 8pt;
      line-height: 1.35; white-space: pre-wrap; word-break: break-all; page-break-inside: avoid; }
pre code { background: none; padding: 0; font-size: 8pt; }
table { border-collapse: collapse; width: 100%; margin: 6px 0 10px 0; font-size: 8.8pt; page-break-inside: avoid; }
th, td { border: 1px solid #cfd8e3; padding: 3px 6px; text-align: left; vertical-align: top; }
th { background: #e8eff6; }
img { max-width: 100%; border: 1px solid #b8c4d0; margin: 4px 0 2px 0; page-break-inside: avoid; }
p.cap, .cap { font-size: 8.6pt; color: #555; font-style: italic; margin-top: 0; }
.ans { background: #f3f9f3; border-left: 3px solid #3b8a3b; padding: 4px 9px; margin: 4px 0 8px 0; }
blockquote { margin: 6px 0; padding: 4px 10px; border-left: 3px solid #c58b00; background: #fff9ec; }
.pb { page-break-before: always; }
"""

def main(md_path, pdf_path):
    md_path = pathlib.Path(md_path).resolve()
    html_body = markdown.markdown(md_path.read_text(), extensions=["tables", "fenced_code", "md_in_html", "attr_list"])
    html = f"<!doctype html><html><head><meta charset='utf-8'><base href='{md_path.parent.as_uri()}/'><style>{CSS}</style></head><body>{html_body}</body></html>"
    tmp = md_path.with_suffix(".html"); tmp.write_text(html)
    async def run():
        async with async_playwright() as p:
            b = await p.chromium.launch()
            pg = await b.new_page()
            await pg.goto(tmp.as_uri()); await pg.wait_for_load_state("networkidle")
            await pg.pdf(path=pdf_path, format="Letter", print_background=True,
                         display_header_footer=True, header_template="<span></span>",
                         footer_template="<div style='font-size:7.5pt;color:#777;width:100%;text-align:center'>CS 6349 Homework 3 &middot; page <span class='pageNumber'></span> of <span class='totalPages'></span></div>",
                         margin={"top": "0.6in", "bottom": "0.7in", "left": "0.7in", "right": "0.7in"})
            await b.close()
    asyncio.run(run())
    tmp.unlink()
    print("wrote", pdf_path)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
