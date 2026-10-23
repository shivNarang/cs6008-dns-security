#!/bin/sh
# Build report.pdf from report.md (uses a pandoc+latex container; no host TeX needed).
cd "$(dirname "$0")"
docker run --rm --platform linux/amd64 -v "$(pwd)":/data -w /data pandoc/latex:latest \
    report.md -o report.pdf --pdf-engine=xelatex -V geometry:margin=2.2cm -V colorlinks \
    --listings -H report-header.tex
echo "report.pdf built."
