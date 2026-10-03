from database import SessionLocal
from models import Scan, Finding
from services.report import generate_security_report
from services.comparison import compare_scans


SCAN_ID = 20
OUTPUT_FILE = "securecheck_report.pdf"


db = SessionLocal()

try:

    # -------------------------------------------------
    # Current scan
    # -------------------------------------------------

    scan = (
        db.query(Scan)
        .filter(Scan.id == SCAN_ID)
        .first()
    )

    if scan is None:
        raise Exception(
            f"Scan {SCAN_ID} not found"
        )

    # -------------------------------------------------
    # Findings
    # -------------------------------------------------

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan.id
        )
        .all()
    )

    # -------------------------------------------------
    # Previous scan
    # -------------------------------------------------

    previous_scan = (
        db.query(Scan)
        .filter(
            Scan.domain == scan.domain,
            Scan.id < scan.id
        )
        .order_by(
            Scan.id.desc()
        )
        .first()
    )

    # -------------------------------------------------
    # Detailed comparison
    # -------------------------------------------------

    comparison = compare_scans(
        db,
        scan.id
    )

    # -------------------------------------------------
    # Generate PDF
    # -------------------------------------------------

    generate_security_report(
        scan=scan,
        findings=findings,
        output_path=OUTPUT_FILE,
        previous_scan=previous_scan,
        comparison=comparison,
    )

    print(
        "PDF generated successfully!"
    )

    print(
        f"File: {OUTPUT_FILE}"
    )

    if previous_scan:
        print(
            f"Previous scan: #{previous_scan.id}"
        )
    else:
        print(
            "No previous scan available."
        )

finally:

    db.close()