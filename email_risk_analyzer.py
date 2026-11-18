
import csv
import argparse
from collections import Counter
from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak
)


# -----------------------------------------
# EMAIL RISK ANALYZER
# Workora Synthetic Training Dataset
# -----------------------------------------

def get_domain(email):
    email = (email or "").strip().lower()
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip(" >")


def analyze_email(row):
    score = 0
    findings = []

    sender = get_domain(row.get("From"))
    reply = get_domain(row.get("ReplyTo"))
    subject = (row.get("Subject") or "").lower()
    spf = (row.get("SPF") or "").lower()
    dkim = (row.get("DKIM") or "").lower()
    attachment = (row.get("HasAttachment") or "").lower()
    link_domain = (row.get("BodyLinkDomain") or "").lower()

    # 1. SPF analysis
    if spf == "fail":
        score += 20
        findings.append("SPF authentication failed")
    elif spf == "softfail":
        score += 12
        findings.append("SPF softfail detected")
    elif spf == "none":
        score += 8
        findings.append("SPF authentication unavailable")
    elif spf == "pass":
        findings.append("SPF passed")

    # 2. DKIM analysis
    if dkim == "fail":
        score += 20
        findings.append("DKIM authentication failed")
    elif dkim == "none":
        score += 8
        findings.append("DKIM authentication unavailable")
    elif dkim == "pass":
        findings.append("DKIM passed")

    # 3. Reply-To mismatch
    if sender and reply and sender != reply:
        score += 25
        findings.append("Reply-To domain differs from sender")

    # 4. Urgent language
    urgent_words = [
        "urgent", "immediately", "suspended",
        "verify", "required", "account review"
    ]

    detected = [word for word in urgent_words if word in subject]

    if detected:
        score += 15
        findings.append(
            "Urgent subject language: " + ", ".join(detected)
        )

    # 5. Attachment presence
    if attachment == "yes":
        score += 12
        findings.append("Email contains an attachment")

    # 6. External or unexpected link domain
    if link_domain and sender and link_domain != sender:
        score += 20
        findings.append(
            "Email link domain differs from sender domain"
        )

    score = min(score, 100)

    if score >= 55:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not findings:
        findings.append("No configured risk indicators detected")

    return {
        "score": score,
        "risk": risk,
        "findings": findings
    }


# -----------------------------------------
# LOAD CSV DATA
# -----------------------------------------

def load_dataset(filename):
    with open(filename, "r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        required = {
            "MessageID", "From", "ReplyTo", "Subject",
            "SPF", "DKIM", "HasAttachment",
            "BodyLinkDomain", "ExpectedLabel", "PrimaryIndicator"
        }

        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(
                "CSV is missing one or more required columns."
            )

        rows = list(reader)

    if not rows:
        raise ValueError("The CSV file contains no email records.")

    return rows


# -----------------------------------------
# PROCESS EMAILS
# -----------------------------------------

def process_dataset(rows):
    results = []

    for row in rows:
        analysis = analyze_email(row)

        results.append({
            "id": row["MessageID"],
            "sender": row["From"],
            "subject": row["Subject"],
            "spf": row["SPF"],
            "dkim": row["DKIM"],
            "indicator": row["PrimaryIndicator"],
            "expected": row["ExpectedLabel"].strip().title(),
            "predicted": analysis["risk"],
            "score": analysis["score"],
            "findings": analysis["findings"]
        })

    return results


# -----------------------------------------
# EVALUATION
# -----------------------------------------

def evaluate_results(results):
    labels = ["Low", "Medium", "High"]

    matrix = {
        expected: {predicted: 0 for predicted in labels}
        for expected in labels
    }

    correct = 0

    for item in results:
        expected = item["expected"]
        predicted = item["predicted"]

        if expected == predicted:
            correct += 1

        if expected in matrix and predicted in matrix[expected]:
            matrix[expected][predicted] += 1

    accuracy = (correct / len(results)) * 100

    return matrix, accuracy, correct


# -----------------------------------------
# PDF REPORT
# -----------------------------------------

def generate_report(results, output_file):

    styles = getSampleStyleSheet()

    doc = SimpleDocTemplate(
        output_file,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    story = []

    total = len(results)

    expected_counts = Counter(x["expected"] for x in results)
    predicted_counts = Counter(x["predicted"] for x in results)
    indicator_counts = Counter(x["indicator"] for x in results)

    matrix, accuracy, correct = evaluate_results(results)

    story.append(Paragraph(
        "EMAIL RISK ANALYZER",
        styles["Title"]
    ))

    story.append(Paragraph(
        "Phishing Detection and Security Audit Report",
        styles["Heading2"]
    ))

    story.append(Paragraph(
        "Dataset: Workora Synthetic Safe Email Training Dataset",
        styles["Normal"]
    ))

    story.append(Paragraph(
        "Generated: " + datetime.now().strftime("%d-%m-%Y %H:%M"),
        styles["Normal"]
    ))

    story.append(Spacer(1, 15))

    # Dataset overview
    story.append(Paragraph(
        "1. Dataset Overview",
        styles["Heading2"]
    ))

    overview = [
        ["Metric", "Result"],
        ["Total Emails Analyzed", str(total)],
        ["Expected Low Risk", str(expected_counts["Low"])],
        ["Expected Medium Risk", str(expected_counts["Medium"])],
        ["Expected High Risk", str(expected_counts["High"])],
        ["Predicted Low Risk", str(predicted_counts["Low"])],
        ["Predicted Medium Risk", str(predicted_counts["Medium"])],
        ["Predicted High Risk", str(predicted_counts["High"])]
    ]

    table = Table(overview, colWidths=[85 * mm, 55 * mm])

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263A5B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    story.append(table)
    story.append(Spacer(1, 15))

    # Indicator analysis
    story.append(Paragraph(
        "2. Primary Threat Indicator Distribution",
        styles["Heading2"]
    ))

    indicator_data = [["Primary Indicator", "Number of Emails"]]

    for indicator, count in indicator_counts.most_common():
        indicator_data.append([indicator, str(count)])

    indicator_table = Table(
        indicator_data,
        colWidths=[100 * mm, 50 * mm]
    )

    indicator_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263A5B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))

    story.append(indicator_table)
    story.append(Spacer(1, 15))

    # Model evaluation
    story.append(Paragraph(
        "3. Classification Evaluation",
        styles["Heading2"]
    ))

    story.append(Paragraph(
        f"Matching classifications: {correct}/{total}",
        styles["Normal"]
    ))

    story.append(Paragraph(
        f"Classification accuracy: {accuracy:.2f}%",
        styles["Normal"]
    ))

    matrix_data = [
        ["Expected / Predicted", "Low", "Medium", "High"]
    ]

    for label in ["Low", "Medium", "High"]:
        matrix_data.append([
            label,
            str(matrix[label]["Low"]),
            str(matrix[label]["Medium"]),
            str(matrix[label]["High"])
        ])

    matrix_table = Table(
        matrix_data,
        colWidths=[65 * mm, 35 * mm, 35 * mm, 35 * mm]
    )

    matrix_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263A5B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7)
    ]))

    story.append(matrix_table)
    story.append(Spacer(1, 15))

    # Findings and limitations
    story.append(Paragraph(
        "4. Security Findings",
        styles["Heading2"]
    ))

    for indicator, count in indicator_counts.most_common():
        story.append(Paragraph(
            f"- {indicator}: {count} record(s)",
            styles["BodyText"]
        ))

    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "5. Recommendations",
        styles["Heading2"]
    ))

    recommendations = [
        "Verify sender and Reply-To domain consistency.",
        "Investigate SPF and DKIM failures.",
        "Exercise caution with urgent account-related messages.",
        "Review attachments before opening them.",
        "Check unexpected link domains using trusted security procedures.",
        "Use multi-factor authentication and security awareness training."
    ]

    for item in recommendations:
        story.append(Paragraph("- " + item, styles["BodyText"]))

    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "6. Methodology and Limitations",
        styles["Heading2"]
    ))

    story.append(Paragraph(
        "This program uses a transparent, rule-based scoring system. "
        "ExpectedLabel is used only for evaluation, not as a scoring input. "
        "PrimaryIndicator is used for dataset statistics, not as a scoring "
        "input. Display-name mismatch cannot be independently verified "
        "because a separate display-name field is not supplied. "
        "The score is a heuristic and does not establish that an email "
        "is malicious or safe. This synthetic dataset is not live email "
        "traffic. All analysis is performed locally.",
        styles["BodyText"]
    ))

    # Detailed record section
    story.append(PageBreak())

    story.append(Paragraph(
        "7. Individual Email Analysis",
        styles["Heading2"]
    ))

    detail_data = [[
        "Message ID", "Expected", "Predicted",
        "Score", "SPF", "DKIM", "Primary Indicator"
    ]]

    for item in results:
        detail_data.append([
            item["id"],
            item["expected"],
            item["predicted"],
            str(item["score"]),
            item["spf"],
            item["dkim"],
            item["indicator"]
        ])

    detail_table = Table(
        detail_data,
        colWidths=[29 * mm, 25 * mm, 25 * mm,
                   16 * mm, 17 * mm, 17 * mm, 75 * mm],
        repeatRows=1
    )

    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263A5B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE")
    ]))

    story.append(detail_table)

    doc.build(story)


# -----------------------------------------
# MAIN PROGRAM
# -----------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Workora Email Risk Analyzer"
    )

    parser.add_argument(
        "csv_file",
        nargs="?",
        default="email_samples.csv",
        help="Input CSV file"
    )

    parser.add_argument(
        "-o", "--output",
        default="Phishing_Analysis_Report.pdf",
        help="Output PDF report"
    )

    args = parser.parse_args()

    try:
        rows = load_dataset(args.csv_file)
        results = process_dataset(rows)

        matrix, accuracy, correct = evaluate_results(results)

        print("\n========== EMAIL RISK ANALYZER ==========")
        print("Emails analyzed:", len(results))
        print("Correct classifications:", correct)
        print(f"Classification accuracy: {accuracy:.2f}%")

        print("\nRisk distribution:")

        for risk in ["Low", "Medium", "High"]:
            count = sum(
                1 for x in results if x["predicted"] == risk
            )
            print(f"{risk}: {count}")

        print("\nIndividual results:")

        for item in results:
            print(
                item["id"],
                "| Score:", item["score"],
                "| Risk:", item["predicted"]
            )

        generate_report(results, args.output)

        print("\nPDF report generated:", args.output)

    except (OSError, ValueError) as error:
        print("Error:", error)


if __name__ == "__main__":
    main()
