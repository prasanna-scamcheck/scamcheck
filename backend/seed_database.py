"""
Seed the ScamCheck database with initial intelligence data.
Run: python seed_database.py
"""
from datetime import datetime, timedelta
from models import create_tables, SessionLocal, Indicator, Report, indicator_links
from risk_engine import normalize_indicator, calculate_risk_score


def days_ago(n):
    return datetime.utcnow() - timedelta(days=n)


def seed():
    create_tables()
    db = SessionLocal()

    # Check if already seeded
    if db.query(Indicator).count() > 0:
        print("Database already seeded. Skipping.")
        db.close()
        return

    print("Seeding intelligence database...")

    # ── INDICATORS ──
    indicators = [
        Indicator(
            ref_id="IND-0001", type="phone", value="+91 98765 43210",
            normalized_value=normalize_indicator("+91 98765 43210"),
            risk_score=87, complaint_count=24, category="Investment Fraud",
            location="Mumbai, Maharashtra", status="confirmed",
            notes="Linked to fake trading platform 'QuickProfit'. Calls victims claiming guaranteed 300% returns. Uses WhatsApp for follow-ups.",
            first_seen=days_ago(180), last_seen=days_ago(2),
        ),
        Indicator(
            ref_id="IND-0002", type="upi", value="investhelp@okaxis",
            normalized_value=normalize_indicator("investhelp@okaxis"),
            risk_score=92, complaint_count=31, category="Investment Fraud",
            location="Mumbai, Maharashtra", status="confirmed",
            notes="Primary collection UPI for QuickProfit scam ring. High volume transactions reported. Funds moved within 30 minutes of receipt.",
            first_seen=days_ago(160), last_seen=days_ago(1),
        ),
        Indicator(
            ref_id="IND-0003", type="domain", value="quickprofit-invest.in",
            normalized_value=normalize_indicator("quickprofit-invest.in"),
            risk_score=95, complaint_count=18, category="Investment Fraud",
            location="Unknown", status="confirmed",
            notes="Fraudulent investment portal. SSL certificate mismatch. Domain registered 6 months ago via GoDaddy. Fake SEBI registration displayed.",
            first_seen=days_ago(170), last_seen=days_ago(5),
        ),
        Indicator(
            ref_id="IND-0004", type="phone", value="+91 87654 32109",
            normalized_value=normalize_indicator("+91 87654 32109"),
            risk_score=63, complaint_count=8, category="KYC Fraud",
            location="Delhi", status="active",
            notes="Calls pretending to be SBI/RBI officer. Asks for Aadhaar, PAN, and bank details. Threatens account freeze.",
            first_seen=days_ago(90), last_seen=days_ago(10),
        ),
        Indicator(
            ref_id="IND-0005", type="email", value="sbi.kyc.update@gmail.com",
            normalized_value=normalize_indicator("sbi.kyc.update@gmail.com"),
            risk_score=78, complaint_count=14, category="KYC Fraud",
            location="Delhi", status="active",
            notes="Sends phishing emails mimicking SBI KYC renewal. Links to credential harvesting page hosted on free subdomain.",
            first_seen=days_ago(85), last_seen=days_ago(7),
        ),
        Indicator(
            ref_id="IND-0006", type="upi", value="fastloan247@ybl",
            normalized_value=normalize_indicator("fastloan247@ybl"),
            risk_score=71, complaint_count=11, category="Loan Scam",
            location="Bengaluru, Karnataka", status="active",
            notes="Collects 'processing fees' for fake instant loans. No loan ever disbursed. Operates via WhatsApp Business.",
            first_seen=days_ago(120), last_seen=days_ago(3),
        ),
        Indicator(
            ref_id="IND-0007", type="phone", value="+91 76543 21098",
            normalized_value=normalize_indicator("+91 76543 21098"),
            risk_score=55, complaint_count=6, category="Loan Scam",
            location="Bengaluru, Karnataka", status="active",
            notes="WhatsApp-based loan scam. Sends fake approval letters with forged bank letterheads.",
            first_seen=days_ago(100), last_seen=days_ago(15),
        ),
        Indicator(
            ref_id="IND-0008", type="bank_account", value="AXIS004017012345678",
            normalized_value=normalize_indicator("AXIS004017012345678"),
            risk_score=88, complaint_count=19, category="Investment Fraud",
            location="Pune, Maharashtra", status="confirmed",
            notes="Mule account used to layer funds from QuickProfit investment scam. Account holder may be a money mule.",
            first_seen=days_ago(150), last_seen=days_ago(4),
        ),
        Indicator(
            ref_id="IND-0009", type="phone", value="+91 65432 10987",
            normalized_value=normalize_indicator("+91 65432 10987"),
            risk_score=42, complaint_count=3, category="Tech Support Scam",
            location="Hyderabad, Telangana", status="unverified",
            notes="Claims to be Microsoft support. Requests AnyDesk/TeamViewer access. Reports from Hyderabad area.",
            first_seen=days_ago(45), last_seen=days_ago(20),
        ),
        Indicator(
            ref_id="IND-0010", type="domain", value="govt-subsidy-apply.com",
            normalized_value=normalize_indicator("govt-subsidy-apply.com"),
            risk_score=81, complaint_count=22, category="Phishing",
            location="Unknown", status="confirmed",
            notes="Fake government subsidy portal. Harvests Aadhaar and bank details. Mimics PM-KISAN interface.",
            first_seen=days_ago(60), last_seen=days_ago(1),
        ),
        Indicator(
            ref_id="IND-0011", type="upi", value="govthelp2024@paytm",
            normalized_value=normalize_indicator("govthelp2024@paytm"),
            risk_score=74, complaint_count=9, category="Phishing",
            location="Lucknow, Uttar Pradesh", status="active",
            notes="Collects 'registration fees' for fake government subsidy scheme. Linked to govt-subsidy-apply.com.",
            first_seen=days_ago(55), last_seen=days_ago(8),
        ),
        Indicator(
            ref_id="IND-0012", type="wallet", value="0x7a3B8c9D2e1F...9f2E",
            normalized_value=normalize_indicator("0x7a3B8c9D2e1F...9f2E"),
            risk_score=68, complaint_count=5, category="Crypto Scam",
            location="Unknown", status="active",
            notes="Receives BTC/ETH from victims of Telegram crypto doubling scam. 'Send 1 ETH get 2 back' scheme.",
            first_seen=days_ago(30), last_seen=days_ago(12),
        ),
        Indicator(
            ref_id="IND-0013", type="email", value="hr.tcs.careers@outlook.com",
            normalized_value=normalize_indicator("hr.tcs.careers@outlook.com"),
            risk_score=76, complaint_count=16, category="Job Scam",
            location="Chennai, Tamil Nadu", status="confirmed",
            notes="Fake TCS recruitment emails. Charges 'joining deposit' of Rs 5000-15000. Uses forged offer letters with fake HR signatures.",
            first_seen=days_ago(200), last_seen=days_ago(6),
        ),
        Indicator(
            ref_id="IND-0014", type="phone", value="+91 54321 09876",
            normalized_value=normalize_indicator("+91 54321 09876"),
            risk_score=61, complaint_count=7, category="Job Scam",
            location="Chennai, Tamil Nadu", status="active",
            notes="Follow-up calls after fake job offer emails. Pressures victims to pay 'security deposit' urgently.",
            first_seen=days_ago(190), last_seen=days_ago(9),
        ),
        Indicator(
            ref_id="IND-0015", type="upi", value="electromart.deals@axl",
            normalized_value=normalize_indicator("electromart.deals@axl"),
            risk_score=58, complaint_count=4, category="Fake E-commerce",
            location="Jaipur, Rajasthan", status="unverified",
            notes="Fake Instagram electronics store. Advertises iPhones at 50% off. Collects payment, never delivers. Blocks buyers.",
            first_seen=days_ago(25), last_seen=days_ago(11),
        ),
    ]

    db.add_all(indicators)
    db.flush()

    # ── LINK INDICATORS ──
    # QuickProfit scam ring
    link_pairs = [
        ("IND-0001", "IND-0002"), ("IND-0001", "IND-0003"), ("IND-0002", "IND-0003"),
        ("IND-0002", "IND-0008"), ("IND-0001", "IND-0008"),
        # KYC fraud pair
        ("IND-0004", "IND-0005"),
        # Loan scam pair
        ("IND-0006", "IND-0007"),
        # Govt phishing pair
        ("IND-0010", "IND-0011"),
        # Job scam pair
        ("IND-0013", "IND-0014"),
    ]

    ind_map = {ind.ref_id: ind for ind in indicators}
    for ref_a, ref_b in link_pairs:
        a, b = ind_map.get(ref_a), ind_map.get(ref_b)
        if a and b:
            a.linked_indicators.append(b)

    # ── SEED PENDING REPORTS ──
    reports = [
        Report(
            ref_id="RPT-0001", indicator_value="+91 99887 76655", indicator_type="phone",
            category="OTP Fraud", description="Received call claiming my parcel is stuck at customs. Asked for OTP to release it. Called from this number twice.",
            city="Nagpur", state="Maharashtra", status="pending",
            submitted_at=days_ago(1),
        ),
        Report(
            ref_id="RPT-0002", indicator_value="cheapphones@paytm", indicator_type="upi",
            category="Fake E-commerce", description="Paid Rs 12000 for iPhone on Instagram deal page. Seller blocked me after payment. UPI ID was this one.",
            city="Pune", state="Maharashtra", status="pending",
            submitted_at=days_ago(2),
        ),
        Report(
            ref_id="RPT-0003", indicator_value="amazon-refund-help.in", indicator_type="domain",
            category="Phishing", description="Website looks exactly like Amazon India. Claimed I have a refund pending. Asked for full card details including CVV.",
            city="Delhi", state="Delhi", status="pending",
            submitted_at=days_ago(0),
        ),
    ]
    db.add_all(reports)

    db.commit()
    db.close()

    print(f"Seeded {len(indicators)} indicators, {len(link_pairs)} links, {len(reports)} pending reports.")
    print("Database ready.")


if __name__ == "__main__":
    seed()
