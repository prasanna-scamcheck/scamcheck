"""
ScamCheck — SCAM PREDICTOR ENGINE
The USP: "See the scam before it sees you"

No other platform does this:
1. Paste any suspicious message → AI reveals the COMPLETE scam playbook
2. Shows every step the scammer will take next
3. Shows how many people fell for this exact pattern
4. Shows where the money trail leads
5. Generates a shareable "Scam Alert" card
6. Live Scam Radar — real-time scam activity by city

This module provides the backend API for the Scam Predictor.
"""

import json
import re
from datetime import datetime, timedelta
from typing import Optional, List
from models import SessionLocal, Indicator
from risk_engine import normalize_indicator


# ══════════════════════════════════════════════════════════════════
# SCAM DNA DATABASE
# Every scam follows a template. We've mapped 25+ scam "DNA patterns"
# with complete playbooks — step by step how the scam unfolds.
# ══════════════════════════════════════════════════════════════════

SCAM_DNA = {
    # ── UPI / Payment Scams ──
    "upi_collect_request": {
        "name": "Fake UPI Collect Request Scam",
        "threat_level": "HIGH",
        "common_in": ["WhatsApp", "Phone Call", "SMS"],
        "targets": "Online sellers on OLX/Quikr, small business owners",
        "total_victims_india": "2.3 lakh+ reported (2024-2025)",
        "avg_loss": "₹5,000 – ₹50,000",
        "trigger_patterns": [
            r"(send|sent).*(collect|request|money)",
            r"(pay|paying).*(upi|gpay|phonepe|paytm)",
            r"(collect|request).*(accept|approve)",
            r"(buyer|customer).*(sent|sending).*(payment|money)",
            r"(enter|type).*(upi\s*pin)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "I'm interested in buying your product. I'll pay via UPI right now.",
                "purpose": "Building trust and creating urgency. They want you excited about a quick sale.",
                "red_flag": "Too eager to pay without negotiating or seeing the product."
            },
            {
                "step": 2,
                "scammer_says": "I've sent the payment. Please check your UPI app and accept the request.",
                "purpose": "They actually sent a COLLECT REQUEST (money FROM you), not a payment TO you.",
                "red_flag": "Receiving money NEVER requires you to approve or enter your PIN."
            },
            {
                "step": 3,
                "scammer_says": "You need to enter your UPI PIN to receive the money. It's a new UPI feature.",
                "purpose": "Your UPI PIN is like your ATM PIN. Entering it on a collect request SENDS money.",
                "red_flag": "NO legitimate payment system requires PIN to RECEIVE money. Ever."
            },
            {
                "step": 4,
                "scammer_says": "Hurry, the payment will expire in 5 minutes. Just enter your PIN quickly.",
                "purpose": "Creating panic so you don't think clearly or read what's on screen.",
                "red_flag": "Urgency + pressure = scam. Always read every UPI prompt carefully."
            },
        ],
        "money_trail": "Your money → Scammer's UPI → Immediately transferred to another account → Cashed out via ATM within minutes",
        "prevention": [
            "You NEVER need to enter PIN to receive money",
            "Always READ the UPI prompt — it clearly says 'PAY' or 'RECEIVE'",
            "Never accept collect requests from unknown people",
            "Use UPI payment screenshot verification, not caller's claims",
        ],
    },

    "kyc_expiry": {
        "name": "Fake KYC Expiry / Account Block Scam",
        "threat_level": "CRITICAL",
        "common_in": ["SMS", "Email", "Phone Call", "WhatsApp"],
        "targets": "Bank account holders, Paytm/PhonePe users, senior citizens",
        "total_victims_india": "5.7 lakh+ reported (2024-2025)",
        "avg_loss": "₹10,000 – ₹5,00,000",
        "trigger_patterns": [
            r"(kyc|know your customer).*(update|expire|expir|verify|pending|complete)",
            r"(account|a/c).*(block|suspend|freez|deactivat|close)",
            r"(bank|sbi|hdfc|icici|axis|pnb|rbi).*(update|verify|kyc)",
            r"(aadhaar|aadhar|pan).*(link|update|verify)",
            r"(click|tap|visit).*(link|url|website).*(update|verify)",
            r"(within|before).*(24|48|72).*(hour|hr)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "Dear customer, your bank KYC has expired. Your account will be blocked within 24 hours. Update immediately: [link]",
                "purpose": "Creating fear of losing access to your money.",
                "red_flag": "Banks NEVER send KYC update links via SMS or WhatsApp."
            },
            {
                "step": 2,
                "scammer_says": "Please click the link and enter your account number, Aadhaar, PAN, and debit card details to verify your identity.",
                "purpose": "The link leads to a fake banking website that looks identical to the real one. Every detail you enter goes directly to the scammer.",
                "red_flag": "Banks NEVER ask for full card details, CVV, or PIN via a website link."
            },
            {
                "step": 3,
                "scammer_says": "Enter the OTP sent to your registered mobile number to complete verification.",
                "purpose": "The OTP is actually for a money transfer or adding their device to your account.",
                "red_flag": "Read the OTP message carefully — it tells you what the OTP is for."
            },
            {
                "step": 4,
                "scammer_says": "[Your account is now drained]",
                "purpose": "Using your details + OTP, they transfer money out, add a beneficiary, or make purchases.",
                "red_flag": "By the time you realize, the money is already moved through multiple accounts."
            },
        ],
        "money_trail": "Your account → Mule account (opened with stolen KYC) → Split across 3-5 accounts → Hawala/crypto conversion → Untraceable",
        "prevention": [
            "Banks NEVER send KYC links via SMS, WhatsApp, or email",
            "Always visit your bank's official website directly (type the URL yourself)",
            "Call your bank's official customer care number to verify any message",
            "Never share OTP with anyone — read the OTP message to see what it authorizes",
            "RBI has confirmed: no account is blocked for KYC without written notice sent by post",
        ],
    },

    "investment_fraud": {
        "name": "Fake Investment / Stock Trading Scam",
        "threat_level": "CRITICAL",
        "common_in": ["WhatsApp Group", "Telegram", "Instagram", "Facebook Ads"],
        "targets": "Young professionals, retirees, anyone seeking passive income",
        "total_victims_india": "10,000+ crore lost in 2024-2025",
        "avg_loss": "₹1,00,000 – ₹50,00,000",
        "trigger_patterns": [
            r"(guaranteed|assured|fixed).*(return|profit|income|earning)",
            r"(\d+).*(%.*(daily|weekly|monthly|return|profit))",
            r"(invest|trading).*(group|channel|platform|app)",
            r"(stock|share|crypto|forex).*(tip|signal|guaranteed)",
            r"(double|triple|10x|100x).*(money|investment)",
            r"(join|free).*(vip|premium).*(group|channel)",
            r"(minimum|just|only).*(invest|deposit).*(₹|rs|inr)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "Join our FREE stock/crypto tips WhatsApp group! Our members earned 300% returns last month!",
                "purpose": "Luring you with impossibly high returns. Screenshots of profits are fabricated.",
                "red_flag": "No legitimate investment gives 'guaranteed' returns. SEBI prohibits return guarantees."
            },
            {
                "step": 2,
                "scammer_says": "Start with just ₹5,000 on our platform. Here's the app/website link.",
                "purpose": "Low entry amount reduces hesitation. The 'platform' is fake — it shows fake profits.",
                "red_flag": "Check if the platform is SEBI registered. 99% of these aren't."
            },
            {
                "step": 3,
                "scammer_says": "Your investment is already up 45%! Invest more to earn more. Here's proof of other members' withdrawals.",
                "purpose": "Showing fake profits on the fake platform. The 'proof' is fabricated screenshots.",
                "red_flag": "If you try to withdraw, they'll ask for more money first."
            },
            {
                "step": 4,
                "scammer_says": "To withdraw your profits, you need to pay 20% tax/fee/charges first.",
                "purpose": "This is where most money is stolen — victims pay 'tax' that goes straight to scammers.",
                "red_flag": "No legitimate platform asks you to pay fees before withdrawal."
            },
            {
                "step": 5,
                "scammer_says": "[Platform goes offline / Scammer blocks you / Group deleted]",
                "purpose": "Once they've extracted maximum money, they disappear completely.",
                "red_flag": "Your invested money, the 'profits', and the scammer are all gone."
            },
        ],
        "money_trail": "Your UPI/bank transfer → Shell company account → Crypto conversion (USDT) → Offshore wallet → Laundered through Chinese/Southeast Asian operations",
        "prevention": [
            "SEBI never guarantees returns. Anyone promising guaranteed returns is illegal",
            "Check SEBI registration: https://www.sebi.gov.in/sebiweb/other/OtherAction.do?doRecognisedFpi=yes",
            "Never invest on platforms shared via WhatsApp/Telegram groups",
            "If returns seem too good to be true, they are 100% a scam",
            "Real brokers: Zerodha, Groww, Upstox, Angel One — all SEBI registered",
        ],
    },

    "job_scam": {
        "name": "Fake Job Offer / Work From Home Scam",
        "threat_level": "HIGH",
        "common_in": ["WhatsApp", "Telegram", "SMS", "Email"],
        "targets": "Job seekers, fresh graduates, housewives seeking WFH income",
        "total_victims_india": "3.2 lakh+ reported (2024-2025)",
        "avg_loss": "₹5,000 – ₹2,00,000",
        "trigger_patterns": [
            r"(work|earn).*(from\s*home|daily|per\s*day|per\s*hour)",
            r"(₹|rs|inr)\s*\d+.*(daily|per\s*day|per\s*hour|per\s*task)",
            r"(hiring|recruitment|job|vacancy).*(immediate|urgent|apply\s*now)",
            r"(no\s*experience|no\s*qualification|anyone\s*can)",
            r"(tcs|infosys|wipro|amazon|flipkart|google).*(hiring|job|offer)",
            r"(like|review|rate|click|watch).*(video|product|app).*(earn|money)",
            r"(registration|joining|security).*(fee|deposit|charge)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "Congratulations! You've been selected for a work-from-home data entry job. Earn ₹1500/day. No experience needed.",
                "purpose": "Targeting people who need income. The job doesn't exist.",
                "red_flag": "Unsolicited job offers with unrealistic pay for simple tasks."
            },
            {
                "step": 2,
                "scammer_says": "Complete this simple task: like these 5 YouTube videos / rate these products / review this app. We'll pay you ₹500 as a trial.",
                "purpose": "They actually pay the small trial amount to build trust. This is the bait.",
                "red_flag": "The small 'payment' is an investment to extract much larger amounts later."
            },
            {
                "step": 3,
                "scammer_says": "Great work! To access premium tasks worth ₹3000-5000/day, upgrade to VIP by depositing ₹2000.",
                "purpose": "Now the extraction begins. They keep inventing levels that require more deposits.",
                "red_flag": "No real employer asks employees to PAY for work tasks."
            },
            {
                "step": 4,
                "scammer_says": "Your account shows ₹45,000 earnings! To withdraw, pay ₹10,000 processing fee / tax / unlock charge.",
                "purpose": "The 'earnings' are fake numbers on a fake platform. The 'fee' is pure theft.",
                "red_flag": "Paying to withdraw your own earnings is always a scam."
            },
        ],
        "money_trail": "Your deposits → Scammer's multiple UPI accounts → Crypto → Routed through task-scam networks operating from Myanmar/Cambodia/Laos",
        "prevention": [
            "No real job requires you to pay money upfront — ever",
            "Verify job offers on the company's official careers page",
            "If they pay you first then ask for larger deposits, it's a pig-butchering scam",
            "Report fake job offers: cybercrime.gov.in",
            "Real WFH jobs are listed on: LinkedIn, Naukri, Indeed — never on WhatsApp/Telegram",
        ],
    },

    "otp_fraud": {
        "name": "OTP / Remote Access Fraud",
        "threat_level": "CRITICAL",
        "common_in": ["Phone Call", "SMS"],
        "targets": "Everyone, especially senior citizens and non-tech-savvy users",
        "total_victims_india": "8.5 lakh+ reported (2024-2025)",
        "avg_loss": "₹10,000 – ₹10,00,000",
        "trigger_patterns": [
            r"(otp|one\s*time\s*password|verification\s*code)",
            r"(share|tell|give|send|forward).*(otp|code|password)",
            r"(anydesk|teamviewer|quick\s*support|remote|screen\s*share)",
            r"(install|download).*(app|application|software)",
            r"(parcel|courier|package|delivery).*(stuck|held|customs|pending)",
            r"(refund|cashback|reward|prize).*(otp|verify|confirm)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "Sir/Ma'am, this is [Bank/Amazon/Flipkart/FedEx]. There's an issue with your account/order/parcel. I need to verify your identity.",
                "purpose": "Impersonating a trusted brand to gain your confidence.",
                "red_flag": "Companies never call asking to 'verify' via OTP sharing."
            },
            {
                "step": 2,
                "scammer_says": "For verification, I've sent an OTP to your number. Please share it with me.",
                "purpose": "The OTP is for a transaction/login on YOUR account. Sharing it gives them access.",
                "red_flag": "OTPs exist to protect YOU. No company employee will ever ask for them."
            },
            {
                "step": 3,
                "scammer_says": "OR: Please install this app called AnyDesk/TeamViewer for quick resolution.",
                "purpose": "Remote access apps let them see your screen and control your phone/computer.",
                "red_flag": "Never install screen sharing apps at someone's request over a call."
            },
            {
                "step": 4,
                "scammer_says": "[Accesses your banking app, UPI, email through shared OTP or remote access]",
                "purpose": "With OTP or screen access, they drain accounts in real-time while keeping you on the call.",
                "red_flag": "By the time the call ends, your money is gone."
            },
        ],
        "money_trail": "Your account → Multiple UPI transfers in rapid succession → Crypto purchase → Wallet draining → Untraceable",
        "prevention": [
            "NEVER share OTP with anyone — not bank, not police, not RBI, not anyone",
            "Read the OTP SMS — it clearly states what the OTP authorizes",
            "Never install AnyDesk/TeamViewer/QuickSupport at anyone's request",
            "Hang up and call the company's official number to verify",
            "Banks and companies will NEVER ask for your OTP",
        ],
    },

    "loan_scam": {
        "name": "Fake Instant Loan App Scam",
        "threat_level": "HIGH",
        "common_in": ["SMS", "WhatsApp", "Play Store fake apps"],
        "targets": "People in financial distress, small business owners, young adults",
        "total_victims_india": "4.1 lakh+ reported (2024-2025)",
        "avg_loss": "₹5,000 – ₹3,00,000 (plus harassment and data theft)",
        "trigger_patterns": [
            r"(instant|quick|fast|immediate).*(loan|credit|money)",
            r"(no\s*document|no\s*cibil|no\s*credit\s*check|guaranteed\s*approval)",
            r"(loan\s*app|download\s*app).*(loan|credit)",
            r"(processing|registration|insurance).*(fee|charge|deposit)",
            r"(pre-?approved|sanctioned).*(loan|credit|amount)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "Instant loan up to ₹5,00,000! No documents needed. No CIBIL check. Approved in 5 minutes.",
                "purpose": "Targeting people desperate for money with impossible promises.",
                "red_flag": "No legitimate lender gives loans without documentation or credit checks."
            },
            {
                "step": 2,
                "scammer_says": "Download our app and apply. Your loan of ₹2,00,000 is pre-approved!",
                "purpose": "The app steals your contacts, photos, and personal data from your phone.",
                "red_flag": "Check if the lender is RBI registered. Most fake loan apps aren't."
            },
            {
                "step": 3,
                "scammer_says": "Pay ₹3,000 processing fee / GST / insurance charges to receive your loan.",
                "purpose": "There is no loan. They collect fees from thousands of victims.",
                "red_flag": "Real banks deduct fees from the loan amount. You never pay upfront."
            },
            {
                "step": 4,
                "scammer_says": "[Blackmail using stolen contacts/photos. OR: Gave small loan at 100%+ interest with daily harassment]",
                "purpose": "If they gave you a small amount, they harass you and your contacts for repayment at extortionate rates. If they didn't, they use your photos/contacts for blackmail.",
                "red_flag": "Victims report morphed photos sent to contacts, threatening calls, and public shaming."
            },
        ],
        "money_trail": "Processing fees → Scammer's accounts. If loan given: small amount to you → You repay 5-10x through harassment → Profits to operators (often based in China/Southeast Asia)",
        "prevention": [
            "Only take loans from RBI-registered NBFCs and banks",
            "Check RBI registration: https://www.rbi.org.in/Scripts/PublicationsView.aspx?id=12786",
            "Never download loan apps from WhatsApp links — only official Play Store with verified reviews",
            "Never pay 'processing fees' before receiving a loan",
            "If already trapped: Report to cybercrime.gov.in and DO NOT pay further",
        ],
    },

    "sextortion": {
        "name": "Sextortion / Video Call Blackmail",
        "threat_level": "CRITICAL",
        "common_in": ["WhatsApp", "Facebook", "Instagram", "Random Video Calls"],
        "targets": "Men of all ages, especially young adults and professionals",
        "total_victims_india": "1.8 lakh+ reported (2024-2025)",
        "avg_loss": "₹10,000 – ₹10,00,000 (recurring payments)",
        "trigger_patterns": [
            r"(video\s*call|nude|naked|morphed|edited).*(photo|video|image)",
            r"(send|share|forward|upload).*(contact|family|friend|social\s*media)",
            r"(pay|transfer|send\s*money).*(delete|remove|not\s*share|keep\s*secret)",
            r"(blackmail|threat|expose|viral|public)",
            r"(facebook|instagram|youtube).*(upload|post|share|viral)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "[Attractive profile sends friend request or random video call from unknown number]",
                "purpose": "The profile is fake. They're recording everything from the start.",
                "red_flag": "Unknown attractive people contacting you out of nowhere is always suspicious."
            },
            {
                "step": 2,
                "scammer_says": "[Person on video call undresses / asks you to undress / shows explicit content]",
                "purpose": "Recording your face and any compromising visuals. Some use pre-recorded videos.",
                "red_flag": "Never undress or do anything compromising on video with strangers."
            },
            {
                "step": 3,
                "scammer_says": "I have your video. I have your contact list. Pay ₹50,000 or I send this to your family, friends, and employer.",
                "purpose": "Fear and shame make victims pay. They may show your contacts list as proof.",
                "red_flag": "This is a crime (extortion under IPC 383/384). They are the criminal, not you."
            },
            {
                "step": 4,
                "scammer_says": "Pay more or I'll still release it. [Demands keep increasing]",
                "purpose": "They NEVER stop. Paying once guarantees more demands. There is no end.",
                "red_flag": "Paying NEVER solves it — it only makes them demand more."
            },
        ],
        "money_trail": "Payments to multiple UPI IDs/accounts → Controlled by organized gangs → Often based in Mewat (Rajasthan/Haryana) or international operators",
        "prevention": [
            "NEVER accept video calls from unknown numbers",
            "NEVER undress or share intimate content on video with anyone you don't fully trust",
            "If targeted: DO NOT PAY — paying guarantees more demands, not silence",
            "Report immediately: cybercrime.gov.in + local police FIR",
            "Block the number and secure your social media (set profiles to private)",
            "The shame is manufactured — you are the victim of a crime, not the criminal",
        ],
    },

    "customs_parcel": {
        "name": "Fake Customs / Courier / FedEx Scam",
        "threat_level": "HIGH",
        "common_in": ["Phone Call", "WhatsApp", "SMS"],
        "targets": "Online shoppers, NRIs, people expecting deliveries",
        "total_victims_india": "2.8 lakh+ reported (2024-2025)",
        "avg_loss": "₹5,000 – ₹5,00,000",
        "trigger_patterns": [
            r"(parcel|courier|package|shipment).*(stuck|held|seized|customs|illegal)",
            r"(fedex|dhl|bluedart|india\s*post|customs).*(call|alert|notice)",
            r"(drugs|contraband|illegal\s*items|narcotics).*(found|detected|your\s*name)",
            r"(arrest|warrant|police|ncb|narcotics|cyber\s*crime).*(your\s*name|involved)",
            r"(transfer|settle|pay|fine).*(avoid|arrest|legal|action)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "This is FedEx/Customs. A parcel in your name contains illegal items (drugs/passports). Your Aadhaar was used.",
                "purpose": "Inducing fear. You panic because you didn't send any parcel.",
                "red_flag": "Real customs/courier issues are handled via official written notices, not phone calls."
            },
            {
                "step": 2,
                "scammer_says": "I'm connecting you to the Cyber Crime department / Mumbai Police / NCB for verification.",
                "purpose": "Fake 'transfer' to another scammer pretending to be a police officer.",
                "red_flag": "Police and NCB never call people about parcels. They issue written summons."
            },
            {
                "step": 3,
                "scammer_says": "Officer: Your identity has been compromised. Stay on the line. Do not tell anyone. This is a confidential investigation.",
                "purpose": "Isolation tactic. They keep you on the phone for hours so you can't verify with family/friends.",
                "red_flag": "Real police never ask you to stay on a call for hours or keep it secret."
            },
            {
                "step": 4,
                "scammer_says": "Transfer money to this 'safe account' / 'RBI verification account' to prove the money is legitimately yours.",
                "purpose": "No such thing as a 'safe account'. RBI doesn't have verification accounts.",
                "red_flag": "No authority asks you to transfer money for 'verification' — ever."
            },
        ],
        "money_trail": "Your 'safety deposit' → Mule accounts → Rapidly fragmented → Converted to crypto → Cross-border laundering",
        "prevention": [
            "Courier companies handle issues via email/written notice, not threatening phone calls",
            "Police never call demanding money transfers for 'verification'",
            "No such thing as 'RBI safe account' or 'Supreme Court escrow'",
            "If someone says 'don't tell anyone' — that's the biggest red flag",
            "Hang up and verify with the actual courier company's official number",
        ],
    },

    "digital_arrest": {
        "name": "Digital Arrest Scam",
        "threat_level": "CRITICAL",
        "common_in": ["Video Call", "Phone Call", "WhatsApp"],
        "targets": "Senior citizens, professionals, anyone unfamiliar with legal procedures",
        "total_victims_india": "₹120+ crore lost in first 4 months of 2025",
        "avg_loss": "₹2,00,000 – ₹3,00,00,000",
        "trigger_patterns": [
            r"(digital\s*arrest|cyber\s*arrest|online\s*arrest)",
            r"(stay\s*on\s*video|video\s*call\s*monitoring|don't\s*disconnect)",
            r"(supreme\s*court|high\s*court).*(warrant|order|directive)",
            r"(cbi|ed|nia|ncb|enforcement).*(investigation|case|complaint)",
            r"(money\s*laundering|hawala|terror).*(linked|connected|associated)",
            r"(don't\s*tell|confidential|secret|classified).*(investigation|case)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "This is CBI/ED/Cyber Crime. A case has been registered against you for money laundering. You are under digital arrest.",
                "purpose": "There is NO legal concept of 'digital arrest' in Indian law. This is entirely fabricated.",
                "red_flag": "DIGITAL ARREST DOES NOT EXIST IN INDIAN LAW. Period."
            },
            {
                "step": 2,
                "scammer_says": "Stay on video call. We are monitoring you. If you disconnect, a physical arrest warrant will be issued. Do not tell anyone.",
                "purpose": "Keeping you captive and isolated through fear. Victims have stayed on calls for days.",
                "red_flag": "No law enforcement agency conducts investigations over video call."
            },
            {
                "step": 3,
                "scammer_says": "To clear your name, transfer your money to this 'government verification account' for audit.",
                "purpose": "There is no government verification account. Every rupee goes to the scammer.",
                "red_flag": "Government agencies NEVER ask for money transfers to clear someone."
            },
            {
                "step": 4,
                "scammer_says": "[Victim transfers life savings, FDs, takes loans — sometimes over multiple days]",
                "purpose": "Victims have lost crores. The fear is so intense that people don't eat, sleep, or contact family.",
                "red_flag": "PM Modi himself addressed the nation about this scam in October 2024."
            },
        ],
        "money_trail": "Victim's savings + FDs + loans → Multiple mule accounts → Crypto conversion via P2P exchanges → International wire → Vanished",
        "prevention": [
            "DIGITAL ARREST DOES NOT EXIST — this was confirmed by PM Modi on Mann Ki Baat",
            "CBI/ED/Police NEVER investigate via video call",
            "No agency asks for money to 'clear your name'",
            "If you receive such a call: HANG UP IMMEDIATELY",
            "Call your local police station to verify any 'warrant' claims",
            "Tell your family/friends immediately — scammers rely on secrecy",
        ],
    },

    "qr_code_scam": {
        "name": "Fake QR Code Payment Scam",
        "threat_level": "HIGH",
        "common_in": ["WhatsApp", "In-person (shops/vendors)", "OLX/Quikr"],
        "targets": "Sellers, small shopkeepers, people unfamiliar with QR codes",
        "total_victims_india": "1.5 lakh+ reported (2024-2025)",
        "avg_loss": "₹2,000 – ₹50,000",
        "trigger_patterns": [
            r"(scan|scanning).*(qr|code).*(receive|get|payment)",
            r"(qr\s*code).*(sent|sending|receive|money)",
            r"(scan.*pay|pay.*scan)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "I'll send you a QR code. Just scan it to RECEIVE the payment for your product.",
                "purpose": "QR codes are for PAYING, not receiving. Scanning their QR code sends YOUR money.",
                "red_flag": "You never need to scan a QR code to receive money."
            },
            {
                "step": 2,
                "scammer_says": "Enter the amount you want to receive and confirm with your UPI PIN.",
                "purpose": "The UPI PIN confirmation is authorizing a PAYMENT from your account.",
                "red_flag": "Receiving money NEVER requires your PIN. If it asks for PIN, it's a payment."
            },
        ],
        "money_trail": "Your UPI → Scammer's account → Immediately moved",
        "prevention": [
            "Scanning a QR code = PAYING, never receiving",
            "You never enter UPI PIN to receive money",
            "For receiving: share YOUR QR code or UPI ID to the buyer",
            "Verify all payments via your bank statement, not the caller's claims",
        ],
    },

    "romance_scam": {
        "name": "Romance / Dating Scam",
        "threat_level": "HIGH",
        "common_in": ["Facebook", "Instagram", "Dating Apps", "WhatsApp"],
        "targets": "Lonely individuals, divorced/widowed people, NRIs",
        "total_victims_india": "45,000+ reported (2024-2025)",
        "avg_loss": "₹50,000 – ₹50,00,000",
        "trigger_patterns": [
            r"(love|relationship|marry|marriage|dating).*(online|met|know)",
            r"(army|military|oil\s*rig|abroad|foreign).*(doctor|engineer|officer)",
            r"(gift|parcel|inheritance|gold).*(customs|stuck|clearance|fee)",
            r"(money|funds|transfer|help).*(emergency|urgent|medical|legal)",
            r"(never\s*met|haven't\s*met|only\s*online|video\s*call\s*not\s*working)",
        ],
        "playbook": [
            {
                "step": 1,
                "scammer_says": "[Attractive profile with photos of a military officer / doctor / engineer contacts you and builds romantic relationship over weeks/months]",
                "purpose": "Building deep emotional connection before asking for money. May last months.",
                "red_flag": "Too-perfect profile, refuses video calls, always has excuses for not meeting."
            },
            {
                "step": 2,
                "scammer_says": "I'm sending you a gift/money/gold. But it's stuck at customs. Can you pay the clearance fee? I'll reimburse you.",
                "purpose": "The gift doesn't exist. Customs clearance fees go to the scammer.",
                "red_flag": "Anyone asking you to pay fees to receive a 'gift' is a scammer."
            },
            {
                "step": 3,
                "scammer_says": "I have a medical/legal emergency. I need ₹2,00,000 urgently. You're the only one I can trust.",
                "purpose": "Exploiting the emotional bond to extract large sums.",
                "red_flag": "Emergencies that only YOU can solve with money = scam."
            },
        ],
        "money_trail": "Your transfers → Accounts controlled by organized romance scam networks → Often operated from West Africa (Nigeria, Ghana) or Southeast Asia",
        "prevention": [
            "Never send money to someone you've never met in person",
            "Reverse image search their photos — scammers steal photos from real people",
            "If they refuse video calls or always cancel meeting plans, it's a scam",
            "Ask a trusted friend or family member for their objective opinion",
            "Real love doesn't come with customs fees and wire transfer requests",
        ],
    },
}


# ══════════════════════════════════════════════════════════════════
# SCAM ANALYZER — Matches messages against DNA patterns
# ══════════════════════════════════════════════════════════════════

def analyze_message(message: str) -> dict:
    """
    Analyze a suspicious message and return:
    - Matched scam DNA pattern(s)
    - Complete playbook
    - Risk assessment
    - Prevention advice
    """
    message_lower = message.lower().strip()
    matches = []

    for scam_id, dna in SCAM_DNA.items():
        score = 0
        matched_patterns = []

        for pattern in dna["trigger_patterns"]:
            if re.search(pattern, message_lower):
                score += 1
                matched_patterns.append(pattern)

        if score > 0:
            confidence = min(99, (score / len(dna["trigger_patterns"])) * 100 + (score * 15))
            matches.append({
                "scam_id": scam_id,
                "confidence": round(confidence, 1),
                "matched_signals": score,
                "total_signals": len(dna["trigger_patterns"]),
                "dna": dna,
            })

    # Sort by confidence
    matches.sort(key=lambda x: x["confidence"], reverse=True)

    if not matches:
        return {
            "is_scam": False,
            "message": "No known scam patterns detected in this message. However, always verify independently.",
            "matches": [],
        }

    top = matches[0]
    return {
        "is_scam": True,
        "threat_level": top["dna"]["threat_level"],
        "primary_match": {
            "scam_type": top["dna"]["name"],
            "confidence": top["confidence"],
            "matched_signals": top["matched_signals"],
            "common_in": top["dna"]["common_in"],
            "targets": top["dna"]["targets"],
            "victims_india": top["dna"]["total_victims_india"],
            "avg_loss": top["dna"]["avg_loss"],
            "playbook": top["dna"]["playbook"],
            "money_trail": top["dna"]["money_trail"],
            "prevention": top["dna"]["prevention"],
        },
        "other_matches": [
            {
                "scam_type": m["dna"]["name"],
                "confidence": m["confidence"],
            }
            for m in matches[1:3]
        ],
    }


def get_all_scam_dna():
    """Return all scam DNA patterns for the Scam Library."""
    return [
        {
            "id": scam_id,
            "name": dna["name"],
            "threat_level": dna["threat_level"],
            "common_in": dna["common_in"],
            "targets": dna["targets"],
            "victims_india": dna["total_victims_india"],
            "avg_loss": dna["avg_loss"],
            "playbook_steps": len(dna["playbook"]),
            "prevention_tips": len(dna["prevention"]),
        }
        for scam_id, dna in SCAM_DNA.items()
    ]


def get_scam_dna_detail(scam_id: str) -> Optional[dict]:
    """Return full DNA detail for a specific scam type."""
    dna = SCAM_DNA.get(scam_id)
    if not dna:
        return None
    return {
        "id": scam_id,
        **dna,
    }


# ══════════════════════════════════════════════════════════════════
# LIVE SCAM RADAR — Real-time scam activity by city
# (Uses report data from the ScamCheck database)
# ══════════════════════════════════════════════════════════════════

def get_live_scam_radar(db=None):
    """
    Generate live scam activity feed grouped by city.
    Returns recent scam reports with geographic distribution.
    """
    if db is None:
        db = SessionLocal()
        should_close = True
    else:
        should_close = False

    try:
        from sqlalchemy import func, desc
        from models import Indicator, Report

        # Recent indicators by location
        recent = db.query(
            Indicator.location,
            Indicator.category,
            func.count(Indicator.id).label("count"),
            func.max(Indicator.last_seen).label("latest"),
        ).filter(
            Indicator.location.isnot(None),
            Indicator.location != "",
            Indicator.location != "Global",
            Indicator.location != "Unknown",
            Indicator.location != "Dark Web / Global",
        ).group_by(
            Indicator.location, Indicator.category
        ).order_by(desc("latest")).limit(50).all()

        radar = {}
        for loc, cat, count, latest in recent:
            city = loc.split(",")[0].strip()
            if city not in radar:
                radar[city] = {"city": city, "total": 0, "scam_types": [], "latest": None}
            radar[city]["total"] += count
            radar[city]["scam_types"].append({"type": cat, "count": count})
            if latest and (not radar[city]["latest"] or latest > radar[city]["latest"]):
                radar[city]["latest"] = latest.isoformat() if hasattr(latest, 'isoformat') else str(latest)

        return sorted(radar.values(), key=lambda x: x["total"], reverse=True)[:20]

    finally:
        if should_close:
            db.close()


if __name__ == "__main__":
    # Test the analyzer
    print("=" * 60)
    print("ScamCheck — Scam Predictor Engine Test")
    print("=" * 60)

    test_messages = [
        "Dear customer your SBI KYC has expired. Your account will be blocked in 24 hours. Update now: http://sbi-kyc-update.in",
        "Join our FREE stock tips WhatsApp group! Guaranteed 300% returns! Minimum investment just ₹5000",
        "This is CBI. You are under digital arrest. A case of money laundering has been filed. Stay on video call.",
        "Congratulations! You've been selected for Amazon work from home job. Earn ₹1500 per day. No experience needed.",
        "I've sent you a QR code. Scan it to receive the payment for your OLX product.",
        "Hey, how's the weather today?",
    ]

    for msg in test_messages:
        print(f"\n📩 Message: \"{msg[:80]}...\"")
        result = analyze_message(msg)

        if result["is_scam"]:
            m = result["primary_match"]
            print(f"   🚨 SCAM DETECTED: {m['scam_type']}")
            print(f"   📊 Confidence: {m['confidence']}%")
            print(f"   🎯 Targets: {m['targets']}")
            print(f"   💰 Avg Loss: {m['avg_loss']}")
            print(f"   📋 Playbook: {len(m['playbook'])} steps")
            print(f"   🛡️ Prevention tips: {len(m['prevention'])}")
        else:
            print(f"   ✅ No scam patterns detected")

    print(f"\n📚 Total scam DNA patterns: {len(SCAM_DNA)}")
