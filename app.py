
import streamlit as st
import re
import os
import joblib
import numpy as np
from PIL import Image

st.set_page_config(
    page_title="ScamShield AI",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
.main {
    background-color: #f7f9fc;
}
.hero {
    padding: 30px;
    border-radius: 18px;
    background: #111827;
    color: white;
    margin-bottom: 25px;
}
.hero h1 {
    font-size: 42px;
}
.card {
    padding: 20px;
    border-radius: 15px;
    background: white;
    border: 1px solid #e5e7eb;
    margin-bottom: 15px;
}
.danger {
    padding: 20px;
    border-radius: 15px;
    background: #fee2e2;
    border-left: 6px solid #dc2626;
}
.warning {
    padding: 20px;
    border-radius: 15px;
    background: #fef3c7;
    border-left: 6px solid #f59e0b;
}
.safe {
    padding: 20px;
    border-radius: 15px;
    background: #dcfce7;
    border-left: 6px solid #16a34a;
}
</style>
""", unsafe_allow_html=True)

MODEL_DIR = "." 

model = joblib.load(
    MODEL_DIR + "/scam_classifier.pkl"
)

vectorizer = joblib.load(
    MODEL_DIR + "/tfidf_vectorizer.pkl"
)

URGENCY = [
    "urgent", "immediately", "now", "today",
    "last chance", "act fast", "expires",
    "blocked", "suspended", "final warning"
]

FINANCIAL = [
    "payment", "pay", "money", "transfer", "upi",
    "bank", "refund", "fee", "deposit",
    "credit card", "debit card", "transaction"
]

CREDENTIALS = [
    "otp", "password", "pin", "cvv", "login",
    "username", "verification code",
    "security code", "aadhaar", "pan"
]

THREATS = [
    "blocked", "suspended", "legal action",
    "police", "arrest", "penalty",
    "fine", "deactivate", "terminate"
]

REWARDS = [
    "winner", "won", "prize", "reward",
    "bonus", "cashback", "lottery",
    "free", "gift", "selected"
]

AUTHORITY = [
    "bank", "government", "police",
    "income tax", "rbi", "uidai",
    "amazon", "flipkart", "courier",
    "official", "support", "customer care"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "cutt.ly", "is.gd"
]

SCAM_TYPES = {
    "Banking / KYC": [
        "bank", "kyc", "account",
        "blocked", "suspended"
    ],
    "UPI / Payment": [
        "upi", "payment", "transaction",
        "refund", "pay"
    ],
    "Job Scam": [
        "job", "salary", "work from home",
        "hiring", "vacancy", "employment"
    ],
    "Prize / Lottery": [
        "lottery", "winner", "prize",
        "reward", "selected", "cashback"
    ],
    "Investment Scam": [
        "investment", "crypto",
        "trading", "profit", "returns"
    ],
    "Courier Scam": [
        "courier", "parcel",
        "delivery", "customs", "shipment"
    ],
    "Account Takeover": [
        "password", "otp", "login",
        "verification code"
    ],
    "Government Impersonation": [
        "government", "income tax",
        "police", "rbi", "uidai", "aadhaar"
    ]
}

def analyze_url(url):

    url = url.strip()
    score = 0
    indicators = []

    if not url:
        return {
            "score": 0,
            "level": "LOW",
            "indicators": []
        }

    if url.lower().startswith("http://"):
        score += 20
        indicators.append("Uses HTTP instead of HTTPS")

    if re.search(
        r"https?://(?:\d{1,3}\.){3}\d{1,3}",
        url
    ):
        score += 30
        indicators.append("Uses a raw IP address")

    if len(url) > 100:
        score += 15
        indicators.append("Unusually long URL")

    if "@" in url:
        score += 25
        indicators.append("Contains @ symbol")

    for shortener in SHORTENERS:
        if shortener in url.lower():
            score += 25
            indicators.append("Uses URL shortener")
            break

    suspicious = [
        "verify", "secure", "login",
        "update", "account", "claim",
        "reward", "kyc", "support",
        "wallet", "bank"
    ]

    found = [
        word for word in suspicious
        if word in url.lower()
    ]

    if found:
        score += min(25, len(found) * 8)
        indicators.append(
            "Suspicious URL keywords: " +
            ", ".join(found)
        )

    try:
        domain = re.sub(
            r"^https?://",
            "",
            url.lower()
        ).split("/")[0]

        if domain.count(".") >= 3:
            score += 20
            indicators.append(
                "Multiple subdomains detected"
            )
    except:
        pass

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
        "indicators": indicators
    }

def analyze_message(message):

    lower = message.lower()

    X = vectorizer.transform([message])

    probability = float(
        model.predict_proba(X)[0][1]
    )

    score = probability * 55
    indicators = []

    urgency = [
        x for x in URGENCY
        if x in lower
    ]

    financial = [
        x for x in FINANCIAL
        if x in lower
    ]

    credentials = [
        x for x in CREDENTIALS
        if x in lower
    ]

    threats = [
        x for x in THREATS
        if x in lower
    ]

    rewards = [
        x for x in REWARDS
        if x in lower
    ]

    authority = [
        x for x in AUTHORITY
        if x in lower
    ]

    if urgency:
        score += min(15, len(urgency) * 5)
        indicators.append(
            "Urgency pressure detected"
        )

    if financial:
        score += min(12, len(financial) * 3)
        indicators.append(
            "Financial language detected"
        )

    if credentials:
        score += min(15, len(credentials) * 5)
        indicators.append(
            "Credential or sensitive-data request"
        )

    if threats:
        score += min(12, len(threats) * 4)
        indicators.append(
            "Threat or fear language detected"
        )

    if rewards:
        score += min(10, len(rewards) * 3)
        indicators.append(
            "Reward or temptation language detected"
        )

    if authority:
        score += min(10, len(authority) * 3)
        indicators.append(
            "Possible authority impersonation"
        )

    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        message
    )

    url_results = []

    for url in urls:

        result = analyze_url(url)
        url_results.append(result)

        if result["score"] >= 40:
            score += min(
                20,
                result["score"] * 0.2
            )

            indicators.append(
                "Suspicious URL structure detected"
            )

    score = min(round(score), 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    type_scores = {}

    for scam_type, words in SCAM_TYPES.items():

        count = sum(
            1 for word in words
            if word in lower
        )

        if count:
            type_scores[scam_type] = count

    if type_scores:
        scam_type = max(
            type_scores,
            key=type_scores.get
        )
    else:
        scam_type = "General Spam / Unknown"

    dna = {
        "Urgency": min(100, len(urgency) * 30),
        "Fear / Threat": min(100, len(threats) * 30),
        "Authority": min(100, len(authority) * 25),
        "Financial Pressure": min(100, len(financial) * 20),
        "Credential Theft": min(100, len(credentials) * 35),
        "Reward": min(100, len(rewards) * 25)
    }

    attack_path = []

    if authority:
        attack_path.append(
            "1. Impersonate trusted organization"
        )

    if urgency or threats:
        attack_path.append(
            "2. Create urgency or fear"
        )

    if urls:
        attack_path.append(
            "3. Send victim to suspicious link"
        )

    if credentials:
        attack_path.append(
            "4. Attempt credential theft"
        )

    if financial:
        attack_path.append(
            "5. Attempt financial extraction"
        )

    if not attack_path:
        attack_path = [
            "1. Unknown sender/message",
            "2. Social engineering attempt",
            "3. Potential victim interaction"
        ]

    return {
        "risk": score,
        "probability": probability * 100,
        "level": level,
        "indicators": indicators,
        "type": scam_type,
        "dna": dna,
        "attack": attack_path,
        "urls": url_results
    }

@st.cache_resource
def get_reader():

    import easyocr

    return easyocr.Reader(
        ["en"],
        gpu=False
    )

def ocr_image(image):

    reader = get_reader()

    text = reader.readtext(
        np.array(image),
        detail=0
    )

    return " ".join(text)

SCENARIOS = {
    "🏦 Bank KYC Scam": {
        "message":
            "Your bank account will be blocked today. "
            "Complete KYC immediately at "
            "http://secure-bank-verify.com",
        "choices": [
            (
                "Click the link and enter details",
                "🚨 HIGH RISK — credentials may be stolen.",
                False
            ),
            (
                "Open the official bank app yourself",
                "🛡️ SAFE — independently verify.",
                True
            ),
            (
                "Reply with your OTP",
                "🚨 CRITICAL — never share OTPs.",
                False
            )
        ]
    },
    "💼 Job Scam": {
        "message":
            "Congratulations! You have been selected "
            "for a work-from-home job. Pay ₹999 registration fee.",
        "choices": [
            (
                "Pay the registration fee",
                "🚨 HIGH RISK — advance-fee pattern.",
                False
            ),
            (
                "Verify the company independently",
                "🛡️ SAFE — verify the employer.",
                True
            ),
            (
                "Send Aadhaar and bank details",
                "🚨 CRITICAL — sensitive data exposure.",
                False
            )
        ]
    },
    "🎁 Prize Scam": {
        "message":
            "You won ₹50,000! Pay ₹2,000 processing fee.",
        "choices": [
            (
                "Pay the processing fee",
                "🚨 HIGH RISK — advance-fee pattern.",
                False
            ),
            (
                "Ignore and verify independently",
                "🛡️ SAFE ACTION.",
                True
            ),
            (
                "Send bank details",
                "🚨 HIGH RISK — financial information exposure.",
                False
            )
        ]
    }
}

st.markdown("""
<div class="hero">

<h1>🛡️ ScamShield AI</h1>

<p>
AI-Powered Scam Detection, Investigation & Defense System
</p>

<p>
<b>SEE IT → CHECK IT → UNDERSTAND IT → THEN ACT</b>
</p>

</div>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ ScamShield")

mode = st.sidebar.radio(
    "Choose Mode",
    [
        "🔍 Analyze Message",
        "📸 Scan Screenshot",
        "🔗 Check URL",
        "🎭 Attack Simulator"
    ]
)

st.sidebar.markdown("---")

st.sidebar.info(
    "Pre-click scam protection using "
    "AI + NLP + OCR + URL intelligence."
)

if mode == "🔍 Analyze Message":

    st.subheader("🔍 AI Scam Investigation")

    message = st.text_area(
        "Paste suspicious message",
        height=180,
        placeholder=
        "Example: Your bank account will be blocked today..."
    )

    if st.button(
        "🚨 ANALYZE THREAT",
        use_container_width=True
    ):

        if not message.strip():

            st.warning("Enter a message first.")

        else:

            result = analyze_message(message)

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "Risk Score",
                f"{result['risk']}/100"
            )

            c2.metric(
                "Threat",
                result["level"]
            )

            c3.metric(
                "ML Probability",
                f"{result['probability']:.1f}%"
            )

            c4.metric(
                "Scam Type",
                result["type"]
            )

            if result["level"] in [
                "CRITICAL", "HIGH"
            ]:

                st.markdown(
                    """
                    <div class="danger">
                    <h3>🚨 PRE-CLICK WARNING</h3>
                    Suspicious scam characteristics detected.
                    <br><br>
                    <b>Do not click links or share OTPs,
                    passwords, PINs or financial information.</b>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            elif result["level"] == "MEDIUM":

                st.markdown(
                    """
                    <div class="warning">
                    ⚠️ Suspicious characteristics detected.
                    Verify independently before acting.
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            else:

                st.markdown(
                    """
                    <div class="safe">
                    🟢 No strong scam indicators detected.
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            st.markdown("### 🧬 Scam DNA")

            cols = st.columns(3)

            for i, (name, value) in enumerate(
                result["dna"].items()
            ):

                with cols[i % 3]:

                    st.write(
                        f"**{name}: {value}%**"
                    )

                    st.progress(
                        min(value, 100)
                    )

            st.markdown("### 🚨 Attack Reconstruction")

            for step in result["attack"]:

                st.markdown(
                    f"""
                    <div class="card">
                    {step}
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            st.markdown("### 🔎 Indicators")

            if result["indicators"]:

                for item in result["indicators"]:
                    st.warning("⚠️ " + item)

            else:
                st.success(
                    "No strong rule-based indicators."
                )

            if result["urls"]:

                st.markdown("### 🔗 URL Intelligence")

                for u in result["urls"]:

                    st.write(
                        f"Risk: {u['score']}/100"
                    )

                    for item in u["indicators"]:
                        st.write("⚠️", item)

            st.markdown("### 🛡️ Defense")

            st.info(
                "Do not click suspicious links. "
                "Never share OTP, PIN, CVV or passwords. "
                "Verify through official channels."
            )

elif mode == "📸 Scan Screenshot":

    st.subheader("📸 Screenshot Scam Scanner")

    uploaded = st.file_uploader(
        "Upload screenshot",
        type=["png", "jpg", "jpeg", "webp"]
    )

    if uploaded:

        image = Image.open(uploaded)

        st.image(
            image,
            caption="Uploaded Screenshot",
            use_container_width=True
        )

        if st.button(
            "🔎 EXTRACT & ANALYZE",
            use_container_width=True
        ):

            with st.spinner(
                "Reading screenshot..."
            ):

                extracted = ocr_image(image)

            st.markdown("### 📝 Extracted Text")

            st.text_area(
                "OCR",
                extracted,
                height=160
            )

            if extracted.strip():

                result = analyze_message(
                    extracted
                )

                c1, c2, c3 = st.columns(3)

                c1.metric(
                    "Risk",
                    f"{result['risk']}/100"
                )

                c2.metric(
                    "Threat",
                    result["level"]
                )

                c3.metric(
                    "Scam Type",
                    result["type"]
                )

                if result["level"] in [
                    "CRITICAL", "HIGH"
                ]:
                    st.error(
                        "🚨 Suspicious scam characteristics detected."
                    )
                elif result["level"] == "MEDIUM":
                    st.warning(
                        "⚠️ Verify before interacting."
                    )
                else:
                    st.success(
                        "🟢 No strong scam indicators detected."
                    )

elif mode == "🔗 Check URL":

    st.subheader("🔗 Pre-Click URL Intelligence")

    st.info(
        "The URL is analyzed structurally. "
        "ScamShield does not open the URL."
    )

    url = st.text_input(
        "Enter suspicious URL"
    )

    if st.button(
        "🔎 CHECK URL",
        use_container_width=True
    ):

        if not url.strip():

            st.warning("Enter a URL.")

        else:

            result = analyze_url(url)

            c1, c2 = st.columns(2)

            c1.metric(
                "Risk Score",
                f"{result['score']}/100"
            )

            c2.metric(
                "Threat Level",
                result["level"]
            )

            if result["level"] in [
                "CRITICAL", "HIGH"
            ]:
                st.error(
                    "🚨 Suspicious URL characteristics detected."
                )
            elif result["level"] == "MEDIUM":
                st.warning(
                    "⚠️ Some suspicious indicators detected."
                )
            else:
                st.success(
                    "🟢 No major structural indicators detected."
                )

            for item in result["indicators"]:
                st.write("⚠️", item)

            st.caption(
                "Structural analysis is not proof that a URL "
                "is malicious or safe."
            )

elif mode == "🎭 Attack Simulator":

    st.subheader("🎭 Scam Attack Simulator")

    scenario_name = st.selectbox(
        "Choose scenario",
        list(SCENARIOS.keys())
    )

    scenario = SCENARIOS[scenario_name]

    st.markdown(
        f"""
        <div class="danger">
        <b>Incoming Message</b><br><br>
        {scenario['message']}
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("### What would you do?")

    for i, choice in enumerate(
        scenario["choices"]
    ):

        text, outcome, safe = choice

        if st.button(
            text,
            key=f"choice_{i}",
            use_container_width=True
        ):

            if safe:
                st.success(outcome)
            else:
                st.error(outcome)

            st.info(
                "Scammers often combine urgency, authority, "
                "fear, rewards and financial pressure to make "
                "victims act before thinking."
            )

st.markdown("---")

st.markdown(
    """
    <center>
    <b>🛡️ SCAMSHIELD AI</b><br>
    SEE IT → CHECK IT → UNDERSTAND IT → THEN ACT
    </center>
    """,
    unsafe_allow_html=True
)
