import streamlit as st
import cv2
import numpy as np
import re
import socket
from urllib.parse import urlparse

st.set_page_config(
    page_title="QR Phishing Detector",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 QR-Code Phishing Detector")
st.write("Upload a QR code image or enter a URL to analyze its phishing risk.")

st.info("Educational prototype: The app analyzes URLs but does not open them.")

def analyze_url(url):
    score = 0
    indicators = []

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme != "https":
        score += 1
        indicators.append("URL does not use HTTPS")

    if not host:
        return "HIGH", ["Invalid URL or missing hostname"]

    try:
        socket.inet_aton(host)
        score += 2
        indicators.append("URL uses an IP address")
    except socket.error:
        pass

    keywords = [
        "login", "signin", "verify", "account",
        "password", "wallet", "banking", "secure"
    ]

    found = [word for word in keywords if word in url.lower()]

    if found:
        score += min(len(found), 3)
        indicators.append("Suspicious keywords: " + ", ".join(found))

    if len(url) > 120:
        score += 1
        indicators.append("Unusually long URL")

    shorteners = [
        "bit.ly", "tinyurl.com", "t.co",
        "goo.gl", "ow.ly", "cutt.ly"
    ]

    if any(host.endswith(domain) for domain in shorteners):
        score += 2
        indicators.append("URL uses a link-shortening service")

    if score >= 5:
        risk = "HIGH"
    elif score >= 2:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    if not indicators:
        indicators.append(
            "No suspicious indicators detected by these basic checks"
        )

    return risk, indicators


uploaded_file = st.file_uploader(
    "Upload QR code image",
    type=["png", "jpg", "jpeg"]
)

if uploaded_file:
    image_bytes = np.frombuffer(
        uploaded_file.getvalue(),
        np.uint8
    )

    image = cv2.imdecode(image_bytes, cv2.IMREAD_COLOR)

    detector = cv2.QRCodeDetector()

    decoded_url, points, _ = detector.detectAndDecode(image)

    if decoded_url:
        st.success("QR Code successfully detected!")
        st.write("Extracted URL:", decoded_url)

        risk, indicators = analyze_url(decoded_url)

        st.subheader("Analysis Results")

        if risk == "HIGH":
            st.error("🔴 HIGH RISK")
        elif risk == "MEDIUM":
            st.warning("🟡 MEDIUM RISK")
        else:
            st.success("🟢 LOW RISK")

        st.write("Suspicious indicators:")

        for indicator in indicators:
            st.write("- " + indicator)

        st.info(
            "Recommendation: Do not open suspicious links. "
            "Verify the website independently."
        )

    else:
        st.error("No QR code could be detected in this image.")


st.divider()

st.subheader("Analyze URL Manually")

manual_url = st.text_input("Enter a URL")

if st.button("Analyze URL"):
    if manual_url.strip():
        risk, indicators = analyze_url(manual_url.strip())

        st.write("URL:", manual_url)

        if risk == "HIGH":
            st.error("🔴 HIGH RISK")
        elif risk == "MEDIUM":
            st.warning("🟡 MEDIUM RISK")
        else:
            st.success("🟢 LOW RISK")

        st.write("Indicators:")

        for indicator in indicators:
            st.write("- " + indicator)

    else:
        st.warning("Please enter a URL.")
