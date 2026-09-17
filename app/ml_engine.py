"""Explainable phishing classifier used as one CIPHER-X evidence signal.

The lightweight scikit-learn model runs locally.  A DistilBERT adapter can be
enabled later for a deployment that has reviewed model assets and hardware.
"""
from __future__ import annotations

from functools import lru_cache
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    SKLEARN_AVAILABLE = True
except ImportError:  # The forensic service remains usable during dependency setup.
    SKLEARN_AVAILABLE = False


TRAINING_EXAMPLES = [
    ("Your account is suspended. Verify your password immediately using this link.", 1),
    ("Urgent payment needed. Send your OTP and bank account details today.", 1),
    ("Microsoft security alert: click here to confirm your credentials.", 1),
    ("Invoice attached. Open the executable now to avoid service interruption.", 1),
    ("Wire transfer request is confidential. Reply with card number.", 1),
    ("You won a prize, verify your account and claim it immediately.", 1),
    ("Team meeting moved to 3 PM. The calendar invitation is attached.", 0),
    ("Your monthly project update is available on the internal portal.", 0),
    ("Thank you for your purchase. Your receipt is attached for your records.", 0),
    ("Please review the design document before Friday's planning session.", 0),
    ("The office will be closed on Monday for the public holiday.", 0),
    ("Your requested password reset was completed successfully.", 0),
]


@lru_cache(maxsize=1)
def _model():
    texts, labels = zip(*TRAINING_EXAMPLES)
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), stop_words="english", min_df=1)),
        ("classifier", LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)),
    ]).fit(texts, labels)


def predict_phishing(text: str) -> dict:
    """Return a local, reproducible baseline prediction and useful word cues."""
    if not SKLEARN_AVAILABLE:
        words = (text or "").lower()
        risky = [term for term in ("urgent", "verify", "password", "otp", "credential", "wire transfer", "click") if term in words]
        probability = min(0.95, 0.12 + (0.13 * len(risky)))
        return {"model": "ML dependency setup pending — deterministic fallback", "phishing_probability": round(probability, 4), "label": "needs-review" if risky else "benign-like", "top_text_cues": [{"term": term, "contribution": 0.13} for term in risky], "limitations": "Install the declared scikit-learn dependency to activate the trained local ML baseline."}
    model = _model()
    probability = float(model.predict_proba([text or ""])[0][1])
    vectorizer: TfidfVectorizer = model.named_steps["tfidf"]
    classifier: LogisticRegression = model.named_steps["classifier"]
    terms = vectorizer.get_feature_names_out()
    values = vectorizer.transform([text or ""]).toarray()[0]
    weights = classifier.coef_[0]
    cues = sorted(
        ((terms[i], float(values[i] * weights[i])) for i in values.nonzero()[0]),
        key=lambda item: item[1], reverse=True,
    )[:4]
    return {
        "model": "CIPHER-X local TF-IDF + Logistic Regression baseline",
        "phishing_probability": round(probability, 4),
        "label": "phishing-like" if probability >= 0.65 else "needs-review" if probability >= 0.4 else "benign-like",
        "top_text_cues": [{"term": term, "contribution": round(value, 3)} for term, value in cues if value > 0],
        "limitations": "This local baseline is trained on a small demonstration corpus. It is an explainable triage signal, not a final security verdict.",
    }


def model_status() -> dict:
    """Safe dashboard metadata; it exposes no model internals or email content."""
    return {
        "active": SKLEARN_AVAILABLE,
        "name": "TF-IDF + Logistic Regression" if SKLEARN_AVAILABLE else "Deterministic setup fallback",
        "purpose": "Explainable phishing-language triage alongside technical forensic evidence.",
    }
