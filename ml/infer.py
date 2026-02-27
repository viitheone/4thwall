"""
Inference module for WAF classifier.
Load model once at init; CPU-compatible. No model modification.
"""

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from ml.config import MAX_LENGTH


class WAFClassifier:
    def __init__(self, model_path: str):
        """Load trained model and tokenizer."""
        self.device = torch.device("cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()

    def predict(self, request_text: str) -> dict:
        """
        Args:
            request_text: Serialized request string
        Returns:
            {
                'score': float (0-1),
                'label': 'benign' or 'malicious',
                'confidence': float
            }
        """
        out = self.predict_batch([request_text])
        return out[0]

    def predict_batch(self, request_texts: list) -> list:
        """Batch prediction for efficiency."""
        if not request_texts:
            return []

        enc = self.tokenizer(
            request_texts,
            truncation=True,
            max_length=MAX_LENGTH,
            padding=True,
            return_tensors="pt",
        )
        enc = {k: v.to(self.device) for k, v in enc.items()}

        with torch.no_grad():
            logits = self.model(**enc).logits
            probs = torch.softmax(logits, dim=1)

        results = []
        for i in range(len(request_texts)):
            prob_malicious = probs[i, 1].item()
            label = "malicious" if prob_malicious >= 0.5 else "benign"
            results.append({
                "score": prob_malicious,
                "label": label,
                "confidence": prob_malicious if label == "malicious" else (1.0 - prob_malicious),
            })
        return results
