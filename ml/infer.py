import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from ml.config import MAX_LENGTH


class WAFClassifier:
    def __init__(self, model_path: str):

        self.device = torch.device("cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.model.to(self.device)
        self.model.eval()

        self.metrics = None
        import os, json
        metrics_file = os.path.join(model_path, "metrics.json")
        if os.path.exists(metrics_file):
            try:
                with open(metrics_file, "r") as f:
                    self.metrics = json.load(f)
            except Exception:
                pass

    def predict(self, request_text: str) -> dict:
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
