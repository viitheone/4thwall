"""
Training script for WAF classifier.
Loads dataset, tokenizes, fine-tunes DistilBERT, saves best model by validation F1.
No online training or model updates after saving.
"""

import argparse
import contextlib
import io
import os

import numpy as np
import torch
from datasets import Dataset
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)

from ml.config import (
    BATCH_SIZE,
    LEARNING_RATE,
    MAX_LENGTH,
    MODEL_NAME,
    MODEL_SAVE_PATH,
    NUM_EPOCHS,
    TRAIN_SPLIT,
)
from ml.dataset_loader import create_train_val_split, load_and_preprocess_dataset


def compute_metrics(preds, labels):
    """Precision, recall, F1, confusion matrix."""
    preds_np = np.argmax(preds, axis=1)
    precision = precision_score(labels, preds_np, zero_division=0)
    recall = recall_score(labels, preds_np, zero_division=0)
    f1 = f1_score(labels, preds_np, zero_division=0)
    cm = confusion_matrix(labels, preds_np)
    return {"precision": precision, "recall": recall, "f1": f1, "confusion_matrix": cm.tolist()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_path", required=True, help="Path to training CSV")
    parser.add_argument("--output_dir", default=None, help="Model save path (default from config)")
    parser.add_argument("--epochs", type=int, default=None, help="Number of epochs (default from config)")
    args = parser.parse_args()

    output_dir = args.output_dir or MODEL_SAVE_PATH
    num_epochs = args.epochs if args.epochs is not None else NUM_EPOCHS

    os.makedirs(output_dir, exist_ok=True)

    texts, labels = load_and_preprocess_dataset(args.data_path)
    train_texts, val_texts, train_labels, val_labels = create_train_val_split(
        texts, labels, split_ratio=TRAIN_SPLIT
    )

    train_dataset = Dataset.from_dict({"text": train_texts, "label": train_labels})
    val_dataset = Dataset.from_dict({"text": val_texts, "label": val_labels})

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
            return_tensors=None,
        )

    train_dataset = train_dataset.map(tokenize_fn, batched=True, remove_columns=["text"])
    val_dataset = val_dataset.map(tokenize_fn, batched=True, remove_columns=["text"])
    train_dataset.set_format("torch")
    val_dataset.set_format("torch")

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE)

    num_labels = 2
    with contextlib.redirect_stderr(io.StringIO()):
        model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=num_labels)

    class_counts = np.bincount(train_labels)
    class_weights = torch.tensor(
        1.0 / (class_counts + 1e-6), dtype=torch.float32
    )
    class_weights = class_weights / class_weights.sum() * num_labels

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\nUsing device: {device}")
    model.to(device)
    class_weights = class_weights.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=LEARNING_RATE)
    total_steps = len(train_loader) * num_epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)

    best_f1 = 0.0

    for epoch in range(num_epochs):
        model.train()
        train_loss = 0.0

        print(f"\nStarting Epoch {epoch + 1}/{num_epochs}")
        progress_bar = tqdm(train_loader, desc=f"Epoch {epoch+1}")

        for step, batch in enumerate(progress_bar):
            batch = {k: v.to(device) for k, v in batch.items()}
            labels_batch = batch["label"]
            inputs = {k: v for k, v in batch.items() if k != "label"}

            outputs = model(**inputs)
            loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights)
            loss = loss_fn(outputs.logits, labels_batch)

            train_loss += loss.item()
            loss.backward()
            optimizer.step()
            scheduler.step()
            optimizer.zero_grad()

            progress_bar.set_postfix(loss=loss.item())

        # Validation
        model.eval()
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch in val_loader:
                batch = {k: v.to(device) for k, v in batch.items()}
                labels_batch = batch["label"]
                inputs = {k: v for k, v in batch.items() if k != "label"}
                outputs = model(**inputs)
                all_preds.append(outputs.logits.cpu().numpy())
                all_labels.append(labels_batch.cpu().numpy())

        preds = np.concatenate(all_preds, axis=0)
        labels_np = np.concatenate(all_labels, axis=0)
        metrics = compute_metrics(preds, labels_np)

        print(f"\nEpoch {epoch + 1}/{num_epochs} - train_loss: {train_loss / len(train_loader):.4f}")
        print(f"  val precision: {metrics['precision']:.4f}, recall: {metrics['recall']:.4f}, f1: {metrics['f1']:.4f}")
        print(f"  confusion_matrix: {metrics['confusion_matrix']}")

        if metrics["f1"] > best_f1:
            best_f1 = metrics["f1"]
            model.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)
            
            import json
            cm = metrics["confusion_matrix"]
            acc = (cm[0][0] + cm[1][1]) / max(sum(sum(row) for row in cm), 1)
            metrics_dict = {
                "accuracy": acc,
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"]
            }
            with open(os.path.join(output_dir, "metrics.json"), "w") as f:
                json.dump(metrics_dict, f)
            print(f"  -> Saved best model (F1={best_f1:.4f}) and metrics to {output_dir}")

    print("\nTraining complete.")


if __name__ == "__main__":
    main()
