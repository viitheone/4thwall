"""WAF ML configuration - fixed parameters."""

MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 512
BATCH_SIZE = 16
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3
TRAIN_SPLIT = 0.8
ML_THRESHOLD_BLOCK = 0.9
ML_THRESHOLD_ALERT = 0.6
MODEL_SAVE_PATH = "./models/waf_model"
