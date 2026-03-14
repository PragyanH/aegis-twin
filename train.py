"""
train.py — Train the LSTM Autoencoder on recorded normal traffic.
Run with: python train.py
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from model import LSTMAutoencoder

WINDOW_SIZE = 10
EPOCHS      = 50
BATCH_SIZE  = 32
LR          = 0.001
DATA_FILE   = "normal_traffic.csv"
MODEL_FILE  = "aegis_model.pth"

def make_sequences(data: np.ndarray, window: int):
    sequences = []
    for i in range(len(data) - window):
        sequences.append(data[i:i+window])
    return np.array(sequences)

def train():
    print(f"Loading data from {DATA_FILE}...")
    df = pd.read_csv(DATA_FILE)

    # Expect columns: pkt_size, iat, entropy, symmetry
    features = df[["pkt_size", "iat", "entropy", "symmetry"]].values.astype(np.float32)
    print(f"Loaded {len(features)} samples")

    sequences = make_sequences(features, WINDOW_SIZE)
    print(f"Created {len(sequences)} sequences of length {WINDOW_SIZE}")

    tensor = torch.tensor(sequences, dtype=torch.float32)
    dataset = TensorDataset(tensor)
    loader  = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    model     = LSTMAutoencoder()
    optimizer = torch.optim.Adam(model.parameters(), lr=LR)
    criterion = nn.MSELoss()

    model.train()
    print(f"Training for {EPOCHS} epochs...")
    for epoch in range(EPOCHS):
        total_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            output = model(batch)
            loss   = criterion(output, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        avg = total_loss / len(loader)
        print(f"Epoch {epoch+1}/{EPOCHS}  loss={avg:.6f}")

    torch.save(model.state_dict(), MODEL_FILE)
    print(f"Model saved to {MODEL_FILE}")

if __name__ == "__main__":
    train()
