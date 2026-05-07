"""
Aegis-Twin · Digital Twin Core
================================
LSTMAutoencoder — learns the "normal" behaviour of network traffic.
Anomalies are detected at inference time by measuring how poorly
the model can reconstruct an unseen sequence (high MSE ≈ anomaly).

Input features (per packet, 4 total):
  0 – Packet Size       (bytes)
  1 – IAT               (Inter-Arrival Time, seconds)
  2 – Payload Entropy   (bits)
  3 – Flow Symmetry     (ratio, 0-1)

Sequence length : 10 packets per window
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


# ── Constants ────────────────────────────────────────────────────────────────

INPUT_FEATURES  = 4   # Packet Size, IAT, Payload Entropy, Flow Symmetry
SEQ_LEN         = 10  # packets per sliding window
HIDDEN_SIZE     = 64  # encoder hidden dimension
LATENT_SIZE     = 32  # bottleneck / latent dimension
NUM_LAYERS      = 2   # stacked LSTM layers
DROPOUT         = 0.2 # regularisation (active only when num_layers > 1)


# ── Encoder ──────────────────────────────────────────────────────────────────

class Encoder(nn.Module):
    """
    Compresses a packet-sequence into a fixed-size latent vector.

    Architecture:
        LSTM(input_size → hidden_size, num_layers)  →  Linear(hidden → latent)

    Args:
        input_size  (int): number of features per time-step  (default 4)
        hidden_size (int): LSTM hidden dimension              (default 64)
        latent_size (int): bottleneck representation size     (default 32)
        num_layers  (int): stacked LSTM depth                 (default 2)
        dropout     (float): dropout between LSTM layers      (default 0.2)
    """

    def __init__(
        self,
        input_size:  int   = INPUT_FEATURES,
        hidden_size: int   = HIDDEN_SIZE,
        latent_size: int   = LATENT_SIZE,
        num_layers:  int   = NUM_LAYERS,
        dropout:     float = DROPOUT,
    ) -> None:
        super().__init__()

        self.lstm = nn.LSTM(
            input_size  = input_size,
            hidden_size = hidden_size,
            num_layers  = num_layers,
            batch_first = True,          # (batch, seq, feature)
            dropout     = dropout if num_layers > 1 else 0.0,
        )

        # Project the final hidden state to the latent space
        self.fc = nn.Linear(hidden_size, latent_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (batch, seq_len, input_size)

        Returns:
            z: (batch, latent_size)  — compressed latent representation
        """
        _, (h_n, _) = self.lstm(x)   # h_n: (num_layers, batch, hidden)
        # Take the last layer's hidden state
        last_hidden  = h_n[-1]        # (batch, hidden)
        z            = self.fc(last_hidden)        # (batch, latent)
        return z


# ── Decoder ──────────────────────────────────────────────────────────────────

class Decoder(nn.Module):
    """
    Reconstructs the full packet-sequence from a latent vector.

    Architecture:
        Linear(latent → hidden)  →  repeat seq_len times  →
        LSTM(hidden → hidden, num_layers)  →  Linear(hidden → input_size)

    Args:
        latent_size (int): bottleneck input size         (default 32)
        hidden_size (int): LSTM hidden dimension         (default 64)
        output_size (int): features to reconstruct       (default 4)
        seq_len     (int): output sequence length        (default 10)
        num_layers  (int): stacked LSTM depth            (default 2)
        dropout     (float): dropout between LSTM layers (default 0.2)
    """

    def __init__(
        self,
        latent_size: int   = LATENT_SIZE,
        hidden_size: int   = HIDDEN_SIZE,
        output_size: int   = INPUT_FEATURES,
        seq_len:     int   = SEQ_LEN,
        num_layers:  int   = NUM_LAYERS,
        dropout:     float = DROPOUT,
    ) -> None:
        super().__init__()

        self.seq_len    = seq_len
        self.hidden_size = hidden_size
        self.num_layers  = num_layers

        # Expand latent vector back to LSTM input size
        self.fc_in = nn.Linear(latent_size, hidden_size)

        self.lstm = nn.LSTM(
            input_size  = hidden_size,
            hidden_size = hidden_size,
            num_layers  = num_layers,
            batch_first = True,
            dropout     = dropout if num_layers > 1 else 0.0,
        )

        # Project each LSTM output step to the original feature space
        self.fc_out = nn.Linear(hidden_size, output_size)

    def forward(self, z: torch.Tensor) -> torch.Tensor:
        """
        Args:
            z: (batch, latent_size)

        Returns:
            x_hat: (batch, seq_len, output_size)  — reconstructed sequence
        """
        # Expand latent vector and repeat across the sequence axis
        h = self.fc_in(z)                          # (batch, hidden)
        h = h.unsqueeze(1).repeat(1, self.seq_len, 1)  # (batch, seq, hidden)

        out, _ = self.lstm(h)                      # (batch, seq, hidden)
        x_hat  = self.fc_out(out)                  # (batch, seq, output_size)
        return x_hat


# ── LSTMAutoencoder (Digital Twin) ───────────────────────────────────────────

class LSTMAutoencoder(nn.Module):
    """
    Aegis-Twin Digital Twin — LSTM-based Autoencoder for network traffic.

    The model is trained exclusively on **normal** traffic so that it learns
    a compact internal representation of benign behaviour.  At inference
    time, anomalous traffic produces a high reconstruction error (MSE),
    which is used as an anomaly score.

    Hyperparameters
    ---------------
    input_size  : 4    (Packet Size, IAT, Payload Entropy, Flow Symmetry)
    seq_len     : 10   (sliding window of 10 consecutive packets)
    hidden_size : 64
    latent_size : 32   (bottleneck dimension)
    num_layers  : 2    (stacked LSTM)
    dropout     : 0.2

    Usage
    -----
    >>> model = LSTMAutoencoder()
    >>> x     = torch.randn(32, 10, 4)   # (batch=32, seq=10, features=4)
    >>> x_hat = model(x)                 # (32, 10, 4)
    >>> error = model.reconstruction_error(x)   # (32,) per-sample MSE
    """

    def __init__(
        self,
        input_size:  int   = INPUT_FEATURES,
        seq_len:     int   = SEQ_LEN,
        hidden_size: int   = HIDDEN_SIZE,
        latent_size: int   = LATENT_SIZE,
        num_layers:  int   = NUM_LAYERS,
        dropout:     float = DROPOUT,
    ) -> None:
        super().__init__()

        self.input_size  = input_size
        self.seq_len     = seq_len
        self.hidden_size = hidden_size
        self.latent_size = latent_size

        self.encoder = Encoder(
            input_size  = input_size,
            hidden_size = hidden_size,
            latent_size = latent_size,
            num_layers  = num_layers,
            dropout     = dropout,
        )

        self.decoder = Decoder(
            latent_size = latent_size,
            hidden_size = hidden_size,
            output_size = input_size,
            seq_len     = seq_len,
            num_layers  = num_layers,
            dropout     = dropout,
        )

    # ── Forward pass ─────────────────────────────────────────────────────────

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Encode then decode a batch of packet-window sequences.

        Args:
            x (Tensor): shape (batch, seq_len, input_size)

        Returns:
            x_hat (Tensor): reconstructed sequences, same shape as x
        """
        z     = self.encoder(x)   # compress   → (batch, latent)
        x_hat = self.decoder(z)   # reconstruct → (batch, seq, features)
        return x_hat

    # ── Reconstruction error (anomaly score) ─────────────────────────────────

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        Compute the per-sample Mean Squared Error between the input and its
        reconstruction.  A higher score indicates a more anomalous sequence.

        Args:
            x (Tensor): shape (batch, seq_len, input_size)

        Returns:
            mse (Tensor): shape (batch,) — one MSE value per sample
                          (mean over both the time and feature dimensions)

        Example:
            >>> model.eval()
            >>> with torch.no_grad():
            ...     scores = model.reconstruction_error(x)
            >>> threshold = 0.05   # tune on validation set
            >>> anomalies = scores > threshold
        """
        with torch.no_grad():
            x_hat = self.forward(x)                   # (batch, seq, features)

        # MSE per sample: mean over seq_len and input_size dimensions
        mse = F.mse_loss(x_hat, x, reduction="none")  # (batch, seq, features)
        mse = mse.mean(dim=[1, 2])                     # (batch,)
        return mse

    # ── Utility ──────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        enc_params = sum(p.numel() for p in self.encoder.parameters())
        dec_params = sum(p.numel() for p in self.decoder.parameters())
        total      = enc_params + dec_params
        return (
            f"LSTMAutoencoder(\n"
            f"  input_size  = {self.input_size}  "
            f"[Packet Size | IAT | Payload Entropy | Flow Symmetry]\n"
            f"  seq_len     = {self.seq_len}\n"
            f"  hidden_size = {self.hidden_size}\n"
            f"  latent_size = {self.latent_size}\n"
            f"  encoder params = {enc_params:,}\n"
            f"  decoder params = {dec_params:,}\n"
            f"  total params   = {total:,}\n"
            f")"
        )


# ── Model Test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 1. Create a fake network packet sequence: 1 sample, 10 packets, 4 features
    #    Features: Packet Size | IAT | Payload Entropy | Flow Symmetry
    fake_data = torch.randn(1, SEQ_LEN, INPUT_FEATURES)
    print(f"Input sequence shape : {tuple(fake_data.shape)}")
    print(f"  (batch=1, seq_len={SEQ_LEN}, features={INPUT_FEATURES})\n")

    # 2. Initialise the LSTMAutoencoder (Digital Twin)
    model = LSTMAutoencoder()
    model.eval()

    # 3. Forward pass — get the reconstructed output
    with torch.no_grad():
        reconstructed = model(fake_data)
    print(f"Reconstructed shape  : {tuple(reconstructed.shape)}\n")

    # 4. Calculate Reconstruction Error (Mean Squared Error)
    mse_loss = F.mse_loss(reconstructed, fake_data)
    print(f"Reconstruction Error (MSE) : {mse_loss.item():.6f}")

    print("\nModel Test Successful!")
