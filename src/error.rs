//! Error types for Eyvara VRF operations.

/// Errors that can occur during Eyvara VRF operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EyvaraError {
    /// Proof structure is invalid.
    MalformedProof,
    /// Public key structure is invalid.
    MalformedPublicKey,
    /// Hint weight exceeds omega.
    HintWeightExceeded,
    /// Response norm exceeds the bound.
    NormBoundExceeded,
    /// Fiat-Shamir challenge mismatch.
    ChallengeMismatch,
    /// Output does not match the proof.
    OutputMismatch,
    /// Rejection sampling exhausted all attempts.
    RejectionSamplingFailed,
}

impl std::fmt::Display for EyvaraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedProof => write!(f, "malformed proof"),
            Self::MalformedPublicKey => write!(f, "malformed public key"),
            Self::HintWeightExceeded => write!(f, "hint weight exceeded omega"),
            Self::NormBoundExceeded => write!(f, "response norm exceeded bound"),
            Self::ChallengeMismatch => write!(f, "Fiat-Shamir challenge mismatch"),
            Self::OutputMismatch => write!(f, "VRF output does not match proof"),
            Self::RejectionSamplingFailed => {
                write!(f, "rejection sampling failed after max attempts")
            }
        }
    }
}

impl std::error::Error for EyvaraError {}
