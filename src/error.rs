//! Error types for Eyvara VRF operations.

/// Errors that can occur during Eyvara VRF operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EyvaraError {
    /// A proof field has an unexpected length or structure.
    MalformedProof,
    /// The public key has an unexpected structure.
    MalformedPublicKey,
    /// The hint weight exceeds the allowed maximum.
    HintWeightExceeded,
    /// The response norm exceeds the allowed bound.
    NormBoundExceeded,
    /// The Fiat-Shamir challenge did not match.
    ChallengeMismatch,
    /// The VRF output did not match the proof commitment.
    OutputMismatch,
    /// Key generation or evaluation exhausted the maximum number of
    /// rejection sampling attempts without producing a valid proof.
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
