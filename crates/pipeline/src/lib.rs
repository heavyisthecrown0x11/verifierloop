//! Pipeline stages for one period. Each stage is a separate module with a typed
//! input/output interface and a TODO body — NO stage logic is implemented here.
//!
//! Data flow (see README):
//!   ingest -> normalize -> score -> diff -> report -> (feeds the next period)
//!
//! STAGE-BOUNDARY RULE (do not violate): every tool's DEFAULT-mode native output
//! is collected UNCHANGED in `ingest`; all shaping happens later in `normalize`,
//! never at the source.

pub mod ingest;
pub mod normalize;
pub mod verifier_log;
pub mod score;
pub mod diff;
pub mod report;
pub mod groundtruth;
