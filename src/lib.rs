#[cfg(feature = "zkvm")]
mod zkvm_impl;
#[cfg(feature = "zkvm")]
pub use zkvm_impl::hash_fixed;

#[cfg(not(feature = "zkvm"))]
mod dynamic_impl;
#[cfg(not(feature = "zkvm"))]
pub use dynamic_impl::hash_fixed;
