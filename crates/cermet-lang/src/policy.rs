//! Keyless contract lookup used while authoring sentence rules.

use crate::contract::ActionContract;

pub trait ContractSource {
    fn contract(&self, provider: &str, action: &str) -> Option<&'static ActionContract>;
}

pub struct DefaultContractSource;

impl ContractSource for DefaultContractSource {
    fn contract(&self, provider: &str, action: &str) -> Option<&'static ActionContract> {
        crate::templates::vendored_contract(provider, action)
    }
}
