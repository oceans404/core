use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
    Solana,
    Cosmos,
    Bitcoin,
    Tron,
}

impl ChainType {
    /// Returns the CAIP-2 namespace for this chain type.
    pub fn namespace(&self) -> &'static str {
        match self {
            ChainType::Evm => "eip155",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bip122",
            ChainType::Tron => "tron",
        }
    }

    /// Returns the BIP-44 coin type for this chain type.
    pub fn default_coin_type(&self) -> u32 {
        match self {
            ChainType::Evm => 60,
            ChainType::Solana => 501,
            ChainType::Cosmos => 118,
            ChainType::Bitcoin => 0,
            ChainType::Tron => 195,
        }
    }

    /// Returns the ChainType for a given CAIP-2 namespace.
    pub fn from_namespace(ns: &str) -> Option<ChainType> {
        match ns {
            "eip155" => Some(ChainType::Evm),
            "solana" => Some(ChainType::Solana),
            "cosmos" => Some(ChainType::Cosmos),
            "bip122" => Some(ChainType::Bitcoin),
            "tron" => Some(ChainType::Tron),
            _ => None,
        }
    }
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ChainType::Evm => "evm",
            ChainType::Solana => "solana",
            ChainType::Cosmos => "cosmos",
            ChainType::Bitcoin => "bitcoin",
            ChainType::Tron => "tron",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ChainType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "evm" => Ok(ChainType::Evm),
            "solana" => Ok(ChainType::Solana),
            "cosmos" => Ok(ChainType::Cosmos),
            "bitcoin" => Ok(ChainType::Bitcoin),
            "tron" => Ok(ChainType::Tron),
            _ => Err(format!("unknown chain type: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip() {
        let chain = ChainType::Evm;
        let json = serde_json::to_string(&chain).unwrap();
        assert_eq!(json, "\"evm\"");
        let chain2: ChainType = serde_json::from_str(&json).unwrap();
        assert_eq!(chain, chain2);
    }

    #[test]
    fn test_serde_all_variants() {
        for (chain, expected) in [
            (ChainType::Evm, "\"evm\""),
            (ChainType::Solana, "\"solana\""),
            (ChainType::Cosmos, "\"cosmos\""),
            (ChainType::Bitcoin, "\"bitcoin\""),
            (ChainType::Tron, "\"tron\""),
        ] {
            let json = serde_json::to_string(&chain).unwrap();
            assert_eq!(json, expected);
            let deserialized: ChainType = serde_json::from_str(&json).unwrap();
            assert_eq!(chain, deserialized);
        }
    }

    #[test]
    fn test_namespace_mapping() {
        assert_eq!(ChainType::Evm.namespace(), "eip155");
        assert_eq!(ChainType::Solana.namespace(), "solana");
        assert_eq!(ChainType::Cosmos.namespace(), "cosmos");
        assert_eq!(ChainType::Bitcoin.namespace(), "bip122");
        assert_eq!(ChainType::Tron.namespace(), "tron");
    }

    #[test]
    fn test_coin_type_mapping() {
        assert_eq!(ChainType::Evm.default_coin_type(), 60);
        assert_eq!(ChainType::Solana.default_coin_type(), 501);
        assert_eq!(ChainType::Cosmos.default_coin_type(), 118);
        assert_eq!(ChainType::Bitcoin.default_coin_type(), 0);
        assert_eq!(ChainType::Tron.default_coin_type(), 195);
    }

    #[test]
    fn test_from_namespace() {
        assert_eq!(ChainType::from_namespace("eip155"), Some(ChainType::Evm));
        assert_eq!(ChainType::from_namespace("solana"), Some(ChainType::Solana));
        assert_eq!(ChainType::from_namespace("cosmos"), Some(ChainType::Cosmos));
        assert_eq!(
            ChainType::from_namespace("bip122"),
            Some(ChainType::Bitcoin)
        );
        assert_eq!(ChainType::from_namespace("tron"), Some(ChainType::Tron));
        assert_eq!(ChainType::from_namespace("unknown"), None);
    }

    #[test]
    fn test_from_str() {
        assert_eq!("evm".parse::<ChainType>().unwrap(), ChainType::Evm);
        assert_eq!("Solana".parse::<ChainType>().unwrap(), ChainType::Solana);
        assert!("unknown".parse::<ChainType>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(ChainType::Evm.to_string(), "evm");
        assert_eq!(ChainType::Bitcoin.to_string(), "bitcoin");
    }
}
