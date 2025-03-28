use der::{
    Sequence,
    asn1::{ObjectIdentifier, OctetString},
};
use x509_cert::spki;

pub(crate) const SPC_INDIRECT_DATA_OBJID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.2.1.4");

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SpcIndirectDataContent {
    pub data: SpcAttributeTypeAndOptionalValue,
    pub message_digest: DigestInfo,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct SpcAttributeTypeAndOptionalValue {
    pub value_type: ObjectIdentifier,
    pub value: der::Any,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub(crate) struct DigestInfo {
    pub digest_algorithm: spki::AlgorithmIdentifierOwned,
    pub digest: OctetString,
}
