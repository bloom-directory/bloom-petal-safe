//! Safe smart-account protocol implementation for Bloom.

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address, B256, Signature, U256, keccak256};
use alloy_sol_types::{SolCall, sol};
use petal::{
    DispatchResponse, HostStatus, HttpRequest, PayloadSignRequest, SdkError, SignOutcome,
    SignSelector,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub use serde_json;

const MAX_BODY: usize = 256 * 1024;
const ZERO: &str = "0x0000000000000000000000000000000000000000";
const SENTINEL: &str = "0x0000000000000000000000000000000000000001";
const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";
const DOMAIN_TYPE: &str = "EIP712Domain(uint256 chainId,address verifyingContract)";

sol! {
    function VERSION() external view returns (string);
    function getOwners() external view returns (address[]);
    function getThreshold() external view returns (uint256);
    function nonce() external view returns (uint256);
    function getGuard() external view returns (address);
    function getModulesPaginated(address start, uint256 pageSize) external view returns (address[] array, address next);
    function getStorageAt(uint256 offset, uint256 length) external view returns (bytes);
    function multiSend(bytes transactions);
    function performCreate(uint256 value, bytes deploymentData) returns (address newContract);
    function performCreate2(uint256 value, bytes deploymentData, bytes32 salt) returns (address newContract);
    function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address payable refundReceiver, bytes signatures) returns (bool success);
    function transfer(address to, uint256 value) returns (bool);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRequest {
    pub chain: String,
    pub safe_address: String,
    #[serde(default)]
    pub transaction_service: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafeSnapshot {
    pub chain_id: String,
    pub safe_address: String,
    pub safe_version: String,
    pub singleton: String,
    pub singleton_code_hash: String,
    pub owners: Vec<String>,
    pub threshold: String,
    pub nonce: String,
    pub guard: String,
    pub modules: Vec<String>,
    pub fallback_handler: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub schema: String,
    pub wallet: String,
    pub owner: String,
    pub chain: String,
    pub safe: SafeSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_service: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub to: String,
    #[serde(default = "zero_string")]
    pub value: String,
    #[serde(default = "empty_hex")]
    pub data: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransactionBuilderFile {
    #[serde(default)]
    pub version: Option<String>,
    pub chain_id: String,
    #[serde(default)]
    pub created_at: Option<u64>,
    #[serde(default)]
    pub meta: Option<Value>,
    pub transactions: Vec<BuilderTransaction>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuilderTransaction {
    pub to: String,
    pub value: String,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub contract_method: Option<BuilderMethod>,
    #[serde(default)]
    pub contract_inputs_values: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderMethod {
    pub inputs: Vec<BuilderInput>,
    pub name: String,
    pub payable: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuilderInput {
    #[serde(default)]
    pub internal_type: Option<String>,
    pub name: String,
    #[serde(rename = "type")]
    pub sol_type: String,
    #[serde(default)]
    pub components: Vec<BuilderInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TransactionRequest {
    Call(Call),
    NativeTransfer {
        to: String,
        value: String,
    },
    Erc20Transfer {
        token: String,
        to: String,
        amount: String,
    },
    Batch {
        calls: Vec<Call>,
    },
    TransactionBuilder {
        builder: TransactionBuilderFile,
    },
    Create {
        value: String,
        initcode: String,
    },
    Create2 {
        value: String,
        initcode: String,
        salt: String,
    },
    Rejection,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SafeTx {
    pub to: String,
    pub value: String,
    pub data: String,
    pub operation: u8,
    pub safe_tx_gas: String,
    pub base_gas: String,
    pub gas_price: String,
    pub gas_token: String,
    pub refund_receiver: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEnvelope {
    pub schema: String,
    pub chain_id: String,
    pub safe_address: String,
    pub safe_version: String,
    pub singleton: String,
    pub singleton_code_hash: String,
    pub owner: String,
    pub owners: Vec<String>,
    pub threshold: String,
    pub guard: String,
    pub modules: Vec<String>,
    pub fallback_handler: String,
    pub safe_tx: SafeTx,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_code_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionState {
    pub schema: String,
    pub wallet: String,
    pub safe_id: String,
    pub id: String,
    pub request: TransactionRequest,
    pub snapshot: SafeSnapshot,
    pub safe_tx: SafeTx,
    pub safe_tx_hash: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_wallet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_code_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub executor_wallet: String,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default)]
    pub nonce: Option<u64>,
    #[serde(default)]
    pub max_fee_per_gas: Option<String>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<String>,
}

#[derive(Clone, Copy)]
struct Library {
    address: &'static str,
    code_hash: &'static str,
}

const MULTISEND_130: &[Library] = &[
    Library {
        address: "0x40a2accbd92bca938b02010e17a5b8929b49130d",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
    Library {
        address: "0xa1dabef33b3b82c7814b6d82a79e50f4ac44102b",
        code_hash: "0xa9865ac2d9c7a1591619b188c4d88167b50df6cc0c5327fcbd1c8c75f7c066ad",
    },
];
const CREATE_130: &[Library] = &[
    Library {
        address: "0x7cbb62eaa69f79e6873cd1ecb2392971036cfaa4",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
    Library {
        address: "0xb19d6ffc2182150f8eb585b79d4abcd7c5640a9d",
        code_hash: "0x8155d988823a4f6f1bcbc76a64af8e510c4ce68819290d43cf24956bd24dee82",
    },
];
const MULTISEND_141: &[Library] = &[Library {
    address: "0x9641d764fc13c8b624c04430c7356c1c7c8102e2",
    code_hash: "0xecd5bd14a08c5d2122379900b2f272bdf107a7e92423c10dd5fe3254386c9939",
}];
const CREATE_141: &[Library] = &[Library {
    address: "0x9b35af71d77eaf8d7e40252370304687390a1a52",
    code_hash: "0x2b3060c55fcb8275653e99ad511a71f67ba76934ed66a7d74d6e68b52afff889",
}];
const MULTISEND_150: &[Library] = &[Library {
    address: "0xa83c336b20401af773b6219ba5027174338d1836",
    code_hash: "0xcdbdcec38d2f1c7d961b0029ff8416b7e86e9974d6f0e9c9580c7d17fcfb6663",
}];
const CREATE_150: &[Library] = &[Library {
    address: "0x2ef5ecfbea521449e4de05edb1ce63b75eda90b4",
    code_hash: "0x6b7d8d29bdf7004c4617d95041923774f3f7e74b056bff55c1861c9ec92ce54f",
}];

fn libraries(version: &str) -> Option<(&'static [Library], &'static [Library])> {
    match version {
        "1.3.0" => Some((MULTISEND_130, CREATE_130)),
        "1.4.1" => Some((MULTISEND_141, CREATE_141)),
        "1.5.0" => Some((MULTISEND_150, CREATE_150)),
        _ => None,
    }
}

fn singleton_supported(version: &str, address: &str, hash: &str) -> bool {
    [
        (
            "1.3.0",
            "0xd9db270c1b5e3bd161e8c8503c55ceabee709552",
            "0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e",
        ),
        (
            "1.3.0",
            "0x69f4d1788e39c87893c980c06edf4b7f686e2938",
            "0xbba688fbdb21ad2bb58bc320638b43d94e7d100f6f3ebaab0a4e4de6304b1c2e",
        ),
        (
            "1.3.0",
            "0x3e5c63644e683549055b9be8653de26e0b4cd36e",
            "0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f",
        ),
        (
            "1.3.0",
            "0xfb1bffc9d739b8d520daf37df666da4c687191ea",
            "0x21842597390c4c6e3c1239e434a682b054bd9548eee5e9b1d6a4482731023c0f",
        ),
        (
            "1.4.1",
            "0x41675c099f32341bf84bfc5382af534df5c7461a",
            "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4",
        ),
        (
            "1.4.1",
            "0x29fcb43b46531bca003ddc8fcb67ffe91900c762",
            "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
        ),
        (
            "1.5.0",
            "0xff51a5898e281db6dfc7855790607438df2ca44b",
            "0xdda019cbd7c867a533a2a86e5c53434fdc50b13122b5a5ddb4a8df61b31c20f2",
        ),
        (
            "1.5.0",
            "0xedd160febbd92e350d4d398fb636302fccd67c7e",
            "0x180193227186ccb85316c94db1f0d156ed932b14712cfaac78901899178572dc",
        ),
    ]
    .contains(&(version, address, hash))
}

fn zero_string() -> String {
    "0".into()
}
fn empty_hex() -> String {
    "0x".into()
}
fn invalid(message: impl Into<String>) -> DispatchResponse {
    petal::error(-3, message)
}
fn denied(message: impl Into<String>) -> DispatchResponse {
    petal::error(-2, message)
}
fn backend(message: impl Into<String>) -> DispatchResponse {
    petal::error(-4, message)
}
fn sdk_error(error: SdkError) -> DispatchResponse {
    match error {
        SdkError::Host(HostStatus::Denied) => denied("operation denied by Bloom"),
        error => backend(error.message()),
    }
}

fn safe_segment(value: &str, field: &str) -> Result<(), DispatchResponse> {
    if value.len() > 128 || !petal::is_safe_segment(value) {
        return Err(invalid(format!("{field} is unsafe")));
    }
    Ok(())
}

fn address(value: &str, field: &str) -> Result<Address, DispatchResponse> {
    Address::from_str(value).map_err(|_| invalid(format!("{field} must be an EVM address")))
}

fn normalized_address(value: &str, field: &str) -> Result<String, DispatchResponse> {
    Ok(format!("{:#x}", address(value, field)?))
}

fn uint(value: &str, field: &str) -> Result<U256, DispatchResponse> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid(format!(
            "{field} must be a canonical decimal integer"
        )));
    }
    U256::from_str(value).map_err(|_| invalid(format!("{field} is too large")))
}

fn hex_bytes(value: &str, field: &str) -> Result<Vec<u8>, DispatchResponse> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| invalid(format!("{field} must be 0x-prefixed hex")))?;
    if raw.len() % 2 != 0 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid(format!("{field} is invalid hex")));
    }
    let bytes = hex::decode(raw).map_err(|_| invalid(format!("{field} is invalid hex")))?;
    if bytes.len() > 128 * 1024 {
        return Err(invalid(format!("{field} is too large")));
    }
    Ok(bytes)
}

fn builder_type(input: &BuilderInput) -> Result<DynSolType, DispatchResponse> {
    let canonical = if let Some(suffix) = input.sol_type.strip_prefix("tuple") {
        let components = input
            .components
            .iter()
            .map(builder_type)
            .collect::<Result<Vec<_>, _>>()?;
        format!(
            "({}){suffix}",
            components
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    } else {
        if !input.components.is_empty() {
            return Err(invalid(
                "Transaction Builder components are allowed only for tuple inputs",
            ));
        }
        input.sol_type.clone()
    };
    DynSolType::parse(&canonical).map_err(|e| {
        invalid(format!(
            "invalid Transaction Builder ABI type {canonical}: {e}"
        ))
    })
}

fn json_coercion(value: &Value, ty: &DynSolType) -> Option<String> {
    match ty {
        DynSolType::Tuple(types) => {
            let values = value.as_array()?;
            if values.len() != types.len() {
                return None;
            }
            Some(format!(
                "({})",
                values
                    .iter()
                    .zip(types)
                    .map(|(value, ty)| json_coercion(value, ty))
                    .collect::<Option<Vec<_>>>()?
                    .join(",")
            ))
        }
        DynSolType::Array(ty) | DynSolType::FixedArray(ty, _) => Some(format!(
            "[{}]",
            value
                .as_array()?
                .iter()
                .map(|value| json_coercion(value, ty))
                .collect::<Option<Vec<_>>>()?
                .join(",")
        )),
        DynSolType::Bool => match value {
            Value::Bool(value) => Some(value.to_string()),
            Value::Number(value) if value.as_u64() == Some(0) => Some("false".into()),
            Value::Number(value) if value.as_u64() == Some(1) => Some("true".into()),
            Value::String(value) if value.eq_ignore_ascii_case("true") || value == "1" => {
                Some("true".into())
            }
            Value::String(value) if value.eq_ignore_ascii_case("false") || value == "0" => {
                Some("false".into())
            }
            _ => None,
        },
        DynSolType::String => value
            .as_str()
            .filter(|value| !value.contains('"') && !value.contains('\\'))
            .map(|value| format!("\"{value}\"")),
        _ => match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        },
    }
}

fn coerce_builder_value(ty: &DynSolType, raw: &str) -> Result<DynSolValue, String> {
    match ty.coerce_str(raw) {
        Ok(value) => Ok(value),
        Err(original) => {
            let value: Value = serde_json::from_str(raw).map_err(|_| original.to_string())?;
            let normalized = json_coercion(&value, ty).ok_or_else(|| original.to_string())?;
            ty.coerce_str(&normalized)
                .map_err(|error| error.to_string())
        }
    }
}

fn encode_builder_method(
    method: &BuilderMethod,
    fields: Option<&BTreeMap<String, String>>,
) -> Result<Vec<u8>, DispatchResponse> {
    if method.inputs.len() > 64 {
        return Err(invalid("Transaction Builder method has too many inputs"));
    }
    if method.name.is_empty()
        || matches!(method.name.as_str(), "receive" | "fallback")
        || !method
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(invalid("Transaction Builder method name is invalid"));
    }
    let empty = BTreeMap::new();
    let fields = fields.unwrap_or(&empty);
    let mut used = BTreeSet::new();
    let mut types = Vec::with_capacity(method.inputs.len());
    let mut values = Vec::with_capacity(method.inputs.len());
    for (index, input) in method.inputs.iter().enumerate() {
        let key = if input.name.is_empty() {
            index.to_string()
        } else {
            input.name.clone()
        };
        let raw = fields
            .get(&key)
            .ok_or_else(|| invalid(format!("Transaction Builder input {key} is missing")))?;
        let ty = builder_type(input)?;
        let value = coerce_builder_value(&ty, raw).map_err(|e| {
            invalid(format!(
                "Transaction Builder input {key} does not match {ty}: {e}"
            ))
        })?;
        used.insert(key);
        types.push(ty);
        values.push(value);
    }
    if fields.keys().any(|key| !used.contains(key)) {
        return Err(invalid(
            "Transaction Builder contains an input value not declared by contractMethod",
        ));
    }
    let signature = format!(
        "{}({})",
        method.name,
        types
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut data = keccak256(signature).as_slice()[..4].to_vec();
    data.extend_from_slice(&DynSolValue::Tuple(values).abi_encode_params());
    Ok(data)
}

fn wallet_address(wallet: &str) -> Result<String, DispatchResponse> {
    let bytes =
        petal::sdk::vfs_read(&format!("wallets/{wallet}/address"), 128).map_err(sdk_error)?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| backend("wallet address is not UTF-8"))?
        .trim();
    normalized_address(value, "wallet address")
}

fn binding_key(wallet: &str, safe_id: &str) -> String {
    format!("state/safes/{wallet}/{safe_id}.json")
}
fn tx_key(wallet: &str, id: &str) -> String {
    format!("state/transactions/{wallet}/{id}.json")
}
fn api_key_key(wallet: &str, safe_id: &str) -> String {
    format!("secrets/services/{wallet}/{safe_id}.txt")
}

fn load<T: for<'de> Deserialize<'de>>(key: &str, label: &str) -> Result<T, DispatchResponse> {
    let bytes = petal::sdk::store_get(key, MAX_BODY).map_err(sdk_error)?;
    serde_json::from_slice(&bytes).map_err(|e| backend(format!("stored {label} is invalid: {e}")))
}
fn save<T: Serialize>(key: &str, value: &T) -> Result<(), DispatchResponse> {
    let bytes = serde_json::to_vec(value).map_err(|e| backend(e.to_string()))?;
    petal::sdk::store_put(key, &bytes, false).map_err(sdk_error)
}
fn save_new<T: Serialize>(key: &str, value: &T) -> Result<(), DispatchResponse> {
    let bytes = serde_json::to_vec(value).map_err(|e| backend(e.to_string()))?;
    petal::sdk::store_put_new(key, &bytes, false).map_err(sdk_error)
}

fn chain_result(chain: &str, method: &str, params: Value) -> Result<Value, DispatchResponse> {
    let raw = petal::sdk::chain_read(chain, method, &serde_json::to_string(&params).unwrap())
        .map_err(sdk_error)?;
    serde_json::from_str(&raw).map_err(|e| backend(format!("{method} returned invalid JSON: {e}")))
}

fn rpc_hex(chain: &str, method: &str, params: Value) -> Result<Vec<u8>, DispatchResponse> {
    let value = chain_result(chain, method, params)?;
    let value = value
        .as_str()
        .ok_or_else(|| backend(format!("{method} did not return hex")))?;
    hex_bytes(value, method)
}

fn call(chain: &str, to: &str, data: Vec<u8>) -> Result<Vec<u8>, DispatchResponse> {
    rpc_hex(
        chain,
        "eth_call",
        json!([{"to":to,"data":format!("0x{}",hex::encode(data))},"latest"]),
    )
}

fn storage_word(chain: &str, safe: &str, slot: U256) -> Result<Vec<u8>, DispatchResponse> {
    let result = call(
        chain,
        safe,
        getStorageAtCall {
            offset: slot,
            length: U256::from(32),
        }
        .abi_encode(),
    )?;
    Ok(getStorageAtCall::abi_decode_returns(&result)
        .map_err(|e| backend(format!("decode Safe storage: {e}")))?
        .to_vec())
}

fn fallback_slot() -> U256 {
    U256::from_be_bytes(keccak256("fallback_manager.handler.address").0).wrapping_sub(U256::from(1))
}

fn inspect(chain: &str, safe: &str) -> Result<SafeSnapshot, DispatchResponse> {
    let safe = normalized_address(safe, "safe_address")?;
    let code = rpc_hex(chain, "eth_getCode", json!([safe, "latest"]))?;
    if code.is_empty() {
        return Err(invalid("Safe address has no code"));
    }
    let chain_id_value = chain_result(chain, "eth_chainId", json!([]))?;
    let chain_hex = chain_id_value
        .as_str()
        .ok_or_else(|| backend("eth_chainId did not return hex"))?;
    let chain_id = u64::from_str_radix(chain_hex.trim_start_matches("0x"), 16)
        .map_err(|_| backend("invalid chain ID"))?;
    if chain_id == 0 {
        return Err(invalid("chain ID must be nonzero"));
    }
    let version_result = call(chain, &safe, VERSIONCall {}.abi_encode())?;
    let version = VERSIONCall::abi_decode_returns(&version_result)
        .map_err(|e| invalid(format!("address is not a supported Safe: {e}")))?;
    if libraries(&version).is_none() {
        return Err(invalid(format!("Safe version {version} is unsupported")));
    }
    let owners_result = call(chain, &safe, getOwnersCall {}.abi_encode())?;
    let owners = getOwnersCall::abi_decode_returns(&owners_result)
        .map_err(|e| backend(format!("decode owners: {e}")))?
        .into_iter()
        .map(|a| format!("{a:#x}"))
        .collect::<Vec<_>>();
    if owners.is_empty() || owners.len() > 64 {
        return Err(invalid("Safe owner count is unsupported"));
    }
    let threshold_result = call(chain, &safe, getThresholdCall {}.abi_encode())?;
    let threshold = getThresholdCall::abi_decode_returns(&threshold_result)
        .map_err(|e| backend(format!("decode threshold: {e}")))?;
    if threshold == U256::ZERO || threshold > U256::from(owners.len()) {
        return Err(invalid("Safe threshold is invalid"));
    }
    let nonce_result = call(chain, &safe, nonceCall {}.abi_encode())?;
    let nonce = nonceCall::abi_decode_returns(&nonce_result)
        .map_err(|e| backend(format!("decode nonce: {e}")))?;
    let guard_result = call(chain, &safe, getGuardCall {}.abi_encode())?;
    let guard = getGuardCall::abi_decode_returns(&guard_result)
        .map_err(|e| backend(format!("decode guard: {e}")))?;
    let modules_result = call(
        chain,
        &safe,
        getModulesPaginatedCall {
            start: address(SENTINEL, "sentinel")?,
            pageSize: U256::from(64),
        }
        .abi_encode(),
    )?;
    let modules_return = getModulesPaginatedCall::abi_decode_returns(&modules_result)
        .map_err(|e| backend(format!("decode modules: {e}")))?;
    if modules_return.next != address(SENTINEL, "sentinel")? {
        return Err(invalid("Safe has more than 64 enabled modules"));
    }
    let modules = modules_return
        .array
        .into_iter()
        .map(|a| format!("{a:#x}"))
        .collect();
    let singleton_word = storage_word(chain, &safe, U256::ZERO)?;
    if singleton_word.len() != 32 {
        return Err(backend("Safe singleton storage word has wrong length"));
    }
    let singleton = Address::from_slice(&singleton_word[12..]);
    let singleton_address = format!("{singleton:#x}");
    let singleton_code = rpc_hex(chain, "eth_getCode", json!([singleton_address, "latest"]))?;
    let singleton_code_hash = format!("{:#x}", keccak256(singleton_code));
    if !singleton_supported(&version, &singleton_address, &singleton_code_hash) {
        return Err(denied(
            "Safe singleton address or runtime code is not a supported official deployment",
        ));
    }
    let fallback_word = storage_word(chain, &safe, fallback_slot())?;
    if fallback_word.len() != 32 {
        return Err(backend("Safe fallback storage word has wrong length"));
    }
    let fallback_handler = Address::from_slice(&fallback_word[12..]);
    Ok(SafeSnapshot {
        chain_id: chain_id.to_string(),
        safe_address: safe,
        safe_version: version,
        singleton: singleton_address,
        singleton_code_hash,
        owners,
        threshold: threshold.to_string(),
        nonce: nonce.to_string(),
        guard: format!("{guard:#x}"),
        modules,
        fallback_handler: format!("{fallback_handler:#x}"),
    })
}

fn validate_service(value: Option<String>) -> Result<Option<String>, DispatchResponse> {
    value
        .map(|mut value| {
            while value.ends_with('/') {
                value.pop();
            }
            let authority = value.strip_prefix("https://").unwrap_or_default();
            if authority.is_empty()
                || value.len() > 255
                || !authority.bytes().any(|byte| byte.is_ascii_alphanumeric())
                || !authority.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
                })
            {
                return Err(invalid("transaction_service must be an HTTPS origin"));
            }
            Ok(value)
        })
        .transpose()
}

pub fn bind(wallet: &str, safe_id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(safe_id, "safe id")) {
        return e;
    }
    if body.len() > 16 * 1024 {
        return invalid("binding request is too large");
    }
    let request: BindingRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return invalid(format!("invalid binding JSON: {e}")),
    };
    if !request.chain.starts_with("evm-") || request.chain.len() > 64 {
        return invalid("chain must be a configured evm-* chain");
    }
    let owner = match wallet_address(wallet) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let safe = match inspect(&request.chain, &request.safe_address) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !safe.owners.iter().any(|v| v == &owner) {
        return denied("Bloom wallet is not an owner of this Safe");
    }
    let transaction_service = match validate_service(request.transaction_service) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let binding = Binding {
        schema: "bloom.safe.binding.v1".into(),
        wallet: wallet.into(),
        owner,
        chain: request.chain,
        safe,
        transaction_service,
    };
    match save(&binding_key(wallet, safe_id), &binding) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => e,
    }
}

pub fn read_binding(wallet: &str, safe_id: &str) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(safe_id, "safe id")) {
        return e;
    }
    let binding: Binding = match load(&binding_key(wallet, safe_id), "Safe binding") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let current = match inspect(&binding.chain, &binding.safe.safe_address) {
        Ok(v) => v,
        Err(e) => return e,
    };
    petal::read_json_value(
        &json!({"binding":binding,"current":current,"configuration_changed": configuration(&binding.safe) != configuration(&current)}),
    )
}

fn configuration(
    snapshot: &SafeSnapshot,
) -> (&str, &str, &str, &[String], &str, &str, &[String], &str) {
    (
        &snapshot.safe_version,
        &snapshot.singleton,
        &snapshot.singleton_code_hash,
        &snapshot.owners,
        &snapshot.threshold,
        &snapshot.guard,
        &snapshot.modules,
        &snapshot.fallback_handler,
    )
}

fn transaction_context_matches(
    binding: &Binding,
    state: &TransactionState,
    current: &SafeSnapshot,
) -> bool {
    state.wallet == binding.wallet
        && state.snapshot.safe_address == binding.safe.safe_address
        && state.snapshot.safe_address == current.safe_address
        && state.snapshot.chain_id == binding.safe.chain_id
        && state.snapshot.chain_id == current.chain_id
        && configuration(&state.snapshot) == configuration(&binding.safe)
        && configuration(&state.snapshot) == configuration(current)
}

fn encode_batch(calls: &[Call], safe: &str) -> Result<Vec<u8>, DispatchResponse> {
    if calls.is_empty() || calls.len() > 32 {
        return Err(invalid("batch must contain 1 to 32 calls"));
    }
    let safe = address(safe, "Safe")?;
    let mut packed = Vec::new();
    for call in calls {
        let to = address(&call.to, "call.to")?;
        if to == safe {
            return Err(denied("Safe self-calls are not supported"));
        }
        let value = uint(&call.value, "call.value")?;
        let data = hex_bytes(&call.data, "call.data")?;
        packed.push(0);
        packed.extend_from_slice(to.as_slice());
        packed.extend_from_slice(&value.to_be_bytes::<32>());
        packed.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
        packed.extend_from_slice(&data);
    }
    Ok(multiSendCall {
        transactions: packed.into(),
    }
    .abi_encode())
}

fn verified_library(
    chain: &str,
    candidates: &'static [Library],
) -> Result<(Library, String), DispatchResponse> {
    for library in candidates {
        let code = rpc_hex(chain, "eth_getCode", json!([library.address, "latest"]))?;
        let observed = format!("{:#x}", keccak256(code));
        if observed.eq_ignore_ascii_case(library.code_hash) {
            return Ok((*library, observed));
        }
    }
    Err(denied(
        "no supported canonical Safe library deployment has the expected runtime code",
    ))
}

fn build_tx(
    binding: &Binding,
    request: &TransactionRequest,
) -> Result<(SafeTx, Option<String>, SafeSnapshot), DispatchResponse> {
    let current = inspect(&binding.chain, &binding.safe.safe_address)?;
    if binding.safe.chain_id != current.chain_id
        || configuration(&binding.safe) != configuration(&current)
    {
        return Err(denied(
            "Safe configuration changed; bind it again before drafting",
        ));
    }
    let safe = address(&binding.safe.safe_address, "Safe")?;
    let (to, value, data, operation, library_hash) = match request {
        TransactionRequest::Call(call) => {
            let to = address(&call.to, "call.to")?;
            if to == safe {
                return Err(denied("Safe self-calls are not supported"));
            }
            (
                to,
                uint(&call.value, "call.value")?,
                hex_bytes(&call.data, "call.data")?,
                0,
                None,
            )
        }
        TransactionRequest::NativeTransfer { to, value } => {
            let to = address(to, "to")?;
            if to == safe {
                return Err(denied("Safe self-calls are not supported"));
            }
            (to, uint(value, "value")?, vec![], 0, None)
        }
        TransactionRequest::Erc20Transfer { token, to, amount } => {
            let token = address(token, "token")?;
            if token == safe {
                return Err(denied("Safe self-calls are not supported"));
            }
            let data = transferCall {
                to: address(to, "to")?,
                value: uint(amount, "amount")?,
            }
            .abi_encode();
            (token, U256::ZERO, data, 0, None)
        }
        TransactionRequest::Batch { calls } => {
            let (library, library_hash) = verified_library(
                &binding.chain,
                libraries(&binding.safe.safe_version).unwrap().0,
            )?;
            (
                address(library.address, "MultiSendCallOnly")?,
                U256::ZERO,
                encode_batch(calls, &binding.safe.safe_address)?,
                1,
                Some(library_hash),
            )
        }
        TransactionRequest::TransactionBuilder { builder } => {
            if builder.chain_id != binding.safe.chain_id {
                return Err(denied(
                    "Transaction Builder chainId does not match this Safe",
                ));
            }
            if let Some(meta) = &builder.meta
                && let Some(created_from_safe) =
                    meta.get("createdFromSafeAddress").and_then(Value::as_str)
                && !created_from_safe.eq_ignore_ascii_case(&binding.safe.safe_address)
            {
                return Err(denied(
                    "Transaction Builder Safe address does not match this Safe",
                ));
            }
            let calls = builder
                .transactions
                .iter()
                .map(|transaction| {
                    let data = match (&transaction.data, &transaction.contract_method) {
                        (Some(data), _) => data.clone(),
                        (None, None) => empty_hex(),
                        (None, Some(method)) => format!(
                            "0x{}",
                            hex::encode(encode_builder_method(
                                method,
                                transaction.contract_inputs_values.as_ref()
                            )?)
                        ),
                    };
                    if transaction
                        .contract_method
                        .as_ref()
                        .is_some_and(|method| !method.payable)
                        && uint(&transaction.value, "transaction.value")? != U256::ZERO
                    {
                        return Err(invalid(
                            "Transaction Builder sends value to a nonpayable method",
                        ));
                    }
                    Ok(Call {
                        to: transaction.to.clone(),
                        value: transaction.value.clone(),
                        data,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            if calls.len() == 1 {
                let call = &calls[0];
                let to = address(&call.to, "transaction.to")?;
                if to == safe {
                    return Err(denied("Safe self-calls are not supported"));
                }
                (
                    to,
                    uint(&call.value, "transaction.value")?,
                    hex_bytes(&call.data, "transaction.data")?,
                    0,
                    None,
                )
            } else {
                let (library, library_hash) = verified_library(
                    &binding.chain,
                    libraries(&binding.safe.safe_version).unwrap().0,
                )?;
                (
                    address(library.address, "MultiSendCallOnly")?,
                    U256::ZERO,
                    encode_batch(&calls, &binding.safe.safe_address)?,
                    1,
                    Some(library_hash),
                )
            }
        }
        TransactionRequest::Create { value, initcode } => {
            let (library, library_hash) = verified_library(
                &binding.chain,
                libraries(&binding.safe.safe_version).unwrap().1,
            )?;
            let data = performCreateCall {
                value: uint(value, "value")?,
                deploymentData: hex_bytes(initcode, "initcode")?.into(),
            }
            .abi_encode();
            (
                address(library.address, "CreateCall")?,
                U256::ZERO,
                data,
                1,
                Some(library_hash),
            )
        }
        TransactionRequest::Create2 {
            value,
            initcode,
            salt,
        } => {
            let (library, library_hash) = verified_library(
                &binding.chain,
                libraries(&binding.safe.safe_version).unwrap().1,
            )?;
            let salt = hex_bytes(salt, "salt")?;
            if salt.len() != 32 {
                return Err(invalid("salt must be 32 bytes"));
            }
            let data = performCreate2Call {
                value: uint(value, "value")?,
                deploymentData: hex_bytes(initcode, "initcode")?.into(),
                salt: B256::from_slice(&salt),
            }
            .abi_encode();
            (
                address(library.address, "CreateCall")?,
                U256::ZERO,
                data,
                1,
                Some(library_hash),
            )
        }
        TransactionRequest::Rejection => (safe, U256::ZERO, vec![], 0, None),
    };
    let tx = SafeTx {
        to: format!("{to:#x}"),
        value: value.to_string(),
        data: format!("0x{}", hex::encode(data)),
        operation,
        safe_tx_gas: "0".into(),
        base_gas: "0".into(),
        gas_price: "0".into(),
        gas_token: ZERO.into(),
        refund_receiver: ZERO.into(),
        nonce: current.nonce.clone(),
    };
    Ok((tx, library_hash, current))
}

fn word_address(address: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address.as_slice());
    word
}

pub fn signing_preimage(
    chain_id: &str,
    safe_address: &str,
    tx: &SafeTx,
) -> Result<Vec<u8>, DispatchResponse> {
    let mut domain = Vec::new();
    domain.extend_from_slice(keccak256(DOMAIN_TYPE).as_slice());
    domain.extend_from_slice(&uint(chain_id, "chain_id")?.to_be_bytes::<32>());
    domain.extend_from_slice(&word_address(address(safe_address, "safe_address")?));
    let mut body = Vec::new();
    body.extend_from_slice(keccak256(SAFE_TX_TYPE).as_slice());
    body.extend_from_slice(&word_address(address(&tx.to, "safe_tx.to")?));
    body.extend_from_slice(&uint(&tx.value, "safe_tx.value")?.to_be_bytes::<32>());
    body.extend_from_slice(keccak256(hex_bytes(&tx.data, "safe_tx.data")?).as_slice());
    body.extend_from_slice(&U256::from(tx.operation).to_be_bytes::<32>());
    for (value, field) in [
        (&tx.safe_tx_gas, "safe_tx_gas"),
        (&tx.base_gas, "base_gas"),
        (&tx.gas_price, "gas_price"),
    ] {
        body.extend_from_slice(&uint(value, field)?.to_be_bytes::<32>());
    }
    body.extend_from_slice(&word_address(address(&tx.gas_token, "gas_token")?));
    body.extend_from_slice(&word_address(address(
        &tx.refund_receiver,
        "refund_receiver",
    )?));
    body.extend_from_slice(&uint(&tx.nonce, "nonce")?.to_be_bytes::<32>());
    let mut preimage = vec![0x19, 0x01];
    preimage.extend_from_slice(keccak256(domain).as_slice());
    preimage.extend_from_slice(keccak256(body).as_slice());
    Ok(preimage)
}

pub fn create_transaction(wallet: &str, safe_id: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet")
        .and_then(|_| safe_segment(safe_id, "safe id"))
        .and_then(|_| safe_segment(id, "transaction id"))
    {
        return e;
    }
    if body.len() > MAX_BODY {
        return invalid("transaction request is too large");
    }
    let request: TransactionRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return invalid(format!("invalid transaction JSON: {e}")),
    };
    let binding: Binding = match load(&binding_key(wallet, safe_id), "Safe binding") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (safe_tx, library_code_hash, snapshot) = match build_tx(&binding, &request) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let preimage =
        match signing_preimage(&binding.safe.chain_id, &binding.safe.safe_address, &safe_tx) {
            Ok(v) => v,
            Err(e) => return e,
        };
    let state = TransactionState {
        schema: "bloom.safe.transaction.v1".into(),
        wallet: wallet.into(),
        safe_id: safe_id.into(),
        id: id.into(),
        request,
        snapshot,
        safe_tx,
        safe_tx_hash: format!("{:#x}", keccak256(preimage)),
        phase: "draft".into(),
        owner_signature: None,
        approval_action_id: None,
        service_status: None,
        outbox_id: None,
        execution_tx_hash: None,
        execution_status: None,
        executor_wallet: None,
        library_code_hash,
    };
    match save_new(&tx_key(wallet, id), &state) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => e,
    }
}

fn envelope(binding: &Binding, state: &TransactionState) -> ReviewEnvelope {
    ReviewEnvelope {
        schema: "bloom.safe.review.v1".into(),
        chain_id: binding.safe.chain_id.clone(),
        safe_address: binding.safe.safe_address.clone(),
        safe_version: binding.safe.safe_version.clone(),
        singleton: binding.safe.singleton.clone(),
        singleton_code_hash: binding.safe.singleton_code_hash.clone(),
        owner: binding.owner.clone(),
        owners: binding.safe.owners.clone(),
        threshold: binding.safe.threshold.clone(),
        guard: binding.safe.guard.clone(),
        modules: binding.safe.modules.clone(),
        fallback_handler: binding.safe.fallback_handler.clone(),
        safe_tx: state.safe_tx.clone(),
        library_code_hash: state.library_code_hash.clone(),
    }
}

fn route_id(ctx: &petal::Ctx) -> Result<&str, DispatchResponse> {
    ctx.params
        .iter()
        .find_map(|(k, v)| (k == "bloom.route_id").then_some(v.as_str()))
        .ok_or_else(|| backend("trusted route id is unavailable"))
}

fn claim(ctx: &petal::Ctx, preimage: &[u8], hash: B256) -> Result<Vec<u8>, DispatchResponse> {
    let route = route_id(ctx)?;
    let payload_digest = petal::payload_batch_digest(&[petal::PayloadSignItem {
        preimage: preimage.to_vec(),
        claimed_hash: hash.0,
    }])
    .map_err(sdk_error)?;
    let nonce = Sha256::digest(
        [
            ctx.package_hash.as_bytes(),
            route.as_bytes(),
            b"safe.transaction.confirm",
            hash.as_slice(),
        ]
        .concat(),
    );
    serde_jcs::to_vec(&json!({
        "package_hash":ctx.package_hash, "route":route, "operation_class":"safe.transaction.confirm",
        "crypto_suite":"secp256k1-keccak256-recoverable", "payload_digest":hex::encode(payload_digest),
        "ordered_hashes":[hex::encode(hash)], "declared_debits":[], "declared_destinations":[],
        "declared_fee":{"kind":"none"}, "nonce":hex::encode(&nonce[..16]), "claim_assurance":{"kind":"machine_asserted"}
    })).map_err(|e| backend(e.to_string()))
}

fn signature_address(value: &[u8], hash: B256) -> Result<Address, DispatchResponse> {
    if value.len() != 65 {
        return Err(invalid("Safe owner signature must be 65 bytes"));
    }
    let mut normalized = value.to_vec();
    if normalized[64] >= 27 {
        normalized[64] -= 27;
    }
    if normalized[64] > 1 {
        return Err(invalid("Safe owner signature has invalid recovery id"));
    }
    Signature::from_raw(&normalized)
        .map_err(|e| invalid(format!("invalid owner signature: {e}")))?
        .recover_address_from_prehash(&hash)
        .map_err(|e| invalid(format!("cannot recover owner signature: {e}")))
}

fn normalize_signature(mut value: Vec<u8>) -> Result<String, DispatchResponse> {
    if value.len() != 65 {
        return Err(backend("Bloom returned a non-65-byte Safe signature"));
    }
    if value[64] < 27 {
        value[64] += 27;
    }
    if !matches!(value[64], 27 | 28) {
        return Err(backend("Bloom returned an invalid Safe recovery id"));
    }
    Ok(format!("0x{}", hex::encode(value)))
}

pub fn confirm(ctx: &petal::Ctx, wallet: &str, id: &str) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(id, "transaction id"))
    {
        return e;
    }
    let mut state: TransactionState = match load(&tx_key(wallet, id), "Safe transaction") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let binding: Binding = match load(&binding_key(wallet, &state.safe_id), "Safe binding") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let current = match inspect(&binding.chain, &binding.safe.safe_address) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !transaction_context_matches(&binding, &state, &current)
        || current.nonce != state.safe_tx.nonce
    {
        return denied("Safe configuration or nonce changed; create a new transaction");
    }
    if state.owner_signature.is_some() {
        if binding.transaction_service.is_some() && state.service_status.is_none() {
            match publish(&binding, &state) {
                Ok(status) => {
                    state.service_status = Some(status);
                    state.phase = "proposed".into();
                    return match save(&tx_key(wallet, id), &state) {
                        Ok(()) => DispatchResponse::Write,
                        Err(e) => e,
                    };
                }
                Err(e) => return e,
            }
        }
        return DispatchResponse::Write;
    }
    let preimage = match signing_preimage(
        &binding.safe.chain_id,
        &binding.safe.safe_address,
        &state.safe_tx,
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let hash = keccak256(&preimage);
    if format!("{hash:#x}") != state.safe_tx_hash {
        return backend("stored Safe transaction hash is inconsistent");
    }
    let action = match serde_jcs::to_vec(&envelope(&binding, &state)) {
        Ok(v) => v,
        Err(e) => return backend(e.to_string()),
    };
    let claim = match claim(ctx, &preimage, hash) {
        Ok(v) => v,
        Err(e) => return e,
    };
    match petal::sdk::sign_payload(&PayloadSignRequest {
        wallet: wallet.into(),
        preimage,
        claimed_hash: hash.0,
        signature_algorithm: "secp256k1-keccak256-recoverable".into(),
        operation_class: "safe.transaction.confirm".into(),
        petal_use_claim_jcs: claim,
        claim_assurance_evidence: None,
        approval_hint: state.approval_action_id.clone(),
        action: Some(action),
        advisory: None,
        selector: SignSelector::Exact,
        key_ref_jcs: None,
    }) {
        Ok(SignOutcome::ApprovalPending { action_id, .. }) => {
            state.phase = "approval_required".into();
            state.approval_action_id = Some(action_id);
            if let Err(e) = save(&tx_key(wallet, id), &state) {
                return e;
            }
            DispatchResponse::Write
        }
        Ok(SignOutcome::Signature(bytes)) => {
            if signature_address(&bytes, hash).map(|a| format!("{a:#x}"))
                != Ok(binding.owner.clone())
            {
                return backend("Bloom signature does not recover the bound Safe owner");
            }
            state.owner_signature = match normalize_signature(bytes) {
                Ok(v) => Some(v),
                Err(e) => return e,
            };
            state.approval_action_id = None;
            state.phase = "signed".into();
            if let Err(e) = save(&tx_key(wallet, id), &state) {
                return e;
            }
            if binding.transaction_service.is_some() {
                match publish(&binding, &state) {
                    Ok(status) => {
                        state.service_status = Some(status);
                        state.phase = "proposed".into();
                    }
                    Err(e) => return e,
                }
            }
            match save(&tx_key(wallet, id), &state) {
                Ok(()) => DispatchResponse::Write,
                Err(e) => e,
            }
        }
        Err(e) => sdk_error(e),
    }
}

fn api_key(binding: &Binding, safe_id: &str) -> Option<String> {
    petal::sdk::store_get(&api_key_key(&binding.wallet, safe_id), 8192)
        .ok()
        .and_then(|v| String::from_utf8(v).ok())
}

fn service(
    binding: &Binding,
    safe_id: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Value), DispatchResponse> {
    let origin = binding
        .transaction_service
        .as_deref()
        .ok_or_else(|| invalid("this Safe has no Transaction Service"))?;
    let mut headers = vec![("content-type".into(), "application/json".into())];
    if let Some(key) = api_key(binding, safe_id) {
        headers.push(("authorization".into(), format!("Bearer {}", key.trim())));
    }
    let response = petal::sdk::http_fetch(
        &HttpRequest {
            method: method.into(),
            url: format!("{origin}{path}"),
            headers,
            body,
        },
        MAX_BODY,
    )
    .map_err(sdk_error)?;
    let value = serde_json::from_slice(&response.body)
        .map_err(|e| backend(format!("Transaction Service returned invalid JSON: {e}")))?;
    Ok((response.status, value))
}

fn service_tx_matches(value: &Value, state: &TransactionState) -> bool {
    let field = |name: &str| value.get(name).and_then(|v| v.as_str());
    let number = |name: &str, expected: &str| {
        value.get(name).is_some_and(|v| {
            v.as_str() == Some(expected)
                || v.as_u64()
                    .is_some_and(|number| number.to_string() == expected)
        })
    };
    field("safe").is_some_and(|v| v.eq_ignore_ascii_case(&state.snapshot.safe_address))
        && field("to").is_some_and(|v| v.eq_ignore_ascii_case(&state.safe_tx.to))
        && number("value", &state.safe_tx.value)
        && field("data")
            .unwrap_or("0x")
            .eq_ignore_ascii_case(&state.safe_tx.data)
        && number("operation", &state.safe_tx.operation.to_string())
        && number("safeTxGas", &state.safe_tx.safe_tx_gas)
        && number("baseGas", &state.safe_tx.base_gas)
        && number("gasPrice", &state.safe_tx.gas_price)
        && field("gasToken").is_some_and(|v| v.eq_ignore_ascii_case(&state.safe_tx.gas_token))
        && field("refundReceiver")
            .is_some_and(|v| v.eq_ignore_ascii_case(&state.safe_tx.refund_receiver))
        && number("nonce", &state.safe_tx.nonce)
        && field("safeTxHash").is_some_and(|v| v.eq_ignore_ascii_case(&state.safe_tx_hash))
}

fn publish(binding: &Binding, state: &TransactionState) -> Result<String, DispatchResponse> {
    let hash = &state.safe_tx_hash;
    let path = format!("/api/v1/multisig-transactions/{hash}/");
    let (status, value) = service(binding, &state.safe_id, "GET", &path, vec![])?;
    if status == 200 {
        if !service_tx_matches(&value, state) {
            return Err(denied(
                "Transaction Service returned different Safe transaction fields",
            ));
        }
        let confirm_path = format!("/api/v1/multisig-transactions/{hash}/confirmations/");
        let (status, _) = service(
            binding,
            &state.safe_id,
            "POST",
            &confirm_path,
            serde_json::to_vec(&json!({"signature":state.owner_signature})).unwrap(),
        )?;
        if !(200..300).contains(&status) {
            return Err(backend(format!(
                "Transaction Service confirmation failed with status {status}"
            )));
        }
        return Ok("confirmed".into());
    }
    if status != 404 {
        return Err(backend(format!(
            "Transaction Service lookup failed with status {status}"
        )));
    }
    let path = format!(
        "/api/v1/safes/{}/multisig-transactions/",
        binding.safe.safe_address
    );
    let body = json!({
        "safe":binding.safe.safe_address,"to":state.safe_tx.to,"value":state.safe_tx.value,"data":state.safe_tx.data,
        "operation":state.safe_tx.operation,"gasToken":state.safe_tx.gas_token,"safeTxGas":state.safe_tx.safe_tx_gas,
        "baseGas":state.safe_tx.base_gas,"gasPrice":state.safe_tx.gas_price,"refundReceiver":state.safe_tx.refund_receiver,
        "nonce":state.safe_tx.nonce,"contractTransactionHash":state.safe_tx_hash,"sender":binding.owner,
        "signature":state.owner_signature,"origin":"Bloom Safe Petal"
    });
    let (status, _) = service(
        binding,
        &state.safe_id,
        "POST",
        &path,
        serde_json::to_vec(&body).unwrap(),
    )?;
    if !(200..300).contains(&status) {
        return Err(backend(format!(
            "Transaction Service proposal failed with status {status}"
        )));
    }
    Ok("proposed".into())
}

fn parse_signature(value: &str) -> Result<Vec<u8>, DispatchResponse> {
    hex_bytes(value, "signature")
}

fn ordered_signatures(
    binding: &Binding,
    state: &TransactionState,
    additional: &[String],
) -> Result<Vec<u8>, DispatchResponse> {
    let hash = keccak256(signing_preimage(
        &binding.safe.chain_id,
        &binding.safe.safe_address,
        &state.safe_tx,
    )?);
    let owners = binding
        .safe
        .owners
        .iter()
        .map(|v| address(v, "owner"))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let mut signatures = BTreeMap::new();
    for value in state.owner_signature.iter().chain(additional) {
        let bytes = parse_signature(value)?;
        let owner = signature_address(&bytes, hash)?;
        if !owners.contains(&owner) {
            return Err(denied("signature does not belong to a current Safe owner"));
        }
        let mut safe_bytes = bytes;
        if safe_bytes[64] < 27 {
            safe_bytes[64] += 27;
        }
        if let Some(existing) = signatures.insert(owner, safe_bytes.clone())
            && existing != safe_bytes
        {
            return Err(invalid("conflicting signatures for one Safe owner"));
        }
    }
    let threshold: usize = binding
        .safe
        .threshold
        .parse()
        .map_err(|_| backend("invalid stored threshold"))?;
    if signatures.len() < threshold {
        return Err(denied(format!(
            "Safe threshold requires {threshold} owner signatures; {} supplied",
            signatures.len()
        )));
    }
    Ok(signatures.into_values().take(threshold).flatten().collect())
}

pub fn execute(wallet: &str, id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(id, "transaction id"))
    {
        return e;
    }
    let mut request: ExecuteRequest = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return invalid(format!("invalid execution JSON: {e}")),
    };
    let mut state: TransactionState = match load(&tx_key(wallet, id), "Safe transaction") {
        Ok(v) => v,
        Err(e) => return e,
    };
    if state.outbox_id.is_some() {
        return DispatchResponse::Write;
    }
    let binding: Binding = match load(&binding_key(wallet, &state.safe_id), "Safe binding") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let current = match inspect(&binding.chain, &binding.safe.safe_address) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if !transaction_context_matches(&binding, &state, &current)
        || current.nonce != state.safe_tx.nonce
    {
        return denied("Safe configuration or nonce changed before execution");
    }
    let preimage = match signing_preimage(
        &binding.safe.chain_id,
        &binding.safe.safe_address,
        &state.safe_tx,
    ) {
        Ok(value) => value,
        Err(e) => return e,
    };
    if format!("{:#x}", keccak256(preimage)) != state.safe_tx_hash {
        return backend("stored Safe transaction hash is inconsistent");
    }
    if binding.transaction_service.is_some() {
        let path = format!("/api/v1/multisig-transactions/{}/", state.safe_tx_hash);
        let (status, value) = match service(&binding, &state.safe_id, "GET", &path, vec![]) {
            Ok(v) => v,
            Err(e) => return e,
        };
        if status != 200 || !service_tx_matches(&value, &state) {
            return denied("Transaction Service did not return the exact Safe transaction");
        }
        let confirmations = match value.get("confirmations").and_then(Value::as_array) {
            Some(v) => v,
            None => return backend("Transaction Service omitted confirmations"),
        };
        if confirmations.len() > 64 {
            return denied("Transaction Service returned too many confirmations");
        }
        for confirmation in confirmations {
            let signature = match confirmation.get("signature").and_then(Value::as_str) {
                Some(v) => v,
                None => {
                    return denied(
                        "Transaction Service returned a confirmation without a signature",
                    );
                }
            };
            request.signatures.push(signature.into());
        }
    }
    let signatures = match ordered_signatures(&binding, &state, &request.signatures) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let data = execTransactionCall {
        to: match address(&state.safe_tx.to, "to") {
            Ok(v) => v,
            Err(e) => return e,
        },
        value: match uint(&state.safe_tx.value, "value") {
            Ok(v) => v,
            Err(e) => return e,
        },
        data: match hex_bytes(&state.safe_tx.data, "data") {
            Ok(v) => v.into(),
            Err(e) => return e,
        },
        operation: state.safe_tx.operation,
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasToken: Address::ZERO,
        refundReceiver: Address::ZERO,
        signatures: signatures.into(),
    }
    .abi_encode();
    let staged = match petal::sdk::tx_stage(&petal::EvmTransaction {
        wallet: request.executor_wallet.clone(),
        chain: binding.chain.clone(),
        to: binding.safe.safe_address.clone(),
        value_wei: "0".into(),
        data_hex: format!("0x{}", hex::encode(data)),
        nonce: request.nonce,
        max_fee_per_gas: request.max_fee_per_gas,
        max_priority_fee_per_gas: request.max_priority_fee_per_gas,
    }) {
        Ok(v) => v,
        Err(e) => return sdk_error(e),
    };
    state.outbox_id = Some(staged.outbox_id);
    state.executor_wallet = Some(request.executor_wallet);
    state.phase = "execution_staged".into();
    state.execution_status = Some("staged".into());
    match save(&tx_key(wallet, id), &state) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => e,
    }
}

pub fn read_transaction(wallet: &str, id: &str) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(id, "transaction id"))
    {
        return e;
    }
    let mut state: TransactionState = match load(&tx_key(wallet, id), "Safe transaction") {
        Ok(v) => v,
        Err(e) => return e,
    };
    if let Some(outbox) = state.outbox_id.clone() {
        let binding: Binding = match load(&binding_key(wallet, &state.safe_id), "Safe binding") {
            Ok(v) => v,
            Err(e) => return e,
        };
        let executor = state.executor_wallet.as_deref().unwrap_or(wallet);
        if let Ok(inspection) = petal::sdk::tx_inspect(executor, &binding.chain, &outbox) {
            state.execution_status = Some(inspection.state.clone());
            state.execution_tx_hash = inspection.tx_hash;
            if inspection.state == "confirmed" {
                state.phase = "executed".into();
            } else if inspection.state == "failed" {
                state.phase = "execution_failed".into();
            }
            let _ = save(&tx_key(wallet, id), &state);
        }
    }
    let current_nonce = load::<Binding>(&binding_key(wallet, &state.safe_id), "Safe binding")
        .ok()
        .and_then(|binding| inspect(&binding.chain, &binding.safe.safe_address).ok())
        .map(|snapshot| snapshot.nonce);
    let nonce_conflict = current_nonce.as_deref().is_some_and(|current| {
        uint(current, "current nonce").ok() > uint(&state.safe_tx.nonce, "transaction nonce").ok()
            && state.phase != "executed"
    });
    if nonce_conflict {
        state.phase = "nonce_conflict".into();
        let _ = save(&tx_key(wallet, id), &state);
    }
    let view = json!({
        "schema":state.schema,"wallet":state.wallet,"safe_id":state.safe_id,"id":state.id,"request":state.request,
        "safe_tx":state.safe_tx,"safe_tx_hash":state.safe_tx_hash,"phase":state.phase,
        "approval_action_id":state.approval_action_id,"service_status":state.service_status,"outbox_id":state.outbox_id,
        "execution_tx_hash":state.execution_tx_hash,"execution_status":state.execution_status,"executor_wallet":state.executor_wallet,
        "current_safe_nonce":current_nonce,"nonce_conflict":nonce_conflict
    });
    petal::read_json_value(&view)
}

pub fn set_service_key(wallet: &str, safe_id: &str, body: &[u8]) -> DispatchResponse {
    if let Err(e) = safe_segment(wallet, "wallet").and_then(|_| safe_segment(safe_id, "safe id")) {
        return e;
    }
    if body.is_empty() || body.len() > 8192 {
        return invalid("service key must contain 1 to 8192 bytes");
    }
    let key = match std::str::from_utf8(body) {
        Ok(value) => value.trim(),
        Err(_) => return invalid("service key must be UTF-8"),
    };
    if key.is_empty() || !key.bytes().all(|byte| byte.is_ascii_graphic()) {
        return invalid("service key must contain only visible ASCII without spaces");
    }
    match petal::sdk::store_put(&api_key_key(wallet, safe_id), key.as_bytes(), true) {
        Ok(()) => DispatchResponse::Write,
        Err(e) => sdk_error(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> SafeTx {
        SafeTx {
            to: "0x4000000000000000000000000000000000000000".into(),
            value: "7".into(),
            data: "0x".into(),
            operation: 0,
            safe_tx_gas: "0".into(),
            base_gas: "0".into(),
            gas_price: "0".into(),
            gas_token: ZERO.into(),
            refund_receiver: ZERO.into(),
            nonce: "4".into(),
        }
    }

    #[test]
    fn safe_hash_matches_known_vector() {
        let preimage =
            signing_preimage("31337", "0x1000000000000000000000000000000000000000", &tx()).unwrap();
        assert_eq!(preimage.len(), 66);
        assert_eq!(
            format!("0x{}", hex::encode(&preimage)),
            "0x19012fa662b1cd388662ad0139a7648d932107600c53cbfe554866bafcf8f79876c04df4ec4f257d9031c81f0d3da4cb271b36b22127419c8261f3aed7606264f38b"
        );
        assert_eq!(
            format!("{:#x}", keccak256(preimage)),
            "0xa6119a03d6d492a10575b05da6c5eb47b9aae120c346935ef329c9a9a559a509"
        );
    }

    #[test]
    fn batch_encoding_is_call_only_and_bounded() {
        let (multisend, create) = libraries("1.3.0").unwrap();
        assert_eq!(multisend.len(), 2);
        assert_eq!(create.len(), 2);
        assert_eq!(libraries("1.4.1").unwrap().0.len(), 1);
        assert!(libraries("1.2.0").is_none());

        let calls = vec![Call {
            to: "0x4000000000000000000000000000000000000000".into(),
            value: "2".into(),
            data: "0x1234".into(),
        }];
        let encoded = encode_batch(&calls, "0x1000000000000000000000000000000000000000").unwrap();
        assert_eq!(&encoded[..4], multiSendCall::SELECTOR);
        assert!(encode_batch(&[], ZERO).is_err());
        let self_call = vec![Call {
            to: "0x1000000000000000000000000000000000000000".into(),
            value: "0".into(),
            data: "0x".into(),
        }];
        assert!(encode_batch(&self_call, "0x1000000000000000000000000000000000000000").is_err());
    }

    #[test]
    fn create2_address_uses_safe_as_deployer() {
        let safe = address("0x1000000000000000000000000000000000000000", "safe").unwrap();
        let salt = B256::ZERO;
        let code = vec![0x60, 0, 0x60, 0, 0xf3];
        assert_eq!(
            safe.create2(salt, keccak256(&code)),
            safe.create2_from_code(salt, &code)
        );
    }

    #[test]
    fn canonical_decimal_and_refund_defaults_are_strict() {
        assert!(uint("01", "value").is_err());
        assert!(uint("-1", "value").is_err());
        let preimage =
            signing_preimage("1", "0x1000000000000000000000000000000000000000", &tx()).unwrap();
        let mut changed = tx();
        changed.gas_price = "1".into();
        assert_ne!(
            preimage,
            signing_preimage("1", "0x1000000000000000000000000000000000000000", &changed).unwrap()
        );
        assert_eq!(
            validate_service(Some("https://safe.example/".into())).unwrap(),
            Some("https://safe.example".into())
        );
        for invalid in [
            "http://safe.example",
            "https://user@safe.example",
            "https://safe.example/api",
            "https://safe.example?token=value",
        ] {
            assert!(validate_service(Some(invalid.into())).is_err());
        }
    }

    #[test]
    fn service_response_must_match_refund_and_gas_fields() {
        let state = TransactionState {
            schema: "bloom.safe.transaction.v1".into(),
            wallet: "owner".into(),
            safe_id: "treasury".into(),
            id: "payment".into(),
            request: TransactionRequest::Rejection,
            snapshot: SafeSnapshot {
                chain_id: "31337".into(),
                safe_address: "0x1000000000000000000000000000000000000000".into(),
                safe_version: "1.4.1".into(),
                singleton: "0x2000000000000000000000000000000000000000".into(),
                singleton_code_hash: format!("{:#x}", B256::ZERO),
                owners: vec!["0x3000000000000000000000000000000000000000".into()],
                threshold: "1".into(),
                nonce: "4".into(),
                guard: ZERO.into(),
                modules: vec![],
                fallback_handler: ZERO.into(),
            },
            safe_tx: tx(),
            safe_tx_hash: "0xa6119a03d6d492a10575b05da6c5eb47b9aae120c346935ef329c9a9a559a509"
                .into(),
            phase: "confirmed".into(),
            owner_signature: None,
            approval_action_id: None,
            service_status: None,
            outbox_id: None,
            execution_tx_hash: None,
            execution_status: None,
            executor_wallet: None,
            library_code_hash: None,
        };
        let mut response = json!({
            "safe":state.snapshot.safe_address,"to":state.safe_tx.to,"value":"7","data":null,
            "operation":0,"safeTxGas":0,"baseGas":"0","gasPrice":0,"gasToken":ZERO,
            "refundReceiver":ZERO,"nonce":4,"safeTxHash":state.safe_tx_hash
        });
        assert!(service_tx_matches(&response, &state));
        response["gasPrice"] = json!("1");
        assert!(!service_tx_matches(&response, &state));
        response["gasPrice"] = json!(0);
        response["refundReceiver"] = json!("0x4000000000000000000000000000000000000000");
        assert!(!service_tx_matches(&response, &state));
    }

    #[test]
    fn parses_transaction_builder_raw_data() {
        let request: TransactionRequest = serde_json::from_value(json!({
            "kind":"transaction_builder",
            "builder":{
                "version":"1.0","chainId":"31337","createdAt":1,
                "meta":{"createdFromSafeAddress":"0x1000000000000000000000000000000000000000"},
                "transactions":[{
                    "to":"0x4000000000000000000000000000000000000000","value":"0",
                    "data":"0x1234","contractMethod":null,"contractInputsValues":null
                }]
            }
        }))
        .unwrap();
        assert!(matches!(
            request,
            TransactionRequest::TransactionBuilder { .. }
        ));
    }

    #[test]
    fn encodes_transaction_builder_methods_and_tuple_arrays() {
        let boolean = BuilderMethod {
            inputs: vec![BuilderInput {
                internal_type: Some("bool".into()),
                name: "newValue".into(),
                sol_type: "bool".into(),
                components: vec![],
            }],
            name: "testBooleanValue".into(),
            payable: false,
        };
        let fields = BTreeMap::from([("newValue".into(), "true".into())]);
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(encode_builder_method(&boolean, Some(&fields)).unwrap())
            ),
            "0x6b8515ae0000000000000000000000000000000000000000000000000000000000000001"
        );

        let tuple_array = BuilderMethod {
            inputs: vec![BuilderInput {
                internal_type: Some("tuple[]".into()),
                name: "items".into(),
                sol_type: "tuple[]".into(),
                components: vec![
                    BuilderInput {
                        internal_type: Some("address".into()),
                        name: "account".into(),
                        sol_type: "address".into(),
                        components: vec![],
                    },
                    BuilderInput {
                        internal_type: Some("uint256".into()),
                        name: "amount".into(),
                        sol_type: "uint256".into(),
                        components: vec![],
                    },
                ],
            }],
            name: "foo".into(),
            payable: false,
        };
        let fields = BTreeMap::from([(
            "items".into(),
            r#"[["0x4000000000000000000000000000000000000000","7"]]"#.into(),
        )]);
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(encode_builder_method(&tuple_array, Some(&fields)).unwrap())
            ),
            "0xe487d1950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007"
        );
    }

    #[test]
    fn owner_signatures_are_recovered_deduplicated_and_address_sorted() {
        let first = "0x9698aafeaf421f324a45e56046b6d6a2efcbdd85f8e7ce4134a827052b2e0c5a6086fd542c8757c8e614086c8da010913b0b8d578523ea728a724e636c52ee9b1c";
        let second = "0x21d5a6bbeded469398a83760c4f3b5c42779188f5c6449655d675ad387ae548f63d024139aaf2fc95b0db58d5b8d24bfc441d185b58adafab24c7a903e6079491b";
        let snapshot = SafeSnapshot {
            chain_id: "31337".into(),
            safe_address: "0x1000000000000000000000000000000000000000".into(),
            safe_version: "1.4.1".into(),
            singleton: "0x41675c099f32341bf84bfc5382af534df5c7461a".into(),
            singleton_code_hash:
                "0x1fe2df852ba3299d6534ef416eefa406e56ced995bca886ab7a553e6d0c5e1c4".into(),
            owners: vec![
                "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266".into(),
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8".into(),
            ],
            threshold: "2".into(),
            nonce: "4".into(),
            guard: ZERO.into(),
            modules: vec![],
            fallback_handler: ZERO.into(),
        };
        let binding = Binding {
            schema: "bloom.safe.binding.v1".into(),
            wallet: "owner".into(),
            owner: snapshot.owners[0].clone(),
            chain: "evm-31337".into(),
            safe: snapshot.clone(),
            transaction_service: None,
        };
        let state = TransactionState {
            schema: "bloom.safe.transaction.v1".into(),
            wallet: "owner".into(),
            safe_id: "treasury".into(),
            id: "payment".into(),
            request: TransactionRequest::Rejection,
            snapshot,
            safe_tx: tx(),
            safe_tx_hash: "0xa6119a03d6d492a10575b05da6c5eb47b9aae120c346935ef329c9a9a559a509"
                .into(),
            phase: "signed".into(),
            owner_signature: Some(first.into()),
            approval_action_id: None,
            service_status: None,
            outbox_id: None,
            execution_tx_hash: None,
            execution_status: None,
            executor_wallet: None,
            library_code_hash: None,
        };
        assert!(transaction_context_matches(
            &binding,
            &state,
            &state.snapshot
        ));
        let mut rebound = binding.clone();
        rebound.safe.safe_address = "0x2000000000000000000000000000000000000000".into();
        assert!(!transaction_context_matches(
            &rebound,
            &state,
            &state.snapshot
        ));
        let ordered = ordered_signatures(&binding, &state, &[second.into()]).unwrap();
        assert_eq!(ordered.len(), 130);
        assert_eq!(&ordered[..65], &hex_bytes(second, "signature").unwrap());
        assert!(ordered_signatures(&binding, &state, &[first.into()]).is_err());

        let mut one_owner = binding.clone();
        one_owner.safe.owners.truncate(1);
        one_owner.safe.threshold = "1".into();
        assert!(ordered_signatures(&one_owner, &state, &[second.into()]).is_err());

        let mut malformed = hex_bytes(second, "signature").unwrap();
        malformed[64] = 29;
        assert!(
            ordered_signatures(&binding, &state, &[format!("0x{}", hex::encode(malformed))])
                .is_err()
        );
        assert!(ordered_signatures(&binding, &state, &[format!("{second}00")]).is_err());
    }
}
