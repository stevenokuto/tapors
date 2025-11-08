use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicInfo {
    #[serde(default)]
    pub device_type: String,

    #[serde(default)]
    pub device_model: String,

    #[serde(default)]
    pub device_name: String,

    #[serde(default)]
    pub device_info: String,

    #[serde(default)]
    pub hw_version: String,

    #[serde(default)]
    pub sw_version: String,

    #[serde(default)]
    pub device_alias: String,

    #[serde(default)]
    pub mac: String,

    #[serde(default)]
    pub hw_id: String,

    #[serde(default)]
    pub fw_id: String,

    #[serde(default)]
    pub oem_id: String,

    #[serde(default)]
    pub fw_ver: String,

    // Additional fields stored as dynamic map for flexibility
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildDevice {
    #[serde(default)]
    pub device_id: String,

    #[serde(default)]
    pub device_type: String,

    #[serde(default)]
    pub device_model: String,

    #[serde(default)]
    pub device_name: String,

    #[serde(default)]
    pub nickname: String,

    #[serde(default)]
    pub status: String,

    // Additional fields stored as dynamic map for flexibility
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TapoResponse<T> {
    pub error_code: i32,

    #[serde(default)]
    pub result: Option<T>,

    #[serde(default)]
    pub msg: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MultipleRequestResponse {
    pub error_code: i32,
    pub result: MultipleRequestResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MultipleRequestResult {
    pub responses: Vec<MethodResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MethodResponse {
    pub method: String,
    pub error_code: i32,

    #[serde(default)]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct ChildDeviceListResult {
    pub child_device_list: Vec<ChildDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeviceInfoResult {
    pub device_info: DeviceInfoWrapper,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeviceInfoWrapper {
    pub basic_info: BasicInfo,
}
