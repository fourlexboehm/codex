use std::cmp::Ordering;
use std::io;
use std::path::Path;
use tracing::warn;

use crate::token_data::KnownPlan as InternalKnownPlan;
use crate::token_data::PlanType as InternalPlanType;
use codex_app_server_protocol::AuthMode;
use codex_protocol::account::PlanType as AccountPlanType;

use super::file_account_store::active_auth_file_name;
use super::file_account_store::list_saved_auth_files;
use super::file_account_store::save_new_active_auth_file;
use super::file_account_store::switch_active_auth_file;
use super::file_account_store::validate_saved_auth_file_name;
use super::storage::AuthCredentialsStoreMode;
use super::storage::AuthDotJson;
use super::storage::create_auth_storage;
use super::storage::read_auth_json_file;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedAuthAccount {
    pub id: String,
    pub auth_mode: AuthMode,
    pub email: Option<String>,
    pub workspace_id: Option<String>,
    pub plan_type: Option<AccountPlanType>,
    pub api_key_suffix: Option<String>,
    pub is_current: bool,
}

pub fn save_login_auth(
    codex_home: &Path,
    auth: &AuthDotJson,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> io::Result<()> {
    if auth_credentials_store_mode != AuthCredentialsStoreMode::File {
        let storage = create_auth_storage(codex_home.to_path_buf(), auth_credentials_store_mode);
        return storage.save(auth);
    }

    save_new_active_auth_file(codex_home, auth).map(|_| ())
}

pub fn list_saved_accounts(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> io::Result<Vec<SavedAuthAccount>> {
    ensure_saved_accounts_supported(auth_credentials_store_mode)?;

    let current_auth_file_name = active_auth_file_name(codex_home)?;
    let mut accounts: Vec<SavedAuthAccount> = Vec::new();
    for path in list_saved_auth_files(codex_home)? {
        let file_name = path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .ok_or_else(|| io::Error::other("auth file name should be valid UTF-8"))?
            .to_string();
        match read_auth_json_file(&path) {
            Ok(auth_dot_json) => {
                accounts.push(saved_account_from_auth(
                    file_name,
                    auth_dot_json,
                    current_auth_file_name.as_deref(),
                ));
            }
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "ignoring unreadable saved auth file"
                );
            }
        }
    }

    accounts.sort_by(compare_saved_accounts);
    Ok(accounts)
}

pub fn switch_saved_account(
    codex_home: &Path,
    auth_credentials_store_mode: AuthCredentialsStoreMode,
    account_id: &str,
) -> io::Result<bool> {
    ensure_saved_accounts_supported(auth_credentials_store_mode)?;
    validate_saved_auth_file_name(account_id)?;
    switch_active_auth_file(codex_home, account_id)
}

fn ensure_saved_accounts_supported(
    auth_credentials_store_mode: AuthCredentialsStoreMode,
) -> io::Result<()> {
    if auth_credentials_store_mode == AuthCredentialsStoreMode::File {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "saved accounts require cli_auth_credentials_store = \"file\" (current mode: {auth_credentials_store_mode:?})"
        ),
    ))
}

fn saved_account_from_auth(
    file_name: String,
    auth_dot_json: AuthDotJson,
    current_auth_file_name: Option<&str>,
) -> SavedAuthAccount {
    SavedAuthAccount {
        auth_mode: resolved_auth_mode(&auth_dot_json),
        email: auth_dot_json
            .tokens
            .as_ref()
            .and_then(|tokens| tokens.id_token.email.clone()),
        workspace_id: auth_dot_json.tokens.as_ref().and_then(|tokens| {
            tokens
                .account_id
                .clone()
                .or_else(|| tokens.id_token.chatgpt_account_id.clone())
        }),
        plan_type: auth_dot_json.tokens.as_ref().map(|tokens| {
            tokens
                .id_token
                .chatgpt_plan_type
                .as_ref()
                .map(map_plan_type)
                .unwrap_or(AccountPlanType::Unknown)
        }),
        api_key_suffix: auth_dot_json.openai_api_key.as_deref().map(api_key_suffix),
        is_current: current_auth_file_name == Some(file_name.as_str()),
        id: file_name,
    }
}

fn compare_saved_accounts(a: &SavedAuthAccount, b: &SavedAuthAccount) -> Ordering {
    match (a.is_current, b.is_current) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => b.id.cmp(&a.id),
    }
}

fn resolved_auth_mode(auth_dot_json: &AuthDotJson) -> AuthMode {
    auth_dot_json.auth_mode.unwrap_or_else(|| {
        if auth_dot_json.openai_api_key.is_some() {
            AuthMode::ApiKey
        } else {
            AuthMode::Chatgpt
        }
    })
}

fn map_plan_type(plan_type: &InternalPlanType) -> AccountPlanType {
    match plan_type {
        InternalPlanType::Known(known_plan) => match known_plan {
            InternalKnownPlan::Free => AccountPlanType::Free,
            InternalKnownPlan::Go => AccountPlanType::Go,
            InternalKnownPlan::Plus => AccountPlanType::Plus,
            InternalKnownPlan::Pro => AccountPlanType::Pro,
            InternalKnownPlan::Team => AccountPlanType::Team,
            InternalKnownPlan::Business => AccountPlanType::Business,
            InternalKnownPlan::Enterprise => AccountPlanType::Enterprise,
            InternalKnownPlan::Edu => AccountPlanType::Edu,
        },
        InternalPlanType::Unknown(_) => AccountPlanType::Unknown,
    }
}

fn api_key_suffix(api_key: &str) -> String {
    let suffix_reversed: String = api_key.chars().rev().take(4).collect();
    suffix_reversed.chars().rev().collect()
}
