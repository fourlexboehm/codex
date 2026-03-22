use codex_app_server_protocol::AuthMode;
use codex_app_server_protocol::SavedAccount;

use crate::app_event::AppEvent;
use crate::bottom_pane::ColumnWidthMode;
use crate::bottom_pane::SelectionItem;
use crate::bottom_pane::SelectionViewParams;

pub(super) fn build_account_picker_params(accounts: &[SavedAccount]) -> SelectionViewParams {
    let mut initial_selected_idx = None;
    let items = accounts
        .iter()
        .enumerate()
        .map(|(idx, account)| {
            if account.is_current {
                initial_selected_idx = Some(idx);
            }

            let account_id = account.id.clone();
            let name = account_name(account);
            SelectionItem {
                name: name.clone(),
                description: Some(account_description(account)),
                is_current: account.is_current,
                actions: vec![Box::new(move |tx| {
                    tx.send(AppEvent::SwitchAuthAccount {
                        account_id: account_id.clone(),
                    });
                })],
                dismiss_on_select: true,
                search_value: Some(account_search_value(account, &name)),
                ..Default::default()
            }
        })
        .collect();

    SelectionViewParams {
        title: Some("Accounts".to_string()),
        subtitle: Some("Select an account to make its auth file active.".to_string()),
        items,
        initial_selected_idx,
        is_searchable: accounts.len() > 6,
        search_placeholder: Some("Search saved accounts".to_string()),
        col_width_mode: ColumnWidthMode::AutoAllRows,
        ..Default::default()
    }
}

fn account_name(account: &SavedAccount) -> String {
    if let Some(email) = account.email.as_deref() {
        return email.to_string();
    }

    if let Some(suffix) = account.api_key_suffix.as_deref() {
        return format!("API key (...{suffix})");
    }

    if let Some(workspace_id) = account.workspace_id.as_deref() {
        return format!("Workspace {workspace_id}");
    }

    account.id.clone()
}

fn account_description(account: &SavedAccount) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("file {}", account.id));
    parts.push(account_mode_label(account.auth_mode));

    if let Some(plan_type) = account.plan_type {
        parts.push(format!(
            "plan {}",
            title_case(format!("{plan_type:?}").as_str())
        ));
    }
    if let Some(workspace_id) = account.workspace_id.as_deref() {
        parts.push(format!("workspace {workspace_id}"));
    }

    parts.join(" | ")
}

fn account_mode_label(auth_mode: AuthMode) -> String {
    match auth_mode {
        AuthMode::ApiKey => "API key".to_string(),
        AuthMode::Chatgpt => "ChatGPT".to_string(),
        AuthMode::ChatgptAuthTokens => "External ChatGPT".to_string(),
    }
}

fn account_search_value(account: &SavedAccount, name: &str) -> String {
    let mut parts = vec![
        name.to_string(),
        account.id.clone(),
        account_mode_label(account.auth_mode),
    ];
    if let Some(email) = account.email.as_deref() {
        parts.push(email.to_string());
    }
    if let Some(workspace_id) = account.workspace_id.as_deref() {
        parts.push(workspace_id.to_string());
    }
    if let Some(api_key_suffix) = account.api_key_suffix.as_deref() {
        parts.push(api_key_suffix.to_string());
    }
    parts.join(" ")
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => {
            let mut result = first.to_uppercase().collect::<String>();
            result.push_str(chars.as_str().to_ascii_lowercase().as_str());
            result
        }
        None => String::new(),
    }
}
