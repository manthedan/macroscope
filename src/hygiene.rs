use crate::model::*;
use plist::Value;
use std::collections::BTreeSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

const OLD_EXPOSED_PROCESS_SECONDS: u64 = 24 * 60 * 60;
const DETACHED_BROWSER_SECONDS: u64 = 6 * 60 * 60;

pub fn scan_persistence(apps: &AppsReport) -> PersistenceReport {
    let mut report = PersistenceReport::default();
    let mut roots = Vec::new();
    if let Some(home) = dirs::home_dir() {
        roots.push((
            home.join("Library/LaunchAgents"),
            LaunchItemScope::UserAgent,
        ));
    }
    roots.push((
        PathBuf::from("/Library/LaunchAgents"),
        LaunchItemScope::SystemAgent,
    ));
    roots.push((
        PathBuf::from("/Library/LaunchDaemons"),
        LaunchItemScope::SystemDaemon,
    ));

    for (root, scope) in roots {
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                report
                    .errors
                    .push(format!("{}: failed to enumerate: {error}", root.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    report.errors.push(format!(
                        "{}: failed to read directory entry: {error}",
                        root.display()
                    ));
                    continue;
                }
            };
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("plist") {
                continue;
            }
            match parse_launch_item_file(&path, scope) {
                Ok(item) => report.launch_items.push(item),
                Err(error) => report.errors.push(format!("{}: {error}", path.display())),
            }
        }
    }

    correlate_parent_apps(&mut report.launch_items, apps);
    report.launch_items.sort_by(|a, b| a.path.cmp(&b.path));
    report
}

pub fn parse_launch_item_file(path: &Path, scope: LaunchItemScope) -> Result<LaunchItem, String> {
    let value = Value::from_file(path).map_err(|error| error.to_string())?;
    parse_launch_item_value(path, scope, &value)
}

pub fn parse_launch_item_bytes(
    path: &Path,
    scope: LaunchItemScope,
    bytes: &[u8],
) -> Result<LaunchItem, String> {
    let value =
        Value::from_reader(std::io::Cursor::new(bytes)).map_err(|error| error.to_string())?;
    parse_launch_item_value(path, scope, &value)
}

fn parse_launch_item_value(
    path: &Path,
    scope: LaunchItemScope,
    value: &Value,
) -> Result<LaunchItem, String> {
    let dictionary = value
        .as_dictionary()
        .ok_or_else(|| "launch item root is not a dictionary".to_string())?;
    let label = dictionary
        .get("Label")
        .and_then(Value::as_string)
        .map(String::from)
        .unwrap_or_else(|| {
            path.file_stem()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".into())
        });
    let raw_program_arguments = dictionary
        .get("ProgramArguments")
        .and_then(Value::as_array)
        .map(|arguments| {
            arguments
                .iter()
                .filter_map(Value::as_string)
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let explicit_program = dictionary
        .get("Program")
        .and_then(Value::as_string)
        .map(String::from);
    let program_from_arguments = explicit_program.is_none();
    let translocation_target = explicit_program
        .iter()
        .chain(raw_program_arguments.iter())
        .find_map(|value| extract_translocation_path(value));
    let program_arguments = redact_arguments(raw_program_arguments, explicit_program.as_deref());
    let program = explicit_program.map(PathBuf::from).or_else(|| {
        program_arguments
            .first()
            .map(|value| resolve_launch_program(value))
    });
    let program_exists = program.as_ref().map(|program| program.exists());
    let run_at_load = dictionary
        .get("RunAtLoad")
        .and_then(Value::as_boolean)
        .unwrap_or(false);
    let keep_alive = dictionary.get("KeepAlive").is_some_and(|value| {
        value
            .as_boolean()
            .unwrap_or_else(|| value.as_dictionary().is_some())
    });
    let associated_bundle_ids = dictionary
        .get("AssociatedBundleIdentifiers")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_string)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    Ok(LaunchItem {
        path: path.to_path_buf(),
        label,
        scope,
        program,
        program_from_arguments,
        program_arguments,
        translocation_target,
        program_exists,
        run_at_load,
        keep_alive,
        associated_bundle_ids,
        parent_app_present: None,
        parent_product: None,
    })
}

fn extract_translocation_path(value: &str) -> Option<String> {
    value.split_whitespace().find_map(|word| {
        let start = word.find('/')?;
        let candidate = word[start..]
            .trim_matches(|character: char| matches!(character, '\'' | '"' | ';' | ')' | '('));
        (candidate.contains("/AppTranslocation/") || candidate.contains("/T/AppTranslocation/"))
            .then(|| candidate.to_string())
    })
}

pub fn correlate_parent_apps(items: &mut [LaunchItem], apps: &AppsReport) {
    for item in items {
        if !item
            .program
            .as_ref()
            .is_some_and(|path| path.starts_with("/Library/PrivilegedHelperTools"))
        {
            continue;
        }

        if let Some(app) = apps.apps.iter().find(|app| {
            item.associated_bundle_ids
                .iter()
                .any(|expected| app.bundle_id.as_deref() == Some(expected.as_str()))
        }) {
            item.parent_app_present = Some(true);
            item.parent_product = Some(app.path.display().to_string());
            continue;
        }

        let tokens = vendor_tokens(&item.label);
        let inferred_app = apps.apps.iter().find(|app| {
            let identity = format!(
                "{} {}",
                app.bundle_id.as_deref().unwrap_or_default(),
                app.path.display()
            );
            strong_product_match(&tokens, &identity)
        });
        let (product, system_products_complete) = if let Some(app) = inferred_app {
            (Some(app.path.display().to_string()), true)
        } else {
            related_system_product(&tokens)
        };
        let metadata_incomplete = apps.apps.iter().any(|app| {
            app.scan_error
                .as_deref()
                .is_some_and(|error| error.contains("failed to read metadata"))
                && (!item.associated_bundle_ids.is_empty()
                    || strong_product_match(&tokens, &app.path.display().to_string()))
        });
        item.parent_app_present = if product.is_none()
            && (!apps.root_errors.is_empty() || metadata_incomplete || !system_products_complete)
        {
            None
        } else {
            Some(product.is_some())
        };
        item.parent_product = product;
    }
}

fn strong_product_match(tokens: &[String], identity: &str) -> bool {
    let parts: BTreeSet<String> = identity
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| part.len() >= 4)
        .map(str::to_ascii_lowercase)
        .collect();
    let matched: BTreeSet<&String> = tokens
        .iter()
        .filter(|token| parts.contains(*token))
        .collect();
    if matched.len() >= 2 {
        return true;
    }
    let product_name = Path::new(identity)
        .file_name()
        .and_then(|name| Path::new(name).file_stem())
        .map(|name| name.to_string_lossy().to_ascii_lowercase());
    product_name.is_some_and(|name| matched.iter().any(|token| token.as_str() == name))
}

fn related_system_product(tokens: &[String]) -> (Option<String>, bool) {
    const ROOTS: &[&str] = &["/Library/Filesystems", "/Library/PreferencePanes"];
    let mut complete = true;
    for root in ROOTS {
        match Path::new(root).try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(_) => {
                complete = false;
                continue;
            }
        }
        for entry in walkdir::WalkDir::new(root).max_depth(2).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    complete = false;
                    continue;
                }
            };
            let path = entry.path().display().to_string();
            if strong_product_match(tokens, &path) {
                return (Some(path), complete);
            }
        }
    }
    (None, complete)
}

fn vendor_tokens(label: &str) -> Vec<String> {
    const IGNORED: &[&str] = &[
        "com",
        "org",
        "net",
        "helper",
        "privilegedhelper",
        "uninstallerhelper",
        "uninstallerwatcher",
        "service",
        "daemon",
        "appplayer",
        "launch",
        "agent",
        "update",
        "updater",
        "watcher",
        "installer",
        "privileged",
        "adobe",
        "google",
        "microsoft",
        "waves",
    ];
    label
        .split(|character: char| !character.is_ascii_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|token| token.len() >= 4 && !IGNORED.contains(&token.as_str()))
        .collect()
}

pub fn scan_runtime() -> RuntimeReport {
    let mut report = RuntimeReport::default();
    match Command::new("ps")
        .args([
            "-axo",
            "pid=,ppid=,pgid=,uid=,etime=,state=,%cpu=,%mem=,command=",
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            report.processes = parse_ps_output(&String::from_utf8_lossy(&output.stdout));
        }
        Ok(output) => report.errors.push(format!(
            "ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => report.errors.push(format!("failed to run ps: {error}")),
    }

    match Command::new("ps").args(["-axo", "pid=,comm="]).output() {
        Ok(output) if output.status.success() => {
            let executables = parse_ps_executables(&String::from_utf8_lossy(&output.stdout));
            for process in &mut report.processes {
                process.executable = executables.get(&process.pid).cloned();
            }
        }
        Ok(output) => report.errors.push(format!(
            "ps executable collection failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => report
            .errors
            .push(format!("failed to collect process executables: {error}")),
    }

    let tailscale_addresses = confirmed_tailscale_addresses();
    match Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"])
        .output()
    {
        Ok(output) if output.status.success() => {
            report.listeners = parse_lsof_output_with_tailscale_addresses(
                &String::from_utf8_lossy(&output.stdout),
                &tailscale_addresses,
            );
        }
        Ok(output)
            if output.status.code() == Some(1)
                && output.stdout.is_empty()
                && String::from_utf8_lossy(&output.stderr).trim().is_empty() => {}
        Ok(output) => {
            if !output.stdout.is_empty() {
                report.listeners = parse_lsof_output_with_tailscale_addresses(
                    &String::from_utf8_lossy(&output.stdout),
                    &tailscale_addresses,
                );
            }
            report.errors.push(format!(
                "lsof failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Err(error) => report.errors.push(format!("failed to run lsof: {error}")),
    }

    report
}

fn confirmed_tailscale_addresses() -> BTreeSet<IpAddr> {
    let candidates = [
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "/usr/local/bin/tailscale",
        "/opt/homebrew/bin/tailscale",
        "tailscale",
    ];
    for candidate in candidates {
        let Ok(output) = Command::new(candidate).arg("ip").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let addresses: BTreeSet<IpAddr> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();
        if !addresses.is_empty() {
            return addresses;
        }
    }
    BTreeSet::new()
}

pub fn parse_ps_executables(output: &str) -> std::collections::BTreeMap<u32, PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let split = line.find(char::is_whitespace)?;
            let pid = line[..split].parse().ok()?;
            let executable = line[split..].trim();
            (!executable.is_empty()).then(|| (pid, PathBuf::from(executable)))
        })
        .collect()
}

pub fn parse_ps_output(output: &str) -> Vec<ProcessEntry> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse().ok()?;
            let ppid = fields.next()?.parse().ok()?;
            let pgid = fields.next()?.parse().ok()?;
            let uid = fields.next()?.parse().ok()?;
            let elapsed_seconds = parse_elapsed(fields.next()?)?;
            let state = fields.next()?.to_string();
            let cpu_percent = fields.next()?.parse().ok()?;
            let memory_percent = fields.next()?.parse().ok()?;
            let command = redact_command(&fields.collect::<Vec<_>>().join(" "));
            if command.is_empty() {
                return None;
            }
            Some(ProcessEntry {
                pid,
                ppid,
                pgid,
                uid,
                executable: None,
                elapsed_seconds,
                state,
                cpu_percent,
                memory_percent,
                command,
            })
        })
        .collect()
}

pub fn process_matches_launch_item(
    item: &LaunchItem,
    command: &str,
    executable: Option<&Path>,
) -> bool {
    let Some(program) = &item.program else {
        return false;
    };
    let executable_name = program
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if executable_name != "env" {
        let program_matches = match executable {
            Some(path) => {
                path == program
                    || (program.components().count() == 1
                        && path.file_name() == program.file_name())
            }
            None => command_mentions_path(command, &program.display().to_string()),
        };
        if !program_matches {
            return false;
        }
    }
    let shared_interpreter = executable_name == "env" || is_shared_interpreter(&executable_name);
    if !shared_interpreter {
        let redacted = item
            .program_arguments
            .iter()
            .any(|argument| argument.contains("<redacted"));
        let safe_arguments = item
            .program_arguments
            .iter()
            .skip(1)
            .take_while(|argument| !argument.contains("<redacted"))
            .collect::<Vec<_>>();
        if redacted
            && !safe_arguments
                .iter()
                .any(|argument| !argument.starts_with('-') && argument.contains('/'))
        {
            return false;
        }
        return safe_arguments
            .into_iter()
            .all(|argument| command_mentions_path(command, argument));
    }
    launch_identity_arguments(item, &executable_name).is_some_and(|arguments| {
        if executable_name == "env" {
            let process_executable = command.split_whitespace().next().unwrap_or_default();
            let effective_name = arguments.first().and_then(|argument| {
                Path::new(argument)
                    .file_name()
                    .map(|name| name.to_string_lossy())
            });
            let process_name = Path::new(process_executable)
                .file_name()
                .map(|name| name.to_string_lossy());
            effective_name == process_name
                && arguments
                    .iter()
                    .skip(1)
                    .all(|argument| command_mentions_path(command, argument))
        } else {
            arguments
                .iter()
                .all(|argument| command_mentions_path(command, argument))
        }
    })
}

fn launch_identity_arguments(item: &LaunchItem, executable_name: &str) -> Option<Vec<String>> {
    let start = usize::from(!item.program_arguments.is_empty());
    let arguments: Vec<String> = item.program_arguments[start..].to_vec();
    if executable_name == "env" {
        return env_launch_identity(&arguments);
    }
    if is_shell_executable(executable_name)
        && let Some(flag_index) = arguments
            .iter()
            .position(|argument| is_shell_command_flag(argument))
        && let Some(payload) = arguments.get(flag_index + 1)
    {
        let subject = payload
            .split("<redacted")
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(['\'', '"'])
            .trim();
        if subject.contains('/') {
            return Some(vec![subject.to_string()]);
        }
    }

    interpreter_identity_arguments(&arguments, executable_name)
}

fn resolve_launch_program(value: &str) -> PathBuf {
    let candidate = PathBuf::from(value);
    if candidate.components().count() != 1 {
        return candidate;
    }
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .into_iter()
        .map(|root| Path::new(root).join(value))
        .find(|path| path.exists())
        .unwrap_or(candidate)
}

fn env_launch_identity(arguments: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_str();
        if matches!(argument, "-S" | "--split-string") {
            let split = split_env_string(arguments.get(index + 1)?);
            return env_launch_identity(&split);
        }
        if matches!(argument, "-u" | "--unset" | "-C" | "--chdir" | "-P") {
            index += 2;
            continue;
        }
        if (argument.starts_with("-P") && argument.len() > 2)
            || argument.starts_with("--unset=")
            || argument.starts_with("--chdir=")
        {
            index += 1;
            continue;
        }
        if argument.starts_with('-') || argument.contains('=') {
            index += 1;
            continue;
        }
        return effective_launch_identity(argument, &arguments[index + 1..]);
    }
    None
}

fn split_env_string(value: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if escaped {
        current.push('\\');
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn effective_launch_identity(effective: &str, arguments: &[String]) -> Option<Vec<String>> {
    let effective_name = Path::new(effective)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if is_shared_interpreter(&effective_name) {
        let mut identity = vec![effective.to_string()];
        identity.extend(interpreter_identity_arguments(arguments, &effective_name)?);
        Some(identity)
    } else {
        Some(vec![effective.to_string()])
    }
}

fn is_shared_interpreter(executable_name: &str) -> bool {
    matches!(
        executable_name,
        "node" | "nodejs" | "sh" | "bash" | "zsh" | "ruby" | "perl" | "java"
    ) || executable_name.starts_with("python")
}

fn interpreter_identity_arguments(
    arguments: &[String],
    executable_name: &str,
) -> Option<Vec<String>> {
    let mut module_index = None;
    if executable_name.starts_with("python") {
        let mut skip_operand = false;
        for (index, argument) in arguments.iter().enumerate() {
            if skip_operand {
                skip_operand = false;
                continue;
            }
            if matches!(argument.as_str(), "-W" | "-X") {
                skip_operand = true;
                continue;
            }
            if argument == "-m" {
                module_index = Some(index);
                break;
            }
            if argument == "-c" || !argument.starts_with('-') {
                break;
            }
        }
    }
    if let Some(module_index) = module_index {
        let module = arguments.get(module_index + 1)?.clone();
        let mut identity = vec![module];
        identity.extend(
            arguments[module_index + 2..]
                .iter()
                .take_while(|argument| !argument.starts_with("<redacted"))
                .cloned(),
        );
        return Some(identity);
    }
    interpreter_entrypoint(arguments, executable_name).map(|entrypoint| vec![entrypoint])
}

fn interpreter_entrypoint(arguments: &[String], executable_name: &str) -> Option<String> {
    let mut skip_operand = false;
    for (index, argument) in arguments.iter().enumerate() {
        if skip_operand {
            skip_operand = false;
            continue;
        }
        if argument.contains("<redacted") {
            break;
        }
        let perl = executable_name == "perl";
        let ruby = executable_name == "ruby";
        if perl && matches!(argument.as_str(), "-e" | "-E") {
            return arguments.get(index + 1).cloned();
        }
        if matches!(
            argument.as_str(),
            "--require"
                | "-r"
                | "--loader"
                | "--import"
                | "--conditions"
                | "--experimental-loader"
                | "-W"
                | "-X"
                | "-cp"
                | "-classpath"
                | "--class-path"
        ) || ((perl || ruby) && argument == "-I")
            || (ruby && matches!(argument.as_str(), "-C" | "-E"))
        {
            skip_operand = true;
            continue;
        }
        if matches!(argument.as_str(), "-m" | "-c" | "-jar") {
            continue;
        }
        if argument.starts_with('-') {
            continue;
        }
        return Some(argument.clone());
    }
    None
}

pub fn command_mentions_path(command: &str, path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    command.match_indices(path).any(|(start, matched)| {
        let before_ok = start == 0
            || command[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        let end = start + matched.len();
        let after_ok = end == command.len()
            || command[end..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace);
        before_ok && after_ok
    })
}

pub fn redact_command(command: &str) -> String {
    let words: Vec<&str> = command.split_whitespace().collect();
    let executable = effective_runtime_executable(&words);
    if is_shell_executable(executable)
        && let Some(index) = words.iter().position(|word| is_shell_command_flag(word))
        && index + 1 < words.len()
    {
        let prefix = words[..=index].join(" ");
        let payload = words[index + 1..]
            .join(" ")
            .trim_matches(['\'', '"'])
            .to_string();
        return format!("{prefix} {}", redact_command(&payload));
    }
    let mut output = Vec::new();
    let mut credential_executable = executable.to_string();
    for &word in &words {
        let normalized = word.trim_matches(|character: char| {
            matches!(character, '\'' | '"' | ';' | '|' | '&' | '(' | ')')
        });
        if !sensitive_short_options(normalized).is_empty() {
            credential_executable = normalized.to_string();
        }
        if let Some(prefix) = sensitive_attached_short_option(normalized, &credential_executable) {
            output.push(format!("{prefix}<redacted-tail>"));
            break;
        }
        if let Some((key, _)) = normalized.split_once('=')
            && (sensitive_key(key) || sensitive_option(key, &credential_executable))
        {
            // `ps` cannot tell whether later words belonged to the same argv value.
            output.push(format!("{key}=<redacted-tail>"));
            break;
        }
        if sensitive_header(normalized) {
            output.push("<redacted-tail>".into());
            break;
        }
        if url_has_credentials(normalized) {
            output.push("<redacted-url>".into());
            continue;
        }
        output.push(word.to_string());
        if normalized.starts_with('-')
            && (sensitive_key(normalized) || sensitive_option(normalized, &credential_executable))
        {
            // `ps` output has lost argv boundaries, so a quoted multi-word secret
            // cannot be distinguished safely from later arguments.
            output.push("<redacted-tail>".into());
            break;
        }
    }
    output.join(" ")
}

fn redact_arguments(arguments: Vec<String>, explicit_program: Option<&str>) -> Vec<String> {
    let executable = effective_argument_executable(&arguments, explicit_program);
    let mut credential_executable = executable.clone();
    let shell_wrapper = is_shell_executable(&executable)
        || arguments
            .iter()
            .any(|argument| is_shell_executable(argument));
    let env_wrapper = explicit_program
        .or_else(|| arguments.first().map(String::as_str))
        .and_then(|program| Path::new(program).file_name())
        .is_some_and(|name| name == "env");
    let mut output = Vec::new();
    let mut redact_next = false;
    let mut sanitize_shell_command = false;
    let mut sanitize_env_split = false;
    let mut preserve_env_operand = false;
    for argument in arguments {
        let normalized = argument.trim_matches(|character: char| {
            matches!(character, '\'' | '"' | ';' | '|' | '&' | '(' | ')')
        });
        if !sensitive_short_options(normalized).is_empty() {
            credential_executable = normalized.to_string();
        }
        if preserve_env_operand {
            output.push(argument);
            preserve_env_operand = false;
            continue;
        }
        if sanitize_env_split {
            output.push(redact_arguments(split_env_string(&argument), None).join(" "));
            sanitize_env_split = false;
            continue;
        }
        if sanitize_shell_command {
            output.push(redact_command(&argument));
            sanitize_shell_command = false;
            continue;
        }
        if redact_next {
            output.push("<redacted>".into());
            redact_next = false;
            continue;
        }
        if let Some(prefix) = sensitive_attached_short_option(&argument, &credential_executable) {
            output.push(format!("{prefix}<redacted>"));
            continue;
        }
        if let Some((key, _)) = argument.split_once('=')
            && (sensitive_key(key) || sensitive_option(key, &credential_executable))
        {
            output.push(format!("{key}=<redacted>"));
            continue;
        }
        if sensitive_header(&argument) || url_has_credentials(&argument) {
            output.push("<redacted>".into());
            continue;
        }
        if sensitive_key(&argument) || sensitive_option(&argument, &credential_executable) {
            redact_next = true;
        }
        if shell_wrapper && is_shell_command_flag(&argument) {
            sanitize_shell_command = true;
        }
        if matches!(argument.as_str(), "-S" | "--split-string") {
            sanitize_env_split = true;
        }
        if env_wrapper
            && matches!(
                argument.as_str(),
                "-u" | "--unset" | "-C" | "--chdir" | "-P"
            )
        {
            preserve_env_operand = true;
        }
        output.push(argument);
    }
    output
}

fn effective_runtime_executable<'a>(words: &'a [&'a str]) -> &'a str {
    let first = words.first().copied().unwrap_or_default();
    if Path::new(first)
        .file_name()
        .is_none_or(|name| name != "env")
    {
        return first;
    }
    let mut index = 1;
    while index < words.len() {
        let word = words[index];
        if matches!(word, "-u" | "--unset" | "-C" | "--chdir" | "-P") {
            index += 2;
        } else if word.starts_with('-') || word.contains('=') {
            index += 1;
        } else {
            return word;
        }
    }
    first
}

fn effective_argument_executable(arguments: &[String], explicit_program: Option<&str>) -> String {
    let initial = explicit_program
        .or_else(|| arguments.first().map(String::as_str))
        .unwrap_or_default();
    if Path::new(initial)
        .file_name()
        .is_some_and(|name| name == "env")
    {
        let start = usize::from(!arguments.is_empty());
        if let Some(identity) = env_launch_identity(&arguments[start..])
            && let Some(effective) = identity.first()
        {
            return effective.clone();
        }
    }
    arguments
        .iter()
        .find(|argument| uses_curl_short_options(argument))
        .cloned()
        .unwrap_or_else(|| initial.to_string())
}

fn sensitive_attached_short_option(value: &str, executable: &str) -> Option<&'static str> {
    if value.starts_with("--") {
        return None;
    }
    sensitive_short_options(executable)
        .into_iter()
        .find(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn sensitive_option(value: &str, executable: &str) -> bool {
    matches!(
        value,
        "--header"
            | "--proxy-header"
            | "--user"
            | "--proxy-user"
            | "--oauth2-bearer"
            | "--cookie"
            | "--cert-password"
            | "--key-password"
            | "--auth"
    ) || sensitive_short_options(executable).contains(&value)
        || (Path::new(executable)
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("redis-cli"))
            && value == "--pass")
}

fn sensitive_short_options(executable: &str) -> Vec<&'static str> {
    let name = Path::new(executable)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    match name.as_str() {
        "curl" => vec!["-H", "-u", "-b"],
        "mysql" | "mariadb" | "mysqladmin" | "mongosh" | "mongo" | "sshpass" => vec!["-p"],
        "redis-cli" => vec!["-a"],
        _ => Vec::new(),
    }
}

fn is_shell_command_flag(value: &str) -> bool {
    value.starts_with('-') && !value.starts_with("--") && value[1..].contains('c')
}

fn is_shell_executable(executable: &str) -> bool {
    Path::new(executable).file_name().is_some_and(|name| {
        matches!(
            name.to_string_lossy().as_ref(),
            "sh" | "bash" | "zsh" | "dash" | "ksh"
        )
    })
}

fn uses_curl_short_options(executable: &str) -> bool {
    Path::new(executable)
        .file_name()
        .is_some_and(|name| name.eq_ignore_ascii_case("curl"))
}

fn sensitive_header(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    upper.starts_with("AUTHORIZATION:")
        || upper.starts_with("PROXY-AUTHORIZATION:")
        || upper == "BEARER"
}

fn url_has_credentials(value: &str) -> bool {
    value.split_once("://").is_some_and(|(_, rest)| {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        authority
            .rsplit_once('@')
            .is_some_and(|(userinfo, _)| !userinfo.is_empty())
    })
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .trim_start_matches('-')
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    matches!(
        normalized.as_str(),
        "TOKEN"
            | "ACCESS_TOKEN"
            | "AUTH_TOKEN"
            | "PASSWORD"
            | "PASSWD"
            | "SECRET"
            | "CLIENT_SECRET"
            | "SECRET_KEY"
            | "PGPASSWORD"
            | "MYSQL_PWD"
            | "REDISCLI_AUTH"
            | "API_KEY"
            | "APIKEY"
            | "CREDENTIAL"
            | "CREDENTIALS"
            | "AUTHORIZATION"
            | "PROXY_AUTHORIZATION"
            | "AWS_SECRET_ACCESS_KEY"
            | "PRIVATE_KEY"
            | "SESSION_KEY"
    ) || normalized.ends_with("_TOKEN")
        || normalized.ends_with("_PASSWORD")
        || normalized.ends_with("_SECRET")
        || normalized.ends_with("_SECRET_KEY")
        || normalized.ends_with("_API_KEY")
        || normalized.ends_with("_ACCESS_KEY")
        || normalized.ends_with("_PRIVATE_KEY")
        || normalized.ends_with("_SESSION_KEY")
        || normalized.ends_with("_CREDENTIAL")
        || normalized.ends_with("_CREDENTIALS")
}

pub fn parse_elapsed(value: &str) -> Option<u64> {
    let (days, clock) = if let Some((days, clock)) = value.split_once('-') {
        (days.parse::<u64>().ok()?, clock)
    } else {
        (0, value)
    };
    let fields: Vec<u64> = clock
        .split(':')
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let seconds = match fields.as_slice() {
        [minutes, seconds] => minutes * 60 + seconds,
        [hours, minutes, seconds] => hours * 3600 + minutes * 60 + seconds,
        _ => return None,
    };
    Some(days * 86_400 + seconds)
}

pub fn parse_lsof_output(output: &str) -> Vec<ListenerEntry> {
    parse_lsof_output_with_tailscale_addresses(output, &BTreeSet::new())
}

pub fn parse_lsof_output_with_tailscale_addresses(
    output: &str,
    tailscale_addresses: &BTreeSet<IpAddr>,
) -> Vec<ListenerEntry> {
    let mut listeners = Vec::new();
    let mut pid = None;
    let mut command = None;

    for line in output.lines() {
        let Some((prefix, value)) = line.split_at_checked(1) else {
            continue;
        };
        match prefix {
            "p" => {
                pid = value.parse().ok();
                command = None;
            }
            "c" => command = Some(value.to_string()),
            "n" => {
                if let Some(pid) = pid {
                    let (port, wildcard, loopback, exposure) =
                        endpoint_traits(value, tailscale_addresses);
                    listeners.push(ListenerEntry {
                        pid,
                        command: command.clone(),
                        endpoint: value.to_string(),
                        port,
                        wildcard,
                        loopback,
                        exposure,
                    });
                }
            }
            _ => {}
        }
    }

    listeners
}

fn endpoint_traits(
    endpoint: &str,
    tailscale_addresses: &BTreeSet<IpAddr>,
) -> (Option<u16>, bool, bool, ListenerExposure) {
    let (address, port) = if endpoint.starts_with('[') {
        endpoint
            .rfind("]:")
            .map(|index| (&endpoint[..=index], &endpoint[index + 2..]))
            .unwrap_or((endpoint, ""))
    } else {
        endpoint.rsplit_once(':').unwrap_or((endpoint, ""))
    };
    let normalized = address.trim_matches(['[', ']']).to_ascii_lowercase();
    let textual_wildcard = matches!(normalized.as_str(), "*" | "0.0.0.0" | "::");
    let textual_loopback =
        normalized == "localhost" || normalized == "::1" || normalized.starts_with("127.");
    let exposure = if textual_wildcard {
        ListenerExposure::Wildcard
    } else if textual_loopback {
        ListenerExposure::Loopback
    } else {
        normalized
            .split('%')
            .next()
            .and_then(|address| address.parse::<IpAddr>().ok())
            .map(|address| classify_ip_exposure(address, tailscale_addresses))
            .unwrap_or(ListenerExposure::Unknown)
    };
    let wildcard = textual_wildcard || exposure == ListenerExposure::Wildcard;
    let loopback = textual_loopback || exposure == ListenerExposure::Loopback;
    (port.parse().ok(), wildcard, loopback, exposure)
}

fn classify_ip_exposure(
    address: IpAddr,
    tailscale_addresses: &BTreeSet<IpAddr>,
) -> ListenerExposure {
    if let IpAddr::V6(address) = address {
        let segments = address.segments();
        if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
            let mapped = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            );
            return classify_ip_exposure(IpAddr::V4(mapped), tailscale_addresses);
        }
    }
    match address {
        address if tailscale_addresses.contains(&address) => ListenerExposure::Tailscale,
        IpAddr::V4(address) if address.is_loopback() => ListenerExposure::Loopback,
        IpAddr::V6(address) if address.is_loopback() => ListenerExposure::Loopback,
        IpAddr::V4(address) if is_tailscale_ipv4(address) => ListenerExposure::Unknown,
        IpAddr::V6(address) if is_tailscale_ipv6(address) => ListenerExposure::Unknown,
        IpAddr::V4(address) if address.is_private() || address.is_link_local() => {
            ListenerExposure::Lan
        }
        IpAddr::V6(address) if address.is_unique_local() || address.is_unicast_link_local() => {
            ListenerExposure::Lan
        }
        IpAddr::V4(address) if address.is_unspecified() => ListenerExposure::Wildcard,
        IpAddr::V6(address) if address.is_unspecified() => ListenerExposure::Wildcard,
        IpAddr::V4(_) | IpAddr::V6(_) => ListenerExposure::Public,
    }
}

fn is_tailscale_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn is_tailscale_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

pub fn launch_item_identity(item: &LaunchItem) -> String {
    let scope = match item.scope {
        LaunchItemScope::UserAgent => "user-agent",
        LaunchItemScope::SystemAgent => "system-agent",
        LaunchItemScope::SystemDaemon => "system-daemon",
    };
    format!(
        "{scope}:{}:{:016x}",
        item.label,
        stable_hash(&item.path.display().to_string())
    )
}

pub fn detect_hygiene_findings(
    persistence: &PersistenceReport,
    runtime: &RuntimeReport,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for item in &persistence.launch_items {
        if item.keep_alive && !item.label.starts_with("com.apple.") && noteworthy_keep_alive(item) {
            let program = item
                .program
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown program".into());
            findings.push(Finding {
                id: format!("persistent-launch-item:{}", launch_item_identity(item)),
                category: FindingCategory::Persistence,
                severity: Severity::Warn,
                confidence: Confidence::High,
                title: "KeepAlive third-party launch item".into(),
                detail: format!(
                    "{} is configured to restart automatically and runs {program}.",
                    item.label
                ),
                evidence: vec![
                    item.path.display().to_string(),
                    format!("KeepAlive=true; RunAtLoad={}", item.run_at_load),
                ],
            });
        }

        if let Some(translocated_target) = item.translocation_target.clone() {
            findings.push(Finding {
                id: format!("translocated-launch-item:{}", launch_item_identity(item)),
                category: FindingCategory::Persistence,
                severity: Severity::Risk,
                confidence: Confidence::High,
                title: "Launch item points into AppTranslocation".into(),
                detail: format!(
                    "{} persists an executable from a temporary AppTranslocation path; this is usually stale or broken.",
                    item.label
                ),
                evidence: vec![
                    item.path.display().to_string(),
                    translocated_target,
                    format!("program_exists={:?}", item.program_exists),
                ],
            });
        }

        if item
            .program
            .as_ref()
            .is_some_and(|path| path.starts_with("/Library/PrivilegedHelperTools"))
            && item.parent_app_present == Some(false)
        {
            findings.push(Finding {
                id: format!("orphaned-privileged-helper:{}", launch_item_identity(item)),
                category: FindingCategory::Persistence,
                severity: Severity::Warn,
                confidence: if item.associated_bundle_ids.is_empty() {
                    Confidence::Medium
                } else {
                    Confidence::High
                },
                title: "Privileged helper lacks a strongly matched parent product".into(),
                detail: format!(
                    "{} installs a root-level helper, but no parent product could be matched with product-specific evidence.",
                    item.label
                ),
                evidence: vec![
                    item.path.display().to_string(),
                    item.program
                        .as_ref()
                        .map(|path| path.display().to_string())
                        .unwrap_or_default(),
                ],
            });
        }
    }

    let mut detached_listener_ids = BTreeSet::new();
    for listener in runtime
        .listeners
        .iter()
        .filter(|listener| !listener.loopback)
    {
        let Some(process) = runtime
            .processes
            .iter()
            .find(|process| process.pid == listener.pid)
        else {
            continue;
        };
        let launch_managed = persistence.launch_items.iter().any(|item| {
            process_matches_launch_item(item, &process.command, process.executable.as_deref())
        });
        if process.ppid == 1
            && process.elapsed_seconds >= OLD_EXPOSED_PROCESS_SECONDS
            && !launch_managed
            && !is_apple_system_process(&process.command)
        {
            let service = stable_service_signature(process);
            let endpoint = listener
                .port
                .map(|port| {
                    if listener.exposure == ListenerExposure::Wildcard {
                        format!("all-{port}")
                    } else {
                        format!("{:?}-{port}", listener.exposure).to_ascii_lowercase()
                    }
                })
                .unwrap_or_else(|| listener.endpoint.clone());
            let id = format!(
                "old-detached-listener:{:016x}:{endpoint}",
                stable_hash(&service)
            );
            if !detached_listener_ids.insert(id.clone()) {
                continue;
            }
            findings.push(Finding {
                id,
                category: FindingCategory::Runtime,
                severity: if matches!(
                    listener.exposure,
                    ListenerExposure::Wildcard | ListenerExposure::Public
                ) {
                    Severity::Risk
                } else {
                    Severity::Warn
                },
                confidence: Confidence::High,
                title: match listener.exposure {
                    ListenerExposure::Wildcard => {
                        "Old detached process listens on all interfaces".into()
                    }
                    ListenerExposure::Tailscale => {
                        "Old detached process listens on a Tailscale address".into()
                    }
                    ListenerExposure::Lan => "Old detached process listens on a LAN address".into(),
                    ListenerExposure::Public => {
                        "Old detached process listens on a public address".into()
                    }
                    ListenerExposure::Loopback | ListenerExposure::Unknown => {
                        "Old detached process has a non-loopback listener".into()
                    }
                },
                detail: format!(
                    "PID {} has PPID 1, has run for {}, and listens on {} ({:?}).",
                    process.pid,
                    format_duration(process.elapsed_seconds),
                    listener.endpoint,
                    listener.exposure
                ),
                evidence: vec![
                    format!("service_signature={service}"),
                    format!("pid={}", process.pid),
                    format!("ppid={}", process.ppid),
                    format!("pgid={}", process.pgid),
                    format!("uid={}", process.uid),
                    format!("port={}", listener.port.unwrap_or_default()),
                    format!("exposure={:?}", listener.exposure),
                    format!("command={}", process.command),
                    format!("endpoint={}", listener.endpoint),
                ],
            });
        }
    }

    let detached_browsers: Vec<&ProcessEntry> = runtime
        .processes
        .iter()
        .filter(|process| {
            process.ppid == 1
                && process.elapsed_seconds >= DETACHED_BROWSER_SECONDS
                && (process.command.contains("/.agent-browser/browsers/")
                    || process.command.contains("agent-browser-darwin"))
        })
        .collect();
    if !detached_browsers.is_empty() {
        findings.push(Finding {
            id: "detached-agent-browser-processes".into(),
            category: FindingCategory::Runtime,
            severity: Severity::Warn,
            confidence: Confidence::High,
            title: "Detached agent-browser processes".into(),
            detail: format!(
                "{} agent-browser/Chrome process(es) have PPID 1 and are older than six hours.",
                detached_browsers.len()
            ),
            evidence: detached_browsers
                .iter()
                .take(12)
                .map(|process| {
                    format!(
                        "pid={} ppid={} pgid={} uid={} command={}",
                        process.pid, process.ppid, process.pgid, process.uid, process.command
                    )
                })
                .collect(),
        });
    }

    let zombies: Vec<&ProcessEntry> = runtime
        .processes
        .iter()
        .filter(|process| process.state.contains('Z'))
        .collect();
    if !zombies.is_empty() {
        findings.push(Finding {
            id: "zombie-processes".into(),
            category: FindingCategory::Runtime,
            severity: Severity::Warn,
            confidence: Confidence::High,
            title: "Zombie processes detected".into(),
            detail: format!(
                "{} zombie process(es) need their parent process to reap or exit.",
                zombies.len()
            ),
            evidence: zombies
                .iter()
                .map(|process| {
                    let parent = runtime
                        .processes
                        .iter()
                        .find(|parent| parent.pid == process.ppid);
                    format!(
                        "pid={} ppid={} pgid={} uid={} parent_uid={} recommended_target_pid={} age={} command={} parent_command={}",
                        process.pid,
                        process.ppid,
                        process.pgid,
                        process.uid,
                        parent.map(|parent| parent.uid).unwrap_or_default(),
                        parent.map(|parent| parent.pid).unwrap_or(process.ppid),
                        format_duration(process.elapsed_seconds),
                        process.command,
                        parent
                            .map(|parent| parent.command.as_str())
                            .unwrap_or("<parent unavailable>")
                    )
                })
                .collect(),
        });
    }

    findings
}

pub fn stable_service_signature(process: &ProcessEntry) -> String {
    let mut words = process.command.split_whitespace();
    let command_executable = words.next().unwrap_or("unknown");
    let arguments = words.map(String::from).collect::<Vec<_>>();
    let executable = process
        .executable
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| command_executable.to_string());
    let executable_name = Path::new(&executable)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    if is_shared_interpreter(&executable_name)
        && let Some(identity) = interpreter_identity_arguments(&arguments, &executable_name)
    {
        return format!("{executable}|{}", identity.join("|"));
    }
    let subject = arguments.iter().map(String::as_str).find(|word| {
        !word.starts_with('-')
            && *word != "<redacted-tail>"
            && (word.contains('/')
                || word.ends_with(".js")
                || word.ends_with(".mjs")
                || word.ends_with(".py")
                || word.ends_with(".rb"))
    });
    subject
        .map(|subject| format!("{executable}|{subject}"))
        .unwrap_or(executable)
}

fn stable_hash(value: &str) -> u64 {
    // FNV-1a is deterministic across processes and Rust releases.
    value
        .as_bytes()
        .iter()
        .fold(0xcbf29ce484222325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

fn noteworthy_keep_alive(item: &LaunchItem) -> bool {
    if item.program_exists == Some(false) || item.label.to_ascii_lowercase().contains("uninstall") {
        return true;
    }
    let program = item
        .program
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    let noteworthy_path = |value: &str| {
        value.contains("/node_modules/")
            || value.contains("/projects/")
            || value.starts_with("/usr/local/")
    };
    item.scope == LaunchItemScope::UserAgent
        && (noteworthy_path(&program)
            || item
                .program_arguments
                .iter()
                .any(|argument| noteworthy_path(argument)))
}

fn is_apple_system_process(command: &str) -> bool {
    command.starts_with("/System/")
        || command.starts_with("/usr/libexec/")
        || command.starts_with("/usr/sbin/")
}

fn format_duration(seconds: u64) -> String {
    if seconds >= 86_400 {
        format!("{}d", seconds / 86_400)
    } else if seconds >= 3_600 {
        format!("{}h", seconds / 3_600)
    } else {
        format!("{}m", seconds / 60)
    }
}
