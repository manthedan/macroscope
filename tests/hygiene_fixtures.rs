use macroscope::hygiene::{
    command_mentions_path, correlate_parent_apps, detect_hygiene_findings, parse_launch_item_bytes,
    parse_lsof_output, parse_lsof_output_with_tailscale_addresses, parse_ps_executables,
    parse_ps_output, process_matches_launch_item, redact_command,
};
use macroscope::model::{AppsReport, LaunchItemScope, PersistenceReport, RuntimeReport};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn empty_apps() -> AppsReport {
    AppsReport {
        scanned_roots: Vec::new(),
        apps: Vec::new(),
        duplicate_bundle_ids: BTreeMap::new(),
        errors: Vec::new(),
        root_errors: Vec::new(),
    }
}

#[test]
fn detects_keepalive_translocation_and_orphaned_helper_fixtures() {
    let fixtures = [
        (
            "/Users/example/Library/LaunchAgents/com.example.gateway.plist",
            LaunchItemScope::UserAgent,
            include_bytes!("fixtures/keepalive-launchagent.plist").as_slice(),
        ),
        (
            "/Users/example/Library/LaunchAgents/com.example.TranslocatedHelper.plist",
            LaunchItemScope::UserAgent,
            include_bytes!("fixtures/broken-apptranslocation.plist").as_slice(),
        ),
        (
            "/Library/LaunchDaemons/com.fixturevendorzz.AppPlayer.privilegedhelper.plist",
            LaunchItemScope::SystemDaemon,
            include_bytes!("fixtures/orphan-privileged-helper.plist").as_slice(),
        ),
    ];

    let mut launch_items = fixtures
        .iter()
        .map(|(path, scope, bytes)| {
            parse_launch_item_bytes(&PathBuf::from(path), *scope, bytes)
                .expect("fixture plist should parse")
        })
        .collect::<Vec<_>>();
    launch_items.push(
        parse_launch_item_bytes(
            &PathBuf::from("/Users/example/Library/LaunchAgents/wrapped-translocation.plist"),
            LaunchItemScope::UserAgent,
            br#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
            <key>Label</key><string>wrapped-translocation</string>
            <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
            <string>tool --token secret /private/var/folders/example/T/AppTranslocation/WRAPPED/d/App</string>
            </array></dict></plist>"#,
        )
        .unwrap(),
    );
    launch_items.push(
        parse_launch_item_bytes(
            &PathBuf::from("/Users/example/Library/LaunchAgents/project-service.plist"),
            LaunchItemScope::UserAgent,
            br#"<?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
            <key>Label</key><string>project-service</string><key>KeepAlive</key><true/>
            <key>ProgramArguments</key><array><string>/bin/sh</string>
            <string>/Users/example/projects/service.sh</string></array>
            </dict></plist>"#,
        )
        .unwrap(),
    );
    let mut duplicate_scope = launch_items[0].clone();
    duplicate_scope.scope = LaunchItemScope::SystemDaemon;
    duplicate_scope.path = "/Library/LaunchDaemons/com.example.gateway.plist".into();
    launch_items.push(duplicate_scope);
    correlate_parent_apps(&mut launch_items, &empty_apps());

    let findings = detect_hygiene_findings(
        &PersistenceReport {
            launch_items,
            errors: Vec::new(),
        },
        &RuntimeReport::default(),
    );
    let ids = findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>();

    assert!(
        ids.iter()
            .any(|id| id.starts_with("persistent-launch-item:user-agent:com.example.gateway:"))
    );
    assert!(
        ids.iter()
            .any(|id| id.starts_with("persistent-launch-item:system-daemon:com.example.gateway:"))
    );
    assert!(
        ids.iter()
            .any(|id| id.starts_with("persistent-launch-item:user-agent:project-service:"))
    );
    assert!(ids.iter().any(|id| {
        id.starts_with("translocated-launch-item:user-agent:com.example.TranslocatedHelper:")
    }));
    assert!(ids.iter().any(|id| {
        id.starts_with("translocated-launch-item:user-agent:wrapped-translocation:")
    }));
    assert!(ids.iter().any(|id| id.starts_with(
        "orphaned-privileged-helper:system-daemon:com.fixturevendorzz.AppPlayer.privilegedhelper:"
    )));
}

#[test]
fn matches_launch_programs_on_command_boundaries() {
    assert!(command_mentions_path(
        "/usr/local/bin/foo --serve",
        "/usr/local/bin/foo"
    ));
    assert!(!command_mentions_path(
        "/usr/local/bin/foobar --serve",
        "/usr/local/bin/foo"
    ));
    let launch = parse_launch_item_bytes(
        &PathBuf::from("/Users/example/Library/LaunchAgents/com.example.gateway.plist"),
        LaunchItemScope::UserAgent,
        include_bytes!("fixtures/keepalive-launchagent.plist"),
    )
    .unwrap();
    assert!(process_matches_launch_item(
        &launch,
        "/Users/example/.nvm/versions/node/v22/bin/node /Users/example/.nvm/versions/node/v22/lib/node_modules/example/dist/entry.js gateway",
        None,
    ));
    assert!(!process_matches_launch_item(
        &launch,
        "/Users/example/.nvm/versions/node/v22/bin/node /Users/example/other.js",
        None,
    ));
    let relative = parse_launch_item_bytes(
        &PathBuf::from("/tmp/relative.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>Label</key><string>relative</string>
        <key>ProgramArguments</key><array><string>sh</string><string>/srv/task.sh</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(
        relative.program.as_deref(),
        Some(std::path::Path::new("/bin/sh"))
    );
    assert!(process_matches_launch_item(
        &relative,
        "/bin/sh /srv/task.sh",
        Some(std::path::Path::new("/bin/sh")),
    ));
    let explicit_relative = parse_launch_item_bytes(
        &PathBuf::from("/tmp/explicit-relative.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>Label</key><string>invalid-relative</string>
        <key>Program</key><string>sh</string><key>ProgramArguments</key>
        <array><string>sh</string><string>/srv/task.sh</string></array>
        </dict></plist>"#,
    )
    .unwrap();
    assert_eq!(
        explicit_relative.program.as_deref(),
        Some(std::path::Path::new("sh"))
    );
    let mut native = launch.clone();
    native.program = Some("/path/server".into());
    native.program_arguments = vec![
        "/path/server".into(),
        "--config".into(),
        "/srv/a.conf".into(),
    ];
    assert!(process_matches_launch_item(
        &native,
        "/path/server --config /srv/a.conf",
        Some(std::path::Path::new("/path/server")),
    ));
    assert!(!process_matches_launch_item(
        &native,
        "/path/server --config /srv/b.conf",
        Some(std::path::Path::new("/path/server")),
    ));
    let mut python_module = native.clone();
    python_module.program = Some("/usr/bin/python3".into());
    python_module.program_arguments = vec![
        "/usr/bin/python3".into(),
        "-m".into(),
        "uvicorn".into(),
        "app_a:app".into(),
    ];
    assert!(!process_matches_launch_item(
        &python_module,
        "/usr/bin/python3 -m uvicorn app_b:app",
        Some(std::path::Path::new("/usr/bin/python3")),
    ));
    python_module.program_arguments = vec![
        "/usr/bin/python3".into(),
        "-W".into(),
        "ignore".into(),
        "-m".into(),
        "uvicorn".into(),
        "app_a:app".into(),
    ];
    assert!(!process_matches_launch_item(
        &python_module,
        "/usr/bin/python3 -W ignore -m uvicorn app_b:app",
        Some(std::path::Path::new("/usr/bin/python3")),
    ));
    let mut credentialed_node = launch.clone();
    credentialed_node.program_arguments = vec![
        credentialed_node
            .program
            .as_ref()
            .unwrap()
            .display()
            .to_string(),
        "/srv/app.js".into(),
        "--api-key=<redacted>".into(),
    ];
    assert!(process_matches_launch_item(
        &credentialed_node,
        "/Users/example/.nvm/versions/node/v22/bin/node /srv/app.js --api-key <redacted-tail>",
        None,
    ));
    let shell_credential = parse_launch_item_bytes(
        &PathBuf::from("/tmp/shell-credential.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>Label</key><string>shell-credential</string>
        <key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string>
        <string>/srv/api --token secret</string></array></dict></plist>"#,
    )
    .unwrap();
    assert!(process_matches_launch_item(
        &shell_credential,
        "/bin/sh -c /srv/api --token <redacted-tail>",
        None,
    ));
    let mut ruby = native.clone();
    ruby.program = Some("/usr/bin/ruby".into());
    ruby.program_arguments = vec![
        "/usr/bin/ruby".into(),
        "-I".into(),
        "/shared/lib".into(),
        "/srv/a.rb".into(),
    ];
    assert!(!process_matches_launch_item(
        &ruby,
        "/usr/bin/ruby -I /shared/lib /srv/b.rb",
        Some(std::path::Path::new("/usr/bin/ruby")),
    ));
    let mut preload = launch.clone();
    preload.program_arguments = vec![
        preload.program.as_ref().unwrap().display().to_string(),
        "--require".into(),
        "/shared/preload.js".into(),
        "/service-a.js".into(),
    ];
    assert!(!process_matches_launch_item(
        &preload,
        "/Users/example/.nvm/versions/node/v22/bin/node --require /shared/preload.js /service-b.js",
        None,
    ));
    let mut wrapped = launch;
    wrapped.program = Some("/usr/bin/env".into());
    wrapped.program_arguments = vec!["/usr/bin/env".into(), "node".into(), "/service-a.js".into()];
    assert!(process_matches_launch_item(
        &wrapped,
        "/opt/homebrew/bin/node /service-a.js",
        None,
    ));
    wrapped.program_arguments = vec![
        "/usr/bin/env".into(),
        "-S".into(),
        "node /service-a.js".into(),
    ];
    assert!(process_matches_launch_item(
        &wrapped,
        "/opt/homebrew/bin/node /service-a.js",
        None,
    ));
    wrapped.program_arguments = vec![
        "/usr/bin/env".into(),
        "-P".into(),
        "/opt/tools".into(),
        "node".into(),
        "/service-a.js".into(),
    ];
    assert!(process_matches_launch_item(
        &wrapped,
        "/opt/homebrew/bin/node /service-a.js",
        None,
    ));
    wrapped.program_arguments = vec![
        "/usr/bin/env".into(),
        "-S".into(),
        "node \"/path with spaces/app.js\"".into(),
    ];
    assert!(process_matches_launch_item(
        &wrapped,
        "/opt/homebrew/bin/node /path with spaces/app.js",
        None,
    ));

    let mut explicit = preload;
    explicit.program = Some("/usr/bin/python3".into());
    explicit.program_from_arguments = false;
    explicit.program_arguments = vec!["custom-argv0".into(), "/srv/app.py".into()];
    assert!(process_matches_launch_item(
        &explicit,
        "custom-argv0 /srv/app.py",
        Some(PathBuf::from("/usr/bin/python3").as_path()),
    ));
}

#[test]
fn redacts_common_command_line_secrets() {
    assert_eq!(
        redact_command("TOKEN=abc tool --api-key hunter2 --mode safe CLIENT_SECRET=value"),
        "TOKEN=<redacted-tail>"
    );
    assert_eq!(
        redact_command("tool --api-key=correct horse --mode safe"),
        "tool --api-key=<redacted-tail>"
    );
    assert_eq!(
        redact_command("tool --password secret phrase --mode safe"),
        "tool --password <redacted-tail>"
    );
    assert_eq!(
        redact_command("AWS_SECRET_ACCESS_KEY=value tool"),
        "AWS_SECRET_ACCESS_KEY=<redacted-tail>"
    );
    assert_eq!(
        redact_command("curl -H Authorization: Bearer token https://example.test"),
        "curl -H <redacted-tail>"
    );
    assert_eq!(
        redact_command("client https://user:password@example.test/path"),
        "client <redacted-url>"
    );
    assert_eq!(
        redact_command("git clone https://ghp_secret@github.com/org/repo"),
        "git clone <redacted-url>"
    );
    assert_eq!(
        redact_command("curl --user alice:secret https://example.test"),
        "curl --user <redacted-tail>"
    );
    assert_eq!(
        redact_command("curl --oauth2-bearer=secret https://example.test"),
        "curl --oauth2-bearer=<redacted-tail>"
    );
    assert_eq!(
        redact_command("curl -ualice:secret https://example.test"),
        "curl -u<redacted-tail>"
    );
    assert_eq!(
        redact_command("curl -HAuthorization:Bearer-token https://example.test"),
        "curl -H<redacted-tail>"
    );
    assert_eq!(
        redact_command("python3 -u /srv/service.py"),
        "python3 -u /srv/service.py"
    );
    assert_eq!(
        redact_command("mysql -psecret database"),
        "mysql -p<redacted-tail>"
    );
    assert_eq!(
        redact_command("sshpass -p secret ssh host"),
        "sshpass -p <redacted-tail>"
    );
    assert_eq!(
        redact_command("/usr/bin/env mysql -psecret database"),
        "/usr/bin/env mysql -p<redacted-tail>"
    );
    assert_eq!(
        redact_command("mysql -p hunter2; curl https://example.test"),
        "mysql -p <redacted-tail>"
    );
    assert_eq!(
        redact_command("redis-cli --pass hunter2 ping"),
        "redis-cli --pass <redacted-tail>"
    );
    assert_eq!(
        redact_command("redis-cli '--pass' hunter2"),
        "redis-cli '--pass' <redacted-tail>"
    );
    assert_eq!(
        redact_command("python3 --secret-key hunter2 app.py"),
        "python3 --secret-key <redacted-tail>"
    );
    assert_eq!(
        redact_command("/usr/bin/env SECRET_KEY=hunter2 python3 app.py"),
        "/usr/bin/env SECRET_KEY=<redacted-tail>"
    );
    assert_eq!(
        redact_command("/usr/bin/env PGPASSWORD=hunter2 psql"),
        "/usr/bin/env PGPASSWORD=<redacted-tail>"
    );
    assert_eq!(
        redact_command("/bin/sh -c 'curl -u alice:secret https://example.test'"),
        "/bin/sh -c curl -u <redacted-tail>"
    );
    assert_eq!(
        redact_command("/bin/sh -c 'echo ready; curl -u alice:secret https://example.test'"),
        "/bin/sh -c echo ready; curl -u <redacted-tail>"
    );
    let wrapped = parse_launch_item_bytes(
        &PathBuf::from("/tmp/wrapped-curl.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>wrapped-curl</string>
        <key>ProgramArguments</key><array>
        <string>/usr/bin/env</string><string>curl</string>
        <string>-ualice:hunter2</string><string>https://example.test</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(wrapped.program_arguments[2], "-u<redacted>");

    let shell_wrapped = parse_launch_item_bytes(
        &PathBuf::from("/tmp/wrapped-shell.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>wrapped-shell</string>
        <key>ProgramArguments</key><array>
        <string>/bin/sh</string><string>-c</string>
        <string>curl -u alice:hunter2 https://example.test</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(
        shell_wrapped.program_arguments[2],
        "curl -u <redacted-tail>"
    );
    let env_shell = parse_launch_item_bytes(
        &PathBuf::from("/tmp/env-shell.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>env-shell</string>
        <key>ProgramArguments</key><array>
        <string>/usr/bin/env</string><string>zsh</string><string>-lc</string>
        <string>curl -u alice:hunter2 https://example.test</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(env_shell.program_arguments[3], "curl -u <redacted-tail>");
    let env_split = parse_launch_item_bytes(
        &PathBuf::from("/tmp/env-split.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>env-split</string>
        <key>ProgramArguments</key><array>
        <string>/usr/bin/env</string><string>-S</string>
        <string>API_TOKEN=secret node /srv/app.js</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(
        env_split.program_arguments[2],
        "API_TOKEN=<redacted> node /srv/app.js"
    );
    let explicit_shell = parse_launch_item_bytes(
        &PathBuf::from("/tmp/explicit-shell.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>explicit-shell</string>
        <key>Program</key><string>/bin/sh</string>
        <key>ProgramArguments</key><array><string>custom</string><string>-c</string>
        <string>curl -u alice:secret https://example.test</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(
        explicit_shell.program_arguments[2],
        "curl -u <redacted-tail>"
    );
    let env_mysql = parse_launch_item_bytes(
        &PathBuf::from("/tmp/env-mysql.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>env-mysql</string>
        <key>ProgramArguments</key><array><string>/usr/bin/env</string>
        <string>mysql</string><string>-psecret</string><string>database</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(env_mysql.program_arguments[2], "-p<redacted>");
    let wrapped_mysql = parse_launch_item_bytes(
        &PathBuf::from("/tmp/nice-mysql.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>Label</key><string>nice-mysql</string>
        <key>Program</key><string>/usr/bin/nice</string><key>ProgramArguments</key>
        <array><string>nice</string><string>mysql</string><string>-psecret</string></array>
        </dict></plist>"#,
    )
    .unwrap();
    assert_eq!(wrapped_mysql.program_arguments[2], "-p<redacted>");
    let env_unset = parse_launch_item_bytes(
        &PathBuf::from("/tmp/env-unset.plist"),
        LaunchItemScope::UserAgent,
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
        <key>Label</key><string>env-unset</string>
        <key>ProgramArguments</key><array><string>/usr/bin/env</string>
        <string>-u</string><string>API_TOKEN</string><string>node</string><string>/srv/app.js</string>
        </array></dict></plist>"#,
    )
    .unwrap();
    assert_eq!(env_unset.program_arguments[2], "API_TOKEN");
    assert!(process_matches_launch_item(
        &env_unset,
        "/opt/homebrew/bin/node /srv/app.js",
        None,
    ));
}

#[test]
fn preserves_process_executable_paths_with_spaces() {
    let executables =
        parse_ps_executables("  42 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n");
    assert_eq!(
        executables.get(&42).unwrap(),
        &PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    );
}

#[test]
fn detects_exposed_orphan_browser_group_and_zombie_from_runtime_fixtures() {
    let processes = parse_ps_output(include_str!("fixtures/ps-runtime.txt"));
    let listeners = parse_lsof_output(include_str!("fixtures/lsof-runtime.txt"));

    assert_eq!(processes.len(), 4);
    assert_eq!(listeners.len(), 2);
    assert!(listeners[0].wildcard);
    assert!(!listeners[0].loopback);
    assert_eq!(
        listeners[0].exposure,
        macroscope::model::ListenerExposure::Wildcard
    );
    assert!(listeners[1].loopback);
    assert_eq!(
        listeners[1].exposure,
        macroscope::model::ListenerExposure::Loopback
    );
    let tailscale_address = "100.100.20.30".parse().unwrap();
    let classified = parse_lsof_output_with_tailscale_addresses(
        "p1\ncserver\nn100.100.20.30:8765\np2\ncserver\nn192.168.1.20:9000\np3\ncserver\nn203.0.113.10:443\np4\ncserver\nn[::ffff:127.0.0.1]:8080\np5\ncserver\nn[::ffff:192.168.1.10]:8081\np6\ncserver\nn[::ffff:0.0.0.0]:8082\n",
        &BTreeSet::from([tailscale_address]),
    );
    assert_eq!(
        classified[0].exposure,
        macroscope::model::ListenerExposure::Tailscale
    );
    assert_eq!(
        parse_lsof_output("p1\ncserver\nn100.100.20.30:8765\n")[0].exposure,
        macroscope::model::ListenerExposure::Unknown
    );
    assert_eq!(
        classified[1].exposure,
        macroscope::model::ListenerExposure::Lan
    );
    assert_eq!(
        classified[2].exposure,
        macroscope::model::ListenerExposure::Public
    );
    assert_eq!(
        classified[3].exposure,
        macroscope::model::ListenerExposure::Loopback
    );
    assert!(classified[3].loopback);
    assert_eq!(
        classified[4].exposure,
        macroscope::model::ListenerExposure::Lan
    );
    assert_eq!(
        classified[5].exposure,
        macroscope::model::ListenerExposure::Wildcard
    );
    assert!(classified[5].wildcard);

    let findings = detect_hygiene_findings(
        &PersistenceReport::default(),
        &RuntimeReport {
            processes,
            listeners,
            errors: Vec::new(),
        },
    );
    let ids = findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<Vec<_>>();

    assert!(
        ids.iter()
            .any(|id| { id.starts_with("old-detached-listener:") && id.ends_with(":all-5183") })
    );
    assert!(ids.contains(&"detached-agent-browser-processes"));
    assert!(ids.contains(&"zombie-processes"));
    let zombie = findings
        .iter()
        .find(|finding| finding.id == "zombie-processes")
        .unwrap();
    assert!(zombie.evidence[0].contains("pgid=6194"));
    assert!(zombie.evidence[0].contains("parent_command=/Users/example/.local/bin/grok"));
    assert!(zombie.evidence[0].contains("recommended_target_pid=6194"));
}
