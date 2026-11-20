use std::path::Path;

use ignore::gitignore::{Gitignore, GitignoreBuilder};

use crate::config::{IgnoreRule, SyncFolderConfig, SyncMode};

// Internal sync-safety patterns so DeltaDrop never syncs its own atomic staging or conflict backups.
const INTERNAL_SAFETY_PATTERNS: &[&str] = &[
    ".deltadrop-tmp*",
    "*.deltadrop-tmp",
    "*.sync-conflict-*",
    ".deltadropignore.tmp",
];

pub struct IgnorePreset {
    pub name: &'static str,
    pub patterns: &'static [&'static str],
}

pub const IGNORE_PRESETS: &[IgnorePreset] = &[
    IgnorePreset {
        name: "Unity",
        patterns: &[
            "Library/",
            "Temp/",
            "Obj/",
            "Build/",
            "Builds/",
            "Logs/",
            "UserSettings/",
            "MemoryCaptures/",
            "*.csproj",
            "*.sln",
            "*.pidb",
            "*.booproj",
            "*.svd",
            "*.pdb",
            "*.mdb",
            "*.opendb",
            "*.VC.db",
        ],
    },
    IgnorePreset {
        name: "Rust",
        patterns: &["target/", "**/*.rs.bk"],
    },
    IgnorePreset {
        name: "Node / Web",
        patterns: &[
            "node_modules/",
            ".next/",
            ".nuxt/",
            "dist/",
            "build/",
            ".cache/",
            ".turbo/",
        ],
    },
    IgnorePreset {
        name: "Python",
        patterns: &[
            "__pycache__/",
            ".venv/",
            "venv/",
            "*.pyc",
            ".pytest_cache/",
            ".mypy_cache/",
        ],
    },
    IgnorePreset {
        name: "C / C++ / IDE",
        patterns: &[
            "build/",
            "cmake-build-*/",
            ".vs/",
            ".idea/",
            ".vscode/*.log",
            "*.o",
            "*.obj",
            "*.exe",
        ],
    },
    IgnorePreset {
        name: "Git / OS Junk",
        patterns: &[".git/", ".DS_Store", "Thumbs.db", "desktop.ini"],
    },
];

pub struct IgnoreFilter {
    matcher: Gitignore,
}

impl IgnoreFilter {
    pub fn for_folder_config(folder: &SyncFolderConfig) -> Self {
        let mut builder = GitignoreBuilder::new(&folder.path);
        for pat in INTERNAL_SAFETY_PATTERNS {
            let _ = builder.add_line(None, pat);
        }
        for rule in &folder.ignore_rules {
            if rule.enabled {
                let trimmed = rule.pattern.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    let _ = builder.add_line(None, trimmed);
                }
            }
        }
        for line in folder.custom_ignore.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                let _ = builder.add_line(None, trimmed);
            }
        }
        let ignore_file = folder.path.join(".deltadropignore");
        if ignore_file.is_file() {
            let _ = builder.add(ignore_file);
        }
        let matcher = builder.build().unwrap_or_else(|_| Gitignore::empty());
        Self { matcher }
    }

    /// Returns true if the relative path (forward-slash normalized) should be synced.
    pub fn should_sync(&self, folder: &SyncFolderConfig, rel_path: &str, is_dir: bool) -> bool {
        if folder.mode == SyncMode::Whitelist {
            let Some(top_dir) = rel_path.split('/').next() else {
                return false;
            };
            if !is_dir && !rel_path.contains('/') {
                return false;
            }
            if !folder.whitelist_subdirs.iter().any(|s| s == top_dir) {
                return false;
            }
        }

        let check_path = folder.path.join(rel_path);
        !self
            .matcher
            .matched_path_or_any_parents(&check_path, is_dir)
            .is_ignore()
    }

    /// Live preview helper for the UI "Test Path" input.
    /// Returns `true` if `sample_rel_path` would be ignored, `false` if it would be synced.
    pub fn test_path_ignored(&self, folder: &SyncFolderConfig, sample_rel_path: &str) -> bool {
        let normalized = sample_rel_path.trim().replace('\\', "/");
        let is_dir = normalized.ends_with('/');
        let rel = normalized.trim_matches('/');
        if rel.is_empty() {
            return false;
        }
        !self.should_sync(folder, rel, is_dir)
    }
}

/// Auto-detects project markers in `dir` and returns matching enabled ignore rules.
pub fn detect_project_ignore_rules(dir: &Path) -> Vec<IgnoreRule> {
    let mut rules = Vec::new();
    let mut push_preset = |name: &str| {
        if let Some(preset) = IGNORE_PRESETS.iter().find(|p| p.name == name) {
            for &pat in preset.patterns {
                if !rules.iter().any(|r: &IgnoreRule| r.pattern == pat) {
                    rules.push(IgnoreRule {
                        pattern: pat.to_string(),
                        enabled: true,
                    });
                }
            }
        }
    };

    if dir.join(".git").exists() {
        push_preset("Git / OS Junk");
    }
    if dir.join("Cargo.toml").is_file() {
        push_preset("Rust");
    }
    if dir.join("package.json").is_file() {
        push_preset("Node / Web");
    }
    if dir.join("Assets").is_dir() && dir.join("ProjectSettings").is_dir() {
        push_preset("Unity");
    }
    if dir.join(".venv").is_dir()
        || dir.join("venv").is_dir()
        || dir.join("pyproject.toml").is_file()
        || dir.join("requirements.txt").is_file()
    {
        push_preset("Python");
    }
    if dir.join("CMakeLists.txt").is_file() || dir.join(".vs").is_dir() {
        push_preset("C / C++ / IDE");
    }
    rules
}

/// Writes `.deltadropignore` in `folder.path` as the single synced source of truth.
pub fn write_ignore_file_from_folder(folder: &SyncFolderConfig) -> std::io::Result<()> {
    if !folder.path.is_dir() {
        return Ok(());
    }
    let mut lines = Vec::new();
    for r in &folder.ignore_rules {
        if r.enabled {
            let p = r.pattern.trim();
            if !p.is_empty() {
                lines.push(p.to_string());
            }
        }
    }
    for line in folder.custom_ignore.lines() {
        let p = line.trim();
        if !p.is_empty() && !lines.iter().any(|x| x == p) {
            lines.push(p.to_string());
        }
    }
    let ignore_path = folder.path.join(".deltadropignore");
    if lines.is_empty() {
        if ignore_path.is_file() {
            let _ = std::fs::remove_file(&ignore_path);
        }
        return Ok(());
    }
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(&ignore_path, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IgnoreRule;

    #[test]
    fn respects_user_rules_toggles_custom_text_and_whitelist() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".deltadropignore"), "secret/\n").unwrap();

        let full_folder = SyncFolderConfig {
            id: "code".into(),
            label: None,
            path: root.path().to_path_buf(),
            mode: SyncMode::Full,
            whitelist_subdirs: vec![],
            ignore_rules: vec![
                IgnoreRule {
                    pattern: "target/".into(),
                    enabled: true,
                },
                IgnoreRule {
                    pattern: "node_modules/".into(),
                    enabled: false,
                },
            ],
            custom_ignore: "*.log\n".into(),
        };
        let filter = IgnoreFilter::for_folder_config(&full_folder);

        assert!(filter.should_sync(&full_folder, "src/main.rs", false));
        assert!(!filter.should_sync(&full_folder, "target/debug/app", false));
        // Disabled rule does not ignore node_modules/
        assert!(filter.should_sync(&full_folder, "node_modules/pkg/index.js", false));
        assert!(!filter.should_sync(&full_folder, "app.log", false));
        assert!(!filter.should_sync(&full_folder, "secret/key.txt", false));
        assert!(!filter.should_sync(&full_folder, "foo.sync-conflict-123.rs", false));

        let wl_folder = SyncFolderConfig {
            id: "projects".into(),
            label: None,
            path: root.path().to_path_buf(),
            mode: SyncMode::Whitelist,
            whitelist_subdirs: vec!["Alpha".into()],
            ignore_rules: vec![IgnoreRule {
                pattern: "Library/".into(),
                enabled: true,
            }],
            custom_ignore: String::new(),
        };
        let wl_filter = IgnoreFilter::for_folder_config(&wl_folder);
        assert!(wl_filter.should_sync(&wl_folder, "Alpha/Assets/Player.cs", false));
        assert!(!wl_filter.should_sync(&wl_folder, "Alpha/Library/cache.db", false));
        assert!(!wl_filter.should_sync(&wl_folder, "Beta/Assets/Player.cs", false));
        assert!(!wl_filter.should_sync(&wl_folder, "root_file.txt", false));
    }

    #[test]
    fn supports_negation_and_live_test_path_preview() {
        let root = tempfile::tempdir().unwrap();
        let folder = SyncFolderConfig {
            id: "web".into(),
            label: None,
            path: root.path().to_path_buf(),
            mode: SyncMode::Full,
            whitelist_subdirs: vec![],
            ignore_rules: vec![],
            custom_ignore: "*.log\n!important.log\ndist/\n".into(),
        };
        let filter = IgnoreFilter::for_folder_config(&folder);
        assert!(filter.test_path_ignored(&folder, "debug.log"));
        assert!(!filter.test_path_ignored(&folder, "important.log"));
        assert!(filter.test_path_ignored(&folder, "dist/bundle.js"));
        assert!(filter.test_path_ignored(&folder, ".deltadropignore.tmp"));
        assert!(!filter.test_path_ignored(&folder, "src/index.ts"));
    }
}
