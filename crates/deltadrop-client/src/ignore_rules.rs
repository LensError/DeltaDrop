use std::path::Path;

use ignore::gitignore::{Gitignore, GitignoreBuilder};

// Internal safety patterns so DeltaDrop never syncs temp staging files or conflict backups.
const INTERNAL_SAFETY_PATTERNS: &[&str] = &[
    ".deltadrop-tmp*",
    "*.deltadrop-tmp*",
    "*.sync-conflict-*",
    ".deltadropignore",
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
    root: std::path::PathBuf,
    matcher: Gitignore,
}

impl IgnoreFilter {
    pub fn from_patterns(root: &Path, patterns: &[String]) -> Self {
        let mut builder = GitignoreBuilder::new(root);
        for pat in INTERNAL_SAFETY_PATTERNS {
            let _ = builder.add_line(None, pat);
        }
        for pat in patterns {
            let trimmed = pat.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                let _ = builder.add_line(None, trimmed);
            }
        }
        let ignore_file = root.join(".deltadropignore");
        if ignore_file.is_file() {
            let _ = builder.add(ignore_file);
        }
        let matcher = builder.build().unwrap_or_else(|_| Gitignore::empty());
        Self {
            root: root.to_path_buf(),
            matcher,
        }
    }

    pub fn should_sync(&self, rel_path: &str, is_dir: bool) -> bool {
        let check_path = self.root.join(rel_path);
        !self
            .matcher
            .matched_path_or_any_parents(&check_path, is_dir)
            .is_ignore()
    }

    pub fn test_path_ignored(&self, sample_rel_path: &str) -> bool {
        let normalized = sample_rel_path.trim().replace('\\', "/");
        let is_dir = normalized.ends_with('/');
        let rel = normalized.trim_matches('/');
        if rel.is_empty() {
            return false;
        }
        !self.should_sync(rel, is_dir)
    }
}

/// Auto-detects project markers in `dir` and returns matching ignore patterns.
pub fn detect_project_ignore_patterns(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut push_preset = |name: &str| {
        if let Some(preset) = IGNORE_PRESETS.iter().find(|p| p.name == name) {
            for &pat in preset.patterns {
                if !out.iter().any(|p: &String| p == pat) {
                    out.push(pat.to_string());
                }
            }
        }
    };

    // Always include OS junk on any folder; add .git if present
    push_preset("Git / OS Junk");
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
    out
}

pub fn preset_is_enabled(patterns: &[String], preset: &IgnorePreset) -> bool {
    preset
        .patterns
        .iter()
        .any(|pat| patterns.iter().any(|p| p == pat))
}

pub fn toggle_preset_patterns(patterns: &mut Vec<String>, preset: &IgnorePreset, enable: bool) {
    if enable {
        for &pat in preset.patterns {
            if !patterns.iter().any(|p| p == pat) {
                patterns.push(pat.to_string());
            }
        }
    } else {
        patterns.retain(|p| !preset.patterns.contains(&p.as_str()));
    }
}

pub fn write_ignore_file(root: &Path, patterns: &[String]) -> std::io::Result<()> {
    if !root.is_dir() {
        return Ok(());
    }
    let ignore_path = root.join(".deltadropignore");
    let clean: Vec<&str> = patterns
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if clean.is_empty() {
        if ignore_path.is_file() {
            let _ = std::fs::remove_file(&ignore_path);
        }
        return Ok(());
    }
    let mut body = clean.join("\n");
    body.push('\n');
    std::fs::write(&ignore_path, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unity_and_rust_and_filters_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Assets")).unwrap();
        std::fs::create_dir_all(dir.path().join("ProjectSettings")).unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\n").unwrap();

        let pats = detect_project_ignore_patterns(dir.path());
        let filter = IgnoreFilter::from_patterns(dir.path(), &pats);
        assert!(!filter.should_sync("Library/ArtifactDB", false));
        assert!(!filter.should_sync("target/debug/app.exe", false));
        assert!(!filter.should_sync(".git/HEAD", false));
        assert!(!filter.should_sync("foo.sync-conflict-pc-123.cs", false));
        assert!(filter.should_sync("Assets/Scripts/Player.cs", false));
        assert!(filter.should_sync("src/main.rs", false));
    }
}
