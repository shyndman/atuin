use std::{io::prelude::*, path::PathBuf};

use config::{Config, Environment, File as ConfigFile, FileFormat};
use eyre::{Result, eyre};
use fs_err::{File, create_dir_all};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::debug;

static EXAMPLE_CONFIG: &str = include_str!("../server.toml");

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Mail {
    #[serde(alias = "enable")]
    pub enabled: bool,

    /// Configuration for the postmark api client
    /// This is what we use for Atuin Cloud, the forum, etc.
    #[serde(default)]
    pub postmark: Postmark,

    #[serde(default)]
    pub verification: MailVerification,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct Postmark {
    #[serde(alias = "token")]
    pub token: Option<String>,
}

#[derive(Default, Clone, Debug, Deserialize, Serialize)]
pub struct MailVerification {
    #[serde(alias = "enable")]
    pub from: String,
    pub subject: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Metrics {
    #[serde(alias = "enabled")]
    pub enable: bool,
    pub host: String,
    pub port: u16,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            enable: false,
            host: String::from("127.0.0.1"),
            port: 9001,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings<DbSettings> {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub open_registration: bool,
    pub max_history_length: usize,
    pub max_record_size: usize,
    pub page_size: i64,
    pub register_webhook_url: Option<String>,
    pub register_webhook_username: String,
    pub metrics: Metrics,
    pub tls: Tls,
    pub mail: Mail,

    /// Advertise a version that is not what we are _actually_ running
    /// Many clients compare their version with api.atuin.sh, and if they differ, notify the user
    /// that an update is available.
    /// Now that we take beta releases, we should be able to advertise a different version to avoid
    /// notifying users when the server runs something that is not a stable release.
    pub fake_version: Option<String>,

    #[serde(flatten)]
    pub db_settings: DbSettings,
}

impl<DbSettings: DeserializeOwned> Settings<DbSettings> {
    pub fn new() -> Result<Self> {
        debug!("Loading server settings");
        let mut config_file = if let Ok(p) = std::env::var("ATUIN_CONFIG_DIR") {
            debug!("Using ATUIN_CONFIG_DIR: {}", p);
            PathBuf::from(p)
        } else {
            let mut config_file = PathBuf::new();
            let config_dir = atuin_common::utils::config_dir();
            debug!("Using default config directory: {}", config_dir.display());
            config_file.push(config_dir);
            config_file
        };

        config_file.push("server.toml");
        debug!("Using config file path: {}", config_file.display());

        // create the config file if it does not exist
        debug!("Setting default configuration values");
        let mut config_builder = Config::builder()
            .set_default("host", "127.0.0.1")?
            .set_default("port", 8888)?
            .set_default("open_registration", false)?
            .set_default("max_history_length", 8192)?
            .set_default("max_record_size", 1024 * 1024 * 1024)? // pretty chonky
            .set_default("path", "")?
            .set_default("register_webhook_username", "")?
            .set_default("page_size", 1100)?
            .set_default("metrics.enable", false)?
            .set_default("metrics.host", "127.0.0.1")?
            .set_default("metrics.port", 9001)?
            .set_default("mail.enable", false)?
            .set_default("tls.enable", false)?
            .set_default("tls.cert_path", "")?
            .set_default("tls.pkey_path", "")?;

        debug!("Adding environment variables as configuration source (prefix 'atuin')");
        config_builder = config_builder.add_source(
            Environment::with_prefix("atuin")
                .prefix_separator("_")
                .separator("__"),
        );
        debug!("Environment variables added as source");

        config_builder = if config_file.exists() {
            debug!("Loading configuration from file: {}", config_file.display());
            config_builder.add_source(ConfigFile::new(
                config_file.to_str().unwrap(),
                FileFormat::Toml,
            ))
        } else {
            debug!("Config file not found, creating default: {}", config_file.display());
            create_dir_all(config_file.parent().unwrap())?;
            let mut file = File::create(config_file)?;
            file.write_all(EXAMPLE_CONFIG.as_bytes())?;
            debug!("Default config file created");
            config_builder
        };

        debug!("Building final configuration");
        let config = config_builder.build()?;
        debug!("Configuration built successfully");

        debug!("Deserializing configuration into Settings struct");
        let settings = config
            .try_deserialize()
            .map_err(|e| eyre!("failed to deserialize: {}", e))?;
        debug!("Settings loaded successfully");
        Ok(settings)
    }
}

pub fn example_config() -> &'static str {
    EXAMPLE_CONFIG
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Tls {
    #[serde(alias = "enabled")]
    pub enable: bool,

    pub cert_path: PathBuf,
    pub pkey_path: PathBuf,
}
