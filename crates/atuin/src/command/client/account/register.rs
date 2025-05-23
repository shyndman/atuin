use clap::Parser;
use eyre::{Result, bail};
use tokio::{fs::File, io::AsyncWriteExt};
use tracing::debug;

use atuin_client::{api_client, settings::Settings};

#[derive(Parser, Debug)]
pub struct Cmd {
    #[clap(long, short)]
    pub username: Option<String>,

    #[clap(long, short)]
    pub password: Option<String>,

    #[clap(long, short)]
    pub email: Option<String>,
}

impl Cmd {
    pub async fn run(self, settings: &Settings) -> Result<()> {
        run(settings, self.username, self.email, self.password).await
    }
}

pub async fn run(
    settings: &Settings,
    username: Option<String>,
    email: Option<String>,
    password: Option<String>,
) -> Result<()> {
    debug!("Starting registration process");
    use super::login::or_user_input;
    println!("Registering for an Atuin Sync account");

    let username = or_user_input(username, "username");
    debug!("Username: {}", username);
    let email = or_user_input(email, "email");
    debug!("Email: {}", email);

    let password = password
        .clone()
        .unwrap_or_else(super::login::read_user_password);

    if password.is_empty() {
        bail!("please provide a password");
    }

    debug!("Calling api_client::register");
    let session =
        api_client::register(settings.sync_address.as_str(), &username, &email, &password).await?;
    debug!("Registration successful");

    let path = settings.session_path.as_str();
    debug!("Saving session to {}", path);
    let mut file = File::create(path).await?;
    file.write_all(session.session.as_bytes()).await?;

    debug!("Loading encryption key");
    let _key = atuin_client::encryption::load_key(settings)?;
    debug!("Encryption key loaded");

    println!(
        "Registration successful! Please make a note of your key (run 'atuin key') and keep it safe."
    );
    println!(
        "You will need it to log in on other devices, and we cannot help recover it if you lose it."
    );

    debug!("Registration process completed successfully");
    Ok(())
}
