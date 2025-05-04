use eyre::Result;
use semver::{Version, VersionReq};
use tracing::debug;

pub fn client_version_min(user_agent: &str, req: &str) -> Result<bool> {
    debug!("Checking client version minimum: user_agent={}, req={}", user_agent, req);
    if user_agent.is_empty() {
        debug!("User agent is empty, returning false");
        return Ok(false);
    }

    let version = user_agent.replace("atuin/", "");
    debug!("Extracted version from user agent: {}", version);

    let req = VersionReq::parse(req)?;
    debug!("Parsed version requirement: {}", req);
    let version = Version::parse(version.as_str())?;
    debug!("Parsed client version: {}", version);

    let matches = req.matches(&version);
    debug!("Client version matches requirement: {}", matches);
    Ok(matches)
}
