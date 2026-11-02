//! Command line of `netorch` on Linux.
use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "netorch",
    version = env!("NETORCH_VERSION"),
    about = "One command for VPN profiles and tunnels",
    long_about = "Connect the profiles saved in the Network Orchestrator app through its \
                  network daemon.\nProfiles are shared with the app."
)]
pub struct Cli {
    /// Print machine-readable JSON instead of text
    #[arg(long, global = true)]
    pub json: bool,
    /// App data directory (default: ~/.local/share/com.netmanager.app)
    #[arg(long, global = true, env = "NETORCH_DATA_DIR", value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List saved profiles
    Ls,
    /// Routing rules of Xray profiles: what goes direct, through the tunnel or nowhere
    #[command(subcommand)]
    Route(RouteCommand),
    /// Ordered backup servers and auto-return of a subscription (failover)
    #[command(subcommand)]
    Backup(BackupCommand),
    /// Adopt the routing policy of a standalone Xray config (rules → this
    /// app's direct/proxy/blocked lists and node pins)
    #[command(subcommand)]
    Migrate(MigrateCommand),
    /// User-configured HTTPS checks through explicitly pinned endpoints
    #[command(subcommand)]
    Checks(ChecksCommand),

    /// Show which connections are running
    Status { target: Option<String> },
    /// Save a profile from a share link, subscription URL or config file
    Add(AddArgs),
    /// Delete a saved profile
    Rm { target: String },
    /// Rename a saved profile
    Rename { target: String, name: String },
    /// List the servers of a subscription
    Endpoints { target: String },
    /// Choose a subscription's server (asks on a terminal when none is given)
    Use {
        target: String,
        /// Server number or part of its name
        server: Option<String>,
    },
    /// Change a subscription's server, reconnecting if it is connected
    Switch {
        target: String,
        /// Server number or part of its name
        server: Option<String>,
    },
    /// Fetch the subscription again for its current list of servers
    Refresh { target: String },
    /// Measure the delay of a subscription's servers, fastest first
    Test(TestArgs),
    /// Connect a saved profile (importing first when given a link, URL or file)
    Up(UpArgs),
    /// Disconnect
    Down {
        target: Option<String>,
        /// Disconnect every running connection
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Show the netorch and daemon versions and whether they work together
    Version,
    /// Print shell completions
    Completions { shell: Shell },
    /// Background process that keeps a connection up (started by `up`)
    #[command(hide = true)]
    Hold { target: String },
}

#[derive(Subcommand)]
pub enum ChecksCommand {
    /// List saved checks without contacting their destinations
    List { profile: String },

    /// Save a check; this does not contact its destination
    Add {
        profile: String,

        /// Explicitly pinned endpoint: number, name, unique fragment, or key
        #[arg(long, value_name = "NODE")]
        via: String,

        /// Display label, not a URL
        #[arg(long)]
        name: String,

        /// HTTPS destination; do not supply credentials, tokens, or webhooks
        #[arg(long, value_name = "HTTPS_URL")]
        url: String,

        /// Opt in to periodic background diagnostics
        #[arg(long)]
        background: bool,
    },

    /// Remove a saved check and stop its background diagnostic
    Remove { profile: String, id: String },

    /// Enable or disable a saved check's background diagnostic
    Background {
        profile: String,
        id: String,
        #[arg(value_parser = clap::value_parser!(BoolOnOff))]
        enabled: BoolOnOff,
    },

    /// Run saved checks now; omit --id to run all
    Run {
        profile: String,
        #[arg(long = "id", value_name = "ID")]
        ids: Vec<String>,
    },
}

impl std::fmt::Debug for ChecksCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChecksCommand(<redacted>)")
    }
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    /// Show the rules of a profile (every Xray profile when none is given)
    Show { profile: Option<String> },
    /// Replace all of a profile's rules
    Set {
        profile: String,
        #[command(flatten)]
        rules: RuleArgs,
        /// Send private LAN ranges direct
        #[arg(long)]
        lan_direct: bool,
    },
    /// Add selectors to a profile's rules, keeping the others
    Add {
        profile: String,
        #[command(flatten)]
        rules: RuleArgs,
    },
    /// Remove selectors from a profile's rules
    Rm {
        profile: String,
        #[command(flatten)]
        rules: RuleArgs,
    },
    /// Which rule of a profile decides a host or address
    Check {
        target: String,
        /// Profile whose rules are replayed
        #[arg(long)]
        profile: String,
    },
    /// Send domains through one named server, nowhere else (fail-closed)
    Pin {
        profile: String,
        /// Server number, part of its name, or a raw 16-hex key
        #[arg(long, value_name = "SERVER")]
        via: String,
        /// Selector to pin (repeat for several); same syntax as --proxy
        #[arg(long, required = true, value_name = "SELECTOR")]
        selector: Vec<String>,
    },
    /// Unpin selectors — or every selector of one server
    Unpin {
        profile: String,
        /// Server number, part of its name, or a raw 16-hex key
        #[arg(long, value_name = "SERVER")]
        via: String,
        /// Selector to unpin; without it the whole pinned route is removed
        #[arg(long, value_name = "SELECTOR")]
        selector: Vec<String>,
    },
    /// Whether the kernel rejects QUIC (UDP/443) on the tunnel interface —
    /// `on` returns an immediate rejection; `off` removes this owned reject rule
    Quic {
        profile: String,
        /// `on` or `off`; omitted shows the current setting
        #[arg(value_parser = clap::value_parser!(BoolOnOff))]
        enabled: Option<BoolOnOff>,
    },
}

/// The failover plan: which servers run after the primary fails its probes,
/// and whether the tunnel returns to the primary when it answers again.
#[derive(Subcommand, Debug)]
pub enum BackupCommand {
    /// Show the primary, the ordered backups and the pinned rules
    Show { profile: String },
    /// Replace the backup chain (order matters, first is tried first)
    Set {
        profile: String,
        /// Server numbers, names or keys, tried in this order
        #[arg(required = true, value_name = "SERVER")]
        servers: Vec<String>,
    },
    /// Append a server to the backup chain
    Add {
        profile: String,
        /// Server number, part of its name, or a raw 16-hex key
        server: String,
    },
    /// Remove a server from the backup chain
    Rm {
        profile: String,
        /// Server number, part of its name, or a raw 16-hex key
        server: String,
    },
    /// Drop every backup
    Clear { profile: String },
    /// Whether the tunnel returns to the primary once it answers again
    Auto {
        profile: String,
        /// `on` (default) or `off`
        #[arg(value_parser = clap::value_parser!(BoolOnOff))]
        enabled: BoolOnOff,
    },
    /// Opt-in filtered pool: matching servers join the failover chain after
    /// the manual backups, verified by real exit country
    #[command(subcommand)]
    Pool(PoolCommand),
    /// Check which servers really answer and which country they exit in
    Verify { profile: String },
}

/// The opt-in pool: servers whose name matches a filter — and whose real
/// exit country the filter names — join the failover chain after the manual
/// backups, in subscription order.
#[derive(Subcommand, Debug)]
pub enum PoolCommand {
    /// Show the filters and the members the last check kept
    Show { profile: String },
    /// Set the filters; the pool is off without this
    Set {
        profile: String,
        /// Verified filter `CC:word|word` or `CC:` for any name in that country.
        /// Name-only filters require --no-verify. Verification contacts
        /// api.country.is and ipinfo.io through each candidate.
        #[arg(required = true, value_name = "FILTER")]
        filters: Vec<String>,
        /// Admit name matches without proving the exit country
        #[arg(long)]
        no_verify: bool,
    },
    /// Turn the pool off and forget its members
    Clear { profile: String },
    /// Re-check the subscription now: live matches replace the pool
    Rebuild { profile: String },
}

/// `on`/`off` as a typed flag for `backup auto`.
#[derive(Debug, Clone, Copy)]
pub enum BoolOnOff {
    On,
    Off,
}

impl std::str::FromStr for BoolOnOff {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "on" => Ok(BoolOnOff::On),
            "off" => Ok(BoolOnOff::Off),
            _ => Err("write `on` or `off`".into()),
        }
    }
}

/// Adopting the routing policy of a standalone Xray `config.json` (like the
/// one `~/vpn` carries) onto a saved Xray profile. `preview` changes
/// nothing; `apply` refuses while the source contains rules this app cannot
/// represent.
#[derive(Subcommand, Debug)]
pub enum MigrateCommand {
    /// Show what the file would change — and what it cannot carry over
    Preview {
        profile: String,
        /// Standalone Xray config.json to read
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
    },
    /// Apply the file's policy to the profile (dry-run safe: fails on
    /// non-equivalent rules instead of faking success)
    Apply {
        profile: String,
        /// Standalone Xray config.json to read
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
    },
}

/// Selectors are `domain:example.com`, `full:host.example.com`,
/// `geosite:category-ads`, `geoip:ru`, an address or a CIDR network.
#[derive(Args, Debug, Default)]
pub struct RuleArgs {
    /// Selector to drop (repeat the flag for several)
    #[arg(long, value_name = "SELECTOR")]
    pub block: Vec<String>,
    /// Selector to send through the tunnel
    #[arg(long, value_name = "SELECTOR")]
    pub proxy: Vec<String>,
    /// Selector to send around the tunnel, directly
    #[arg(long, value_name = "SELECTOR")]
    pub direct: Vec<String>,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// vless:// / hysteria2:// link, https:// subscription URL, or .conf/.ovpn file
    pub input: String,
    /// Display name (default: taken from the link or file name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Subscription profile
    pub target: String,
    /// Measure only the servers whose name contains this text
    pub server: Option<String>,
    /// Show every server, not just the fastest
    #[arg(long)]
    pub all: bool,
    /// How many of the fastest servers to show
    #[arg(long, default_value_t = super::endpoints::DEFAULT_TOP, value_name = "N")]
    pub top: usize,
}

#[derive(Args, Debug)]
pub struct UpArgs {
    /// Saved profile (id or name), or a link / URL / file to import first
    pub target: String,
    /// Name for a profile imported by this command
    #[arg(long)]
    pub name: Option<String>,
    /// Subscription server to use: its number or part of its name
    #[arg(long, value_name = "SERVER")]
    pub endpoint: Option<String>,
    /// Stay in this terminal and disconnect on Ctrl+C, instead of leaving a
    /// background process that keeps the connection up
    #[arg(long, short = 'f')]
    pub foreground: bool,
    /// Read OpenVPN username and password (two lines) from stdin
    #[arg(long)]
    pub auth_stdin: bool,
    /// Read the OpenVPN private key passphrase (one line) from stdin
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn down_all_and_a_target_exclude_each_other() {
        assert!(Cli::try_parse_from(["netorch", "down", "--all", "x"]).is_err());
        assert!(Cli::try_parse_from(["netorch", "down", "--all"]).is_ok());
    }
}
