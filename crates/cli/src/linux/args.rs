//! Command line of `netorch` on Linux.
use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::ffi::OsString;
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
    /// Named proxy exits: run one command through a chosen path of a tunnel
    Proxy(ProxyArgs),

    /// Show which connections are running
    Status { target: Option<String> },
    /// Stream connection snapshots as state changes
    Watch { target: Option<String> },
    /// Inspect connection and daemon readiness without changing state
    Diagnose { target: Option<String> },
    /// Report recovery state, or explicitly clean up all current-user connections
    Recover {
        /// Disconnect ALL current user's daemon and local sessions, restore the proxy, and pause always-on
        #[arg(long)]
        cleanup: bool,
    },
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
    /// Shared unprivileged runtime (normally started on demand)
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Serve,
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
    /// Stay in this terminal and disconnect on Ctrl+C
    #[arg(long, short = 'f')]
    pub foreground: bool,
    /// Read OpenVPN username and password (two lines) from stdin
    #[arg(long)]
    pub auth_stdin: bool,
    /// Read the OpenVPN private key passphrase (one line) from stdin
    #[arg(long)]
    pub passphrase_stdin: bool,
}

/// `netorch proxy`: named per-command exits of a connected Xray TUN profile.
/// With `--profile` (before the exit name) a name that exists on several
/// profiles is picked without asking.
#[derive(Args, Debug)]
pub struct ProxyArgs {
    /// Profile of the exit, when its name is not unique across profiles
    #[arg(long, value_name = "PROFILE")]
    pub profile: Option<String>,
    #[command(subcommand)]
    pub command: ProxyCommand,
}

#[derive(Subcommand)]
pub enum ProxyCommand {
    /// List the named exits of the saved profiles (offline)
    List {
        /// Show only this profile
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// Create or replace a named exit; the command runs only at launch
    #[command(group(
        clap::ArgGroup::new("target")
            .args(["rules", "via", "pool", "direct"])
            .required(true)
    ))]
    Set {
        /// Exit name: 1-32 of a-z 0-9 - _, starting with a letter or digit
        name: String,
        /// Saved Xray profile the exit belongs to
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
        /// The profile's own routing rules decide, like the main connection
        #[arg(long)]
        rules: bool,
        /// Always exit through one server: number, name part or 16-hex key
        #[arg(long, value_name = "NODE")]
        via: Option<String>,
        /// Exit through these servers in order, moving on when one fails
        #[arg(long, value_name = "NODE", num_args = 1..)]
        pool: Option<Vec<String>>,
        /// Bypass the tunnel entirely: the command connects directly
        #[arg(long)]
        direct: bool,
        /// Hosts, domains, IPs or CIDRs (comma-separated) that skip the exit
        #[arg(long, value_name = "ITEM,...", value_delimiter = ',')]
        no_proxy: Vec<String>,
    },
    /// Delete a named exit
    Remove {
        name: String,
        /// Saved profile the exit belongs to
        #[arg(long, value_name = "PROFILE")]
        profile: Option<String>,
    },
    /// `netorch proxy [--profile PROFILE] NAME -- COMMAND [ARGS...]`
    #[command(external_subcommand)]
    Run(Vec<OsString>),
}

impl std::fmt::Debug for ProxyCommand {
    /// The arguments of `proxy NAME -- COMMAND` may carry secrets; only the
    /// variant is shown, the captured argv never.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            ProxyCommand::List { .. } => "List",
            ProxyCommand::Set { .. } => "Set",
            ProxyCommand::Remove { .. } => "Remove",
            ProxyCommand::Run(_) => "Run",
        };
        write!(f, "ProxyCommand::{variant}(<redacted>)")
    }
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

    fn proxy_run(argv: &[&str]) -> Vec<OsString> {
        match Cli::try_parse_from(argv).map(|cli| cli.command) {
            Ok(Command::Proxy(args)) => match args.command {
                ProxyCommand::Run(args) => args,
                _ => panic!("expected the external run variant"),
            },
            Err(error) => panic!("{argv:?} did not parse: {error}"),
            _ => panic!("expected the proxy command"),
        }
    }

    #[test]
    fn proxy_run_captures_the_separator_and_argv_verbatim() {
        // The external capture keeps the literal `--` and every argument of
        // the command, options included; the exit name comes first.
        assert_eq!(
            proxy_run(&[
                "netorch",
                "proxy",
                "nl",
                "--",
                "curl",
                "-sS",
                "example.test"
            ]),
            ["nl", "--", "curl", "-sS", "example.test"]
        );
        assert_eq!(
            proxy_run(&["netorch", "proxy", "direct", "--", "prog", "--flag", "--"]),
            ["direct", "--", "prog", "--flag", "--"]
        );
    }

    #[test]
    fn proxy_run_takes_profile_before_the_name() {
        let cli =
            Cli::try_parse_from(["netorch", "proxy", "--profile", "work", "nl", "--", "curl"])
                .unwrap();
        match cli.command {
            Command::Proxy(args) => {
                assert_eq!(args.profile.as_deref(), Some("work"));
                match args.command {
                    ProxyCommand::Run(args) => assert_eq!(args, ["nl", "--", "curl"]),
                    _ => panic!("expected the run variant"),
                }
            }
            _ => panic!("expected the proxy command"),
        }
        // `--profile` after the name belongs to the command, not netorch.
        assert_eq!(
            proxy_run(&["netorch", "proxy", "nl", "--profile", "x", "--", "curl"]),
            ["nl", "--profile", "x", "--", "curl"]
        );
        // An unknown option before `--` is captured verbatim too: nothing
        // netorch does not know may change the launched command.
        assert_eq!(
            proxy_run(&["netorch", "proxy", "nl", "-x", "--", "curl"]),
            ["nl", "-x", "--", "curl"]
        );
    }

    #[test]
    fn proxy_run_requires_a_command_after_the_separator() {
        // `proxy nl` alone parses but is refused at launch; `proxy` alone is
        // rejected by clap because a subcommand is required.
        assert_eq!(proxy_run(&["netorch", "proxy", "nl"]), ["nl"]);
        assert!(Cli::try_parse_from(["netorch", "proxy"]).is_err());
    }

    #[test]
    fn proxy_set_accepts_profile_after_the_name() {
        let cli = Cli::try_parse_from([
            "netorch",
            "proxy",
            "set",
            "nl",
            "--profile",
            "work",
            "--pool",
            "a",
            "b",
            "--no-proxy",
            "x.test,10.0.0.0/8",
        ])
        .unwrap();
        match cli.command {
            Command::Proxy(args) => match args.command {
                ProxyCommand::Set {
                    name,
                    profile,
                    pool,
                    no_proxy,
                    ..
                } => {
                    assert_eq!(name, "nl");
                    assert_eq!(profile.as_deref(), Some("work"));
                    assert_eq!(pool.unwrap(), ["a", "b"]);
                    assert_eq!(no_proxy, ["x.test", "10.0.0.0/8"]);
                }
                _ => panic!("expected the set variant"),
            },
            _ => panic!("expected the proxy command"),
        }
    }

    #[test]
    fn proxy_set_requires_exactly_one_target() {
        assert!(Cli::try_parse_from(["netorch", "proxy", "set", "n", "--profile", "p"]).is_err());
        assert!(Cli::try_parse_from([
            "netorch",
            "proxy",
            "set",
            "n",
            "--profile",
            "p",
            "--rules",
            "--direct"
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "netorch",
            "proxy",
            "set",
            "n",
            "--profile",
            "p",
            "--via",
            "node"
        ])
        .is_ok());
    }
}
