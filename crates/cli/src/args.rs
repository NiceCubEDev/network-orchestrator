//! macOS business command line (also selected by the portable `macos-cli` feature).
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name="netorch", version=env!("NETORCH_VERSION"), about="Profiles, tunnels and routing shared with Network Orchestrator")]
pub struct Cli {
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(
        long,
        global = true,
        env = "NETORCH_MACOS_DATA_DIR",
        value_name = "DIR"
    )]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand, Debug)]
pub enum Command {
    Ls,
    Status {
        target: Option<String>,
    },
    Add(AddArgs),
    /// Import an explicit backend config, including native Xray JSON.
    Import {
        file: PathBuf,
        #[arg(value_enum)]
        backend: Backend,
        #[arg(long)]
        name: Option<String>,
    },
    Rm {
        target: String,
    },
    Rename {
        target: String,
        name: String,
    },
    /// Edit persisted profile settings; unspecified fields are preserved.
    Edit(EditArgs),
    /// Create a static-route profile from a typed JSON document.
    Static {
        file: PathBuf,
    },
    /// Replace the complete ordering of one backend group.
    Reorder {
        #[arg(value_enum)]
        backend: Backend,
        profiles: Vec<String>,
    },
    Up(UpArgs),
    Down {
        target: Option<String>,
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    Logs {
        target: String,
    },
    Test(TestArgs),
    Inspect {
        target: String,
    },
    Diagnose {
        target: String,
    },
    #[command(subcommand)]
    Subscription(SubscriptionCommand),
    #[command(subcommand)]
    Route(RouteCommand),
    #[command(subcommand)]
    Sets(SetCommand),
    #[command(subcommand)]
    Mode(AppModeCommand),
    /// Execute saved auto-connect policy, continuing individual failures.
    AutoConnect {
        #[arg(long)]
        credentials_file: Option<PathBuf>,
    },
    #[command(subcommand)]
    Credentials(CredentialCommand),
    #[command(subcommand)]
    Network(NetworkCommand),
    #[command(subcommand)]
    Netbird(NetbirdCommand),
    #[command(subcommand)]
    Tailscale(TailscaleCommand),
    #[command(subcommand)]
    Vpn(VpnCommand),
    #[command(subcommand)]
    Intents(IntentCommand),
    #[command(subcommand)]
    Conditions(ConditionCommand),
    #[command(subcommand)]
    Recovery(RecoveryCommand),
    #[command(subcommand)]
    Proxy(ProxyCommand),
    Capabilities,
    Snapshot,
    Doctor,
    #[command(subcommand)]
    Backend(BackendCommand),
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Run the shared unprivileged runtime owner (normally started on demand).
    Serve,
    Completions {
        shell: Shell,
    },
}
#[derive(Args, Debug)]
pub struct AddArgs {
    pub input: String,
    #[arg(long)]
    pub name: Option<String>,
    /// Subscription device identifier; omit to generate, use empty value to disable.
    #[arg(long)]
    pub hwid: Option<String>,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Socks,
    Tun,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    Primary,
    Secondary,
}
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Backend {
    Xray,
    Wireguard,
    Openvpn,
    Static,
}
#[derive(Args, Debug)]
pub struct EditArgs {
    pub target: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    #[arg(long, value_enum)]
    pub role: Option<Role>,
    #[arg(long)]
    pub networks: Option<String>,
    #[arg(long)]
    pub dns_domains: Option<String>,
    #[arg(long)]
    pub auto_connect: Option<bool>,
    #[arg(long)]
    pub wait_for_interface: Option<bool>,
    /// Minutes; 0 disables automatic subscription refresh.
    #[arg(long)]
    pub refresh_interval: Option<u32>,
}
#[derive(Args, Debug, Default)]
pub struct CredentialArgs {
    #[arg(long, conflicts_with = "credentials_file")]
    pub auth_stdin: bool,
    #[arg(long, conflicts_with = "credentials_file")]
    pub passphrase_stdin: bool,
    /// Private JSON file containing authUserPass/privateKeyPassphrase; '-' reads stdin.
    #[arg(long, value_name = "FILE")]
    pub credentials_file: Option<PathBuf>,
    /// Save only after a confirmed successful connection, in the login Keychain.
    #[arg(long)]
    pub remember: bool,
}
#[derive(Args, Debug)]
pub struct UpArgs {
    pub target: String,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    #[arg(long, value_enum)]
    pub role: Option<Role>,
    #[arg(long)]
    pub networks: Option<String>,
    #[arg(long)]
    pub dns_domains: Option<String>,
    #[arg(long)]
    pub system_proxy: bool,
    /// Hold a generation lease; Ctrl+C/client death disconnects only this activation.
    #[arg(short = 'f', long)]
    pub foreground: bool,
    #[command(flatten)]
    pub credentials: CredentialArgs,
}
#[derive(Args, Debug)]
pub struct TestArgs {
    pub target: Option<String>,
    #[arg(long)]
    pub ip: bool,
    #[arg(long, conflicts_with = "ip")]
    pub index: Option<usize>,
}
#[derive(Subcommand, Debug)]
pub enum SubscriptionCommand {
    Endpoints {
        target: String,
    },
    Switch {
        target: String,
        index: usize,
    },
    Refresh {
        target: String,
    },
    /// Refresh all subscriptions, or only stopped subscriptions whose refresh is due.
    RefreshAll {
        #[arg(long)]
        due: bool,
    },
    ImportLog,
    Hwid,
}
#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    Lookup {
        address: String,
    },
    Check {
        target: String,
        #[arg(long)]
        profile: String,
    },
    Show {
        profile: String,
    },
    Set {
        profile: String,
        #[arg(long)]
        block: Vec<String>,
        #[arg(long)]
        proxy: Vec<String>,
        #[arg(long)]
        direct: Vec<String>,
        #[arg(long)]
        lan_direct: bool,
        /// Typed AdvancedRouting JSON (strategy, matcher, DNS); omitted preserves existing settings.
        #[arg(long)]
        advanced: Option<PathBuf>,
        /// Typed GeoUrls JSON; null fields clear custom URLs.
        #[arg(long)]
        geo: Option<PathBuf>,
    },
    /// Merge Happ/Incy routing import, preserving omitted fields.
    Import {
        profile: String,
        file: PathBuf,
    },
}
#[derive(Subcommand, Debug)]
pub enum SetCommand {
    List,
    Capture {
        id: String,
        #[arg(long)]
        name: Option<String>,
    },
    Put {
        id: String,
        #[arg(long)]
        name: String,
        profiles: Vec<String>,
    },
    Import {
        file: PathBuf,
    },
    Apply {
        id: String,
        #[arg(long)]
        credentials_file: Option<PathBuf>,
    },
    Down {
        id: String,
    },
    Delete {
        id: String,
    },
}
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AppMode {
    Combined,
    Orchestrator,
    Manager,
}
#[derive(Subcommand, Debug)]
pub enum AppModeCommand {
    Show,
    Set {
        #[arg(value_enum)]
        mode: AppMode,
    },
    Eligibility {
        target: String,
    },
}
#[derive(Subcommand, Debug)]
pub enum CredentialCommand {
    Requirements { target: String },
    Forget { target: String },
}
#[derive(Subcommand, Debug)]
pub enum NetworkCommand {
    Settings,
    Interfaces,
    Routes,
    Lookup {
        address: std::net::IpAddr,
    },
    Dns,
    DnsProbe {
        hostname: String,
        #[arg(long)]
        server: Option<std::net::IpAddr>,
        #[arg(long)]
        ipv6: bool,
    },
    ProxyEffect,
    Interface {
        name: String,
        #[arg(value_enum)]
        state: Switch,
    },
}
#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Switch {
    Up,
    Down,
}
#[derive(Subcommand, Debug)]
pub enum NetbirdCommand {
    Status,
    Down,
    Log,
    Up {
        #[arg(long)]
        management_url: Option<String>,
        #[arg(long, conflicts_with = "setup_key_file")]
        setup_key_stdin: bool,
        #[arg(long)]
        setup_key_file: Option<PathBuf>,
    },
}
#[derive(Subcommand, Debug)]
pub enum TailscaleCommand {
    Status,
    Up,
    Down,
    Sync,
}
#[derive(Subcommand, Debug)]
pub enum VpnCommand {
    List,
    Set {
        id: String,
        #[arg(value_enum)]
        state: Switch,
    },
}
#[derive(Subcommand, Debug)]
pub enum IntentCommand {
    List,
    Put {
        file: PathBuf,
    },
    Delete {
        id: String,
    },
    Doctor,
    /// Apply typed IntentFix[] in order, stopping at the first failure.
    Apply {
        file: PathBuf,
    },
}
#[derive(Subcommand, Debug)]
pub enum ConditionCommand {
    List,
    Put { file: PathBuf },
    Delete { id: String },
}
#[derive(Subcommand, Debug)]
pub enum RecoveryCommand {
    Report,
    Cleanup,
}
#[derive(Subcommand, Debug)]
pub enum ProxyCommand {
    Set {
        target: String,
        #[arg(value_enum)]
        state: Switch,
    },
    Env {
        target: String,
    },
    Browser {
        target: String,
    },
}
#[derive(Subcommand, Debug)]
pub enum BackendCommand {
    Install {
        #[arg(long)]
        archive: Option<PathBuf>,
    },
}
#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    Status,
    Install,
    Remove,
    Log,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_lease_is_explicit() {
        let Command::Up(args) =
            Cli::try_parse_from(["netorch", "up", "saved", "-f", "--auth-stdin"])
                .unwrap()
                .command
        else {
            panic!()
        };
        assert!(args.foreground);
        assert!(args.credentials.auth_stdin);
        let Command::Up(args) = Cli::try_parse_from(["netorch", "up", "saved"])
            .unwrap()
            .command
        else {
            panic!()
        };
        assert!(!args.foreground);
    }
    #[test]
    fn secrets_have_no_value_arguments() {
        for flag in ["--password", "--passphrase", "--setup-key"] {
            assert!(Cli::try_parse_from(["netorch", "up", "saved", flag, "secret"]).is_err());
        }
    }
    #[test]
    fn down_all_and_target_exclude_each_other() {
        assert!(Cli::try_parse_from(["netorch", "down", "--all", "x"]).is_err());
    }
}
