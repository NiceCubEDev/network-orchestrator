import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { OpenVpnCredentials, Profile, TunnelStatus } from "../types";
import { useT } from "../i18n";
import Modal from "./Modal";

interface OpenVpnCredentialsModalProps {
  /** The profile to connect; the modal is closed while this is null. */
  profile: Profile | null;
  onClose: () => void;
  /** Called after `connect_openvpn_with_credentials` succeeded. */
  onConnected: (profile: Profile, status: TunnelStatus) => void;
  /** Collect without connecting when a shared set must preflight all credentials first. */
  onSubmitCredentials?: (profile: Profile, credentials: OpenVpnCredentials, remember: boolean) => Promise<void>;
}

/** Prompts for OpenVPN credentials and connects with them. */
export default function OpenVpnCredentialsModal({
  profile,
  onClose,
  onConnected,
  onSubmitCredentials,
}: OpenVpnCredentialsModalProps) {
  const t = useT();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reset = () => {
    setUsername("");
    setPassword("");
    setKeyPassphrase("");
    setRemember(false);
    setError(null);
  };

  // A fresh profile always starts from an empty form.
  useEffect(() => {
    reset();
  }, [profile?.id]);

  const close = () => {
    if (busy) return;
    reset();
    onClose();
  };

  const submit = async () => {
    if (!profile) return;
    if (password && !username) {
      setError(t("ovpn.errUserPass"));
      return;
    }
    if (!username && !keyPassphrase) {
      setError(t("ovpn.errCreds"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const credentials: OpenVpnCredentials = {
        ...(username ? { authUserPass: { username, password } } : {}),
        ...(keyPassphrase ? { privateKeyPassphrase: keyPassphrase } : {}),
      };
      if (onSubmitCredentials) {
        await onSubmitCredentials(profile, credentials, remember);
        reset();
        return;
      }
      const status = await invoke<TunnelStatus>(
        "connect_openvpn_with_credentials",
        {
          id: profile.id,
          credentials,
          remember,
        },
      );
      reset();
      onConnected(profile, status);
    } catch (err) {
      setError(t("ovpn.errFailed", { err: String(err) }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={profile !== null}
      title={profile ? `${t("ovpn.title")} — ${profile.name}` : t("ovpn.title")}
      onClose={close}
      maxWidth="420px"
      footer={
        <>
          <button type="button" onClick={close} disabled={busy}>
            {t("common.cancel")}
          </button>
          <button
            type="button"
            className="btn-primary"
            onClick={() => void submit()}
            disabled={busy}
          >
            {onSubmitCredentials ? t("native.diag.ok") : busy ? t("common.connecting") : t("common.connect")}
          </button>
        </>
      }
    >
      <form
        className="profile-form"
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <label>
          {t("ovpn.username")}
          <input type="text" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} />
        </label>
        <label>
          {t("ovpn.password")}
          <input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
        </label>
        <label>
          {t("ovpn.keyPass")}
          <input type="password" autoComplete="off" value={keyPassphrase} onChange={(event) => setKeyPassphrase(event.target.value)} />
        </label>
        <label className="profile-proxy-toggle">
          <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
          {t("ovpn.remember")}
        </label>
        <span className="profile-help">{t("ovpn.keyringHelp")}</span>
        {error && <p className="error" role="alert">{error}</p>}
      </form>
    </Modal>
  );
}
