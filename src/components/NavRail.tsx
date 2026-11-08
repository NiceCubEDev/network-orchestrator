import { ActivityIcon, ConditionsIcon, ProfileIcon, NetworkIcon, RouteIcon, LogsIcon, SettingsIcon } from "../icons";
import { TranslationKey, useT } from "../i18n";

export type Tab = "profiles" | "monitor" | "routes" | "conditions" | "network" | "logs" | "settings";

interface NavItem {
  id: Tab;
  labelKey: TranslationKey;
  icon: React.ReactElement;
}

const PRIMARY: NavItem[] = [
  { id: "profiles", labelKey: "nav.profiles", icon: <ProfileIcon size={20} /> },
  { id: "monitor", labelKey: "nav.monitor", icon: <ActivityIcon size={20} /> },
  { id: "routes", labelKey: "nav.routes", icon: <RouteIcon size={20} /> },
];

const ADVANCED: NavItem[] = [
  { id: "conditions", labelKey: "nav.conditions", icon: <ConditionsIcon size={20} /> },
  { id: "network", labelKey: "nav.network", icon: <NetworkIcon size={20} /> },
  { id: "logs", labelKey: "nav.logs", icon: <LogsIcon size={20} /> },
];

interface NavRailProps {
  tab: Tab;
  setTab: (tab: Tab) => void;
  activeCount: number;
}

function RailButton({
  item,
  active,
  onClick,
  badge,
}: {
  item: NavItem;
  active: boolean;
  onClick: () => void;
  badge?: number;
}) {
  const t = useT();
  const label = t(item.labelKey);
  return (
    <button
      type="button"
      className={`rail-item ${active ? "active" : ""}`}
      onClick={onClick}
      title={label}
    >
      {item.icon}
      {badge !== undefined && badge > 0 && (
        <span className="rail-badge">{badge > 9 ? "9+" : badge}</span>
      )}
      <span className="rail-tooltip">{label}</span>
    </button>
  );
}

export default function NavRail({ tab, setTab, activeCount }: NavRailProps) {
  const t = useT();
  return (
    <nav className="rail">
      <div className="rail-brand" title={t("app.name")}>
        <NetworkIcon size={20} />
      </div>
      <div className="rail-group">
        {PRIMARY.map((item) => (
          <RailButton
            key={item.id}
            item={item}
            active={tab === item.id}
            onClick={() => setTab(item.id)}
            badge={item.id === "profiles" ? activeCount : undefined}
          />
        ))}
      </div>
      <div className="rail-divider" />
      <div className="rail-group rail-group-muted">
        {ADVANCED.map((item) => (
          <RailButton
            key={item.id}
            item={item}
            active={tab === item.id}
            onClick={() => setTab(item.id)}
          />
        ))}
      </div>
      <div className="rail-spacer" />
      <div className="rail-group">
        <RailButton
          item={{ id: "settings", labelKey: "nav.settings", icon: <SettingsIcon size={20} /> }}
          active={tab === "settings"}
          onClick={() => setTab("settings")}
        />
      </div>
    </nav>
  );
}
