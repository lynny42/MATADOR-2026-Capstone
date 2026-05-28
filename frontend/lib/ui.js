import { cn } from "./cn";

export const ui = {
  shell: "mx-auto min-h-screen w-full max-w-[1440px] px-6 py-5",
  topbar: "mb-3 flex min-w-0 items-center justify-between gap-4",
  eyebrow: "m-0 text-xs uppercase tracking-[0.16em] text-[var(--accent)]",
  heading: "mt-1 mb-0",
  panel:
    "w-full rounded-[18px] border border-[var(--line)] bg-[var(--panel-bg)] p-3.5 shadow-none",
  panelHeading: "flex min-w-0 items-center justify-between gap-4",
  dashboardGrid: "grid w-full grid-cols-1 gap-5",
  btnPill:
    "cursor-pointer rounded-full border border-[var(--button-border)] bg-[var(--button-bg)] px-4 py-2.5 text-[var(--accent)] ",
  btnRow: "flex flex-wrap gap-2",
  errorBanner:
    "mb-4 rounded-2xl border border-red-400/40 bg-red-500/10 p-3.5",
  successBanner:
    "mb-4 rounded-2xl border border-emerald-400/40 bg-emerald-500/10 p-3.5 text-[var(--text)]",
  infoBanner:
    "mb-4 rounded-2xl border border-cyan-400/30 bg-cyan-400/10 p-3.5 text-[var(--text)]",
  loadingCard:
    "mb-4 rounded-2xl border border-red-400/40 bg-red-500/10 p-3.5",
  replaySpinner:
    "inline-block h-4 w-4 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent align-[-2px]",
  muted: "text-[var(--muted)]",
  selectorRow: "flex flex-wrap items-stretch gap-4",
  searchBox:
    "flex min-w-[240px] flex-1 items-center gap-2.5 rounded-full border border-[var(--line)] bg-[var(--panel-strong)] px-3.5 py-2.5",
  searchSelect: "w-full border-0 bg-transparent text-[var(--text)] outline-none",
  detailCard:
    "mt-5 rounded-[14px] border border-[var(--line)] bg-[var(--soft-card-bg)] p-3.5",
  detailHeading: "flex items-center justify-between gap-4",
  detailAccent: "text-[28px] text-[var(--accent)]",
  filterGrid: "my-4 grid grid-cols-2 gap-2.5 md:grid-cols-4",
  filterCell: "rounded-xl bg-[var(--soft-card-bg)] p-2.5",
  codeList: "mt-4 grid gap-2.5",
  codeButton:
    "grid w-full gap-1 rounded-[14px] border border-[var(--line)] bg-[var(--soft-card-bg)] p-3.5 text-left break-words text-inherit",
  satelliteMap:
    "mt-3.5 grid w-full grid-cols-1 gap-2.5 sm:grid-cols-3 lg:grid-cols-4 lg:[grid-template-areas:'obc_obc_adcs_com'_'eps_tcs_adcs_com']",
  subsystemCard:
    "relative min-h-32 rounded-[14px] border border-[var(--line)] bg-[var(--panel-strong)] p-2.5 transition hover:-translate-y-0.5",
  subsystemTitle: "flex items-center justify-between gap-4",
  codeStack: "mt-3.5 flex flex-col gap-2",
  codeChip:
    "grid min-w-0 gap-1 overflow-wrap-anywhere rounded-[14px] border border-[var(--line)] bg-[var(--soft-card-bg)] p-2.5 text-left",
  recentThreats: "mt-5 max-w-full overflow-hidden",
  recentThreatHeading: "flex min-w-0 items-center justify-between gap-3",
  recentThreatBadge:
    "whitespace-nowrap rounded-full border border-[var(--button-border)] bg-[var(--button-bg)] px-3 py-2 text-[var(--accent)]",
  recentThreatTrack:
    "mt-2 flex min-h-[118px] max-w-full gap-3 overflow-x-auto overflow-y-visible overscroll-x-contain pb-2 [scroll-snap-type:x_proximity]",
  threatRow:
    "flex min-h-24 min-w-[280px] shrink-0 snap-start flex-col gap-1 rounded-[14px] border border-[var(--line)] bg-[var(--soft-card-bg)] p-2.5 text-left",
  rulePanel: "mb-5",
  ruleGrid:
    "mt-4 grid items-start gap-2.5 lg:grid-cols-[minmax(260px,0.85fr)_minmax(0,1fr)_minmax(0,1fr)]",
  ruleGridTwo:
    "mt-3 grid items-start gap-2.5 md:grid-cols-[minmax(220px,0.85fr)_minmax(0,1.15fr)]",
  ruleList: "grid max-h-[300px] gap-2 overflow-auto",
  ruleListEdit: "grid max-h-[460px] gap-2 overflow-auto",
  ruleListItem:
    "grid gap-1 rounded-xl border border-transparent bg-[var(--soft-card-bg)] p-2.5 text-left text-[var(--text)]",
  ruleListItemActive:
    "border-cyan-400/45 bg-cyan-400/10",
  jsonArea:
    "min-h-[300px] w-full overflow-auto rounded-xl border border-[var(--line)] bg-[var(--input-bg)] p-3 text-[var(--text)]",
  jsonAreaEdit: "min-h-[460px] w-full overflow-auto rounded-xl border border-[var(--line)] bg-[var(--input-bg)] p-3 text-[var(--text)]",
  jsonAreaReadOnly: "resize-none",
  ruleIdInput:
    "mb-2.5 w-full rounded-xl border border-[var(--line)] bg-[var(--input-bg)] p-3 text-[var(--text)]",
  snapshotNav: "my-3 flex flex-wrap items-center gap-2.5",
  advisoryBanner:
    "mb-3.5 rounded-xl border border-yellow-400/45 bg-yellow-400/15 p-3",
  advisoryHint: "font-semibold text-[var(--accent)]",
  columnGrid: "mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2",
  columnCard: "grid gap-1 rounded-xl bg-[var(--soft-card-bg)] p-2.5",
  actionMapGrid: "my-2.5 grid gap-2",
  ruleDetail: "border-t border-[var(--line)] py-3.5",
  replayLayout: "grid w-full gap-4",
  replayStatus:
    "mb-2.5 rounded-xl border border-cyan-400/30 bg-cyan-400/10 p-3 text-[var(--accent)]",
  replayStatusBusy:
    "border-yellow-400/40 bg-yellow-400/15 text-[var(--watch)]",
  comparisonSummary: "my-4 grid grid-cols-1 gap-3 sm:grid-cols-3",
  comparisonSummaryCell:
    "rounded-[14px] border border-[var(--line)] bg-[var(--soft-card-bg)] p-3.5 text-center",
  comparisonGrid: "grid grid-cols-1 gap-3 lg:grid-cols-3",
  comparisonColumn:
    "max-h-80 overflow-auto rounded-2xl border border-[var(--line)] bg-[var(--soft-card-bg)] p-3.5",
  comparisonCard: "mt-2.5 grid gap-1.5 rounded-[14px] p-3",
  thresholdInline: "mb-2.5 grid gap-1.5"
};

const subsystemGridArea = {
  OBC: "obc",
  TCS: "tcs",
  EPS: "eps",
  ADCS: "adcs",
  COM: "com"
};

export function subsystemAreaClass(name) {
  const area = subsystemGridArea[name] || "auto";
  return area === "auto" ? "" : `lg:[grid-area:${area}]`;
}

export function severityCardClass(severity) {
  return cn(
    ui.subsystemCard,
    severity === "normal" && "border-[var(--normal)]",
    severity === "watch" && "border-yellow-400/80",
    severity === "warning" && "border-orange-400/85",
    severity === "critical" && "border-red-400/95"
  );
}

export function severityTextClass(severity) {
  if (severity === "normal") {
    return "font-bold text-[var(--normal)]";
  }
  return "text-[var(--muted)]";
}

export function statusPillClass(kind) {
  return cn(
    "mt-1.5 inline-block rounded-full px-2.5 py-1 text-xs",
    kind === "undefined" &&
      "border border-red-400/45 bg-red-500/15 text-[var(--critical)]",
    kind === "new" && "border border-cyan-400/40 bg-cyan-400/10 text-[var(--accent)]"
  );
}

export function comparisonCardClass(kind) {
  return cn(
    ui.comparisonCard,
    kind === "added" && "border border-emerald-400/35 bg-emerald-400/15",
    kind === "removed" && "border border-red-400/35 bg-red-500/15",
    kind === "changed" && "border border-yellow-400/35 bg-yellow-400/15"
  );
}
