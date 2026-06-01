"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { apiGet, apiSend } from "../lib/api";
import { cn } from "../lib/cn";
import {
  comparisonCardClass,
  severityCardClass,
  severityTextClass,
  statusPillClass,
  subsystemAreaClass,
  ui
} from "../lib/ui";

const severityLabel = {
  normal: "정상",
  watch: "관찰",
  warning: "주의",
  critical: "위험"
};

function formatStepMetricLabel(metricPercent) {
  if (metricPercent === null || metricPercent === undefined) {
    return "Flag";
  }
  const value = Number(metricPercent);
  if (value > 0) {
    return `+${value}%`;
  }
  return `${value}%`;
}

function isColumnEvidenceVisible(columnValue) {
  if (!columnValue) {
    return false;
  }
  if (columnValue.observed !== null && columnValue.observed !== undefined) {
    return true;
  }
  const percent = columnValue.abnormal_percent;
  if (percent === null || percent === undefined) {
    return false;
  }
  return Math.abs(Number(percent)) > 0;
}

function getVisibleRuleColumns(columns) {
  return Object.entries(columns || {}).filter(([, value]) => isColumnEvidenceVisible(value));
}

export default function DashboardPage() {
  const [dashboard, setDashboard] = useState(null);
  const [selectedCommunicationAt, setSelectedCommunicationAt] = useState("");
  const [selectedId, setSelectedId] = useState(null);
  const [selectedDetail, setSelectedDetail] = useState(null);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [rules, setRules] = useState(null);
  const [ruleDraft, setRuleDraft] = useState("");
  const [selectedRuleId, setSelectedRuleId] = useState("");
  const [ruleEditor, setRuleEditor] = useState("");
  const [selectedActionId, setSelectedActionId] = useState("");
  const [actionEditor, setActionEditor] = useState("");
  const [replayResult, setReplayResult] = useState(null);
  const [replayMode, setReplayMode] = useState(false);
  const [replayDashboard, setReplayDashboard] = useState(null);
  const [replayRules, setReplayRules] = useState(null);
  const [replayThresholds, setReplayThresholds] = useState(null);
  const [replayRuleId, setReplayRuleId] = useState("");
  const [replayNewRuleId, setReplayNewRuleId] = useState("");
  const [replayRuleEditor, setReplayRuleEditor] = useState("");
  const [replayThresholdDraft, setReplayThresholdDraft] = useState("");
  const [replayActions, setReplayActions] = useState(null);
  const [replayActionId, setReplayActionId] = useState("");
  const [replayNewActionId, setReplayNewActionId] = useState("");
  const [replayActionEditor, setReplayActionEditor] = useState("");
  const [replayBusy, setReplayBusy] = useState(false);
  const [replayUpdatedAt, setReplayUpdatedAt] = useState("");
  const [replayDirty, setReplayDirty] = useState(false);
  const [replayNotice, setReplayNotice] = useState("");
  const [error, setError] = useState("");
  const [snapshotIndex, setSnapshotIndex] = useState(null);
  const selectedIdRef = useRef(null);
  const selectedCommunicationAtRef = useRef("");
  const snapshotIndexRef = useRef(null);

  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  useEffect(() => {
    selectedCommunicationAtRef.current = selectedCommunicationAt;
  }, [selectedCommunicationAt]);

  useEffect(() => {
    snapshotIndexRef.current = snapshotIndex;
  }, [snapshotIndex]);

  async function loadDashboard(options = {}) {
    try {
      const payload = await apiGet("/api/dashboard");
      setDashboard(payload);
      const latestAt = payload.latest_communication?.communicated_at || "";
      const communications = payload.communications || [];

      if (options.resetToLatest) {
        setSelectedCommunicationAt(latestAt);
        selectedCommunicationAtRef.current = latestAt;
      } else {
        const preserved =
          options.communicationAt ??
          selectedCommunicationAtRef.current ??
          selectedCommunicationAt;
        const exists = preserved
          ? communications.some((item) => item.communicated_at === preserved)
          : false;
        const nextAt = exists ? preserved : latestAt;
        setSelectedCommunicationAt(nextAt);
        selectedCommunicationAtRef.current = nextAt;
      }

      const targetId = options.clearCode ? null : options.detectId ?? selectedIdRef.current;
      setSelectedId(targetId);
      if (targetId) {
        await loadDetail(targetId, { syncCommunicationAt: false });
      } else {
        setSelectedDetail(null);
        setSnapshotIndex(null);
      }
      setError("");
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  async function loadDetail(detectId, options = {}) {
    const { syncCommunicationAt = true } = options;
    try {
      const detail = await apiGet(`/api/detections/${detectId}`);
      setSelectedDetail(detail);
      setSelectedId(detectId);
      setSnapshotIndex(null);
      snapshotIndexRef.current = null;
      if (syncCommunicationAt && detail.detect_time) {
        setSelectedCommunicationAt(detail.detect_time);
        selectedCommunicationAtRef.current = detail.detect_time;
      }
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  function selectCommunication(communicatedAt) {
    selectedCommunicationAtRef.current = communicatedAt;
    setSelectedCommunicationAt(communicatedAt);
    setSelectedId(null);
    setSelectedDetail(null);
    setSnapshotIndex(null);
  }

  function clearSelectedCode() {
    setSelectedId(null);
    setSelectedDetail(null);
    setSnapshotIndex(null);
  }

  function resetToLatestCommunication() {
    const latestAt = dashboard?.latest_communication?.communicated_at || "";
    selectedCommunicationAtRef.current = latestAt;
    setSelectedCommunicationAt(latestAt);
    setSelectedId(null);
    setSelectedDetail(null);
    setSnapshotIndex(null);
  }

  async function loadRules(preferredRuleId = selectedRuleId) {
    try {
      const payload = await apiGet("/api/rules");
      setRules(payload);
      setRuleDraft(JSON.stringify(payload.thresholds, null, 2));
      const fallbackRuleId = preferredRuleId && payload.rules[preferredRuleId]
        ? preferredRuleId
        : Object.keys(payload.rules)[0] || "";
      setSelectedRuleId(fallbackRuleId);
      setRuleEditor(JSON.stringify(payload.rules[fallbackRuleId] || defaultRuleDefinition(), null, 2));
      const fallbackActionId = Object.keys(payload.actions || {})[0] || "";
      setSelectedActionId(fallbackActionId);
      setActionEditor(JSON.stringify(payload.actions?.[fallbackActionId] || defaultActionDefinition(), null, 2));
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  function selectRule(ruleId) {
    setSelectedRuleId(ruleId);
    setRuleEditor(JSON.stringify(rules?.rules?.[ruleId] || defaultRuleDefinition(), null, 2));
  }

  function selectAction(actionId) {
    setSelectedActionId(actionId);
    setActionEditor(JSON.stringify(rules?.actions?.[actionId] || defaultActionDefinition(), null, 2));
  }

  async function openReplayMode() {
    try {
      setReplayBusy(true);
      const payload = rules || await apiGet("/api/rules");
      setRules(payload);
      const rulesCopy = structuredClone(payload.rules);
      const thresholdCopy = structuredClone(payload.thresholds);
      const firstRule = Object.keys(rulesCopy)[0] || "";
      setReplayRules(rulesCopy);
      setReplayThresholds(thresholdCopy);
      setReplayRuleId(firstRule);
      setReplayNewRuleId(firstRule);
      setReplayRuleEditor(JSON.stringify(rulesCopy[firstRule] || defaultRuleDefinition(), null, 2));
      setReplayThresholdDraft(JSON.stringify(thresholdCopy, null, 2));
      const actionsCopy = structuredClone(payload.actions || {});
      const firstAction = Object.keys(actionsCopy)[0] || "";
      setReplayActions(actionsCopy);
      setReplayActionId(firstAction);
      setReplayNewActionId(firstAction);
      setReplayActionEditor(
        JSON.stringify(actionsCopy[firstAction] || defaultActionDefinition(), null, 2)
      );
      setReplayDashboard(null);
      setReplayResult(null);
      setReplayUpdatedAt("");
      setReplayDirty(false);
      setReplayNotice(
        "JSON을 수정한 뒤 «Replay 실행»으로 미리보기를 만드세요. 결과 확인 후 아래 «전체 저장»으로 파일 반영 및 MA 재분석을 실행합니다."
      );
      setRulesOpen(false);
      setReplayMode(true);
    } catch (replayError) {
      setError(replayError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  function syncReplayDrafts() {
    try {
      const nextRules = { ...(replayRules || {}) };
      const ruleId = (replayNewRuleId || replayRuleId || "").trim();
      if (ruleId) {
        nextRules[ruleId] = JSON.parse(replayRuleEditor);
      }
      const nextThresholds = JSON.parse(replayThresholdDraft);
      const nextActions = { ...(replayActions || {}) };
      const actionId = (replayNewActionId || replayActionId || "").trim();
      if (actionId) {
        nextActions[actionId] = JSON.parse(replayActionEditor);
      }
      return { ok: true, nextRules, nextThresholds, nextActions, ruleId, actionId };
    } catch (syncError) {
      return { ok: false, error: syncError.message };
    }
  }

  function applySyncedReplayState(synced) {
    setReplayRules(synced.nextRules);
    setReplayThresholds(synced.nextThresholds);
    setReplayActions(synced.nextActions);
    if (synced.ruleId) {
      setReplayRuleId(synced.ruleId);
      setReplayNewRuleId(synced.ruleId);
    }
    if (synced.actionId) {
      setReplayActionId(synced.actionId);
      setReplayNewActionId(synced.actionId);
    }
  }

  async function runReplayPreview() {
    const synced = syncReplayDrafts();
    if (!synced.ok) {
      setError(`JSON 형식 오류: ${synced.error}`);
      return;
    }
    applySyncedReplayState(synced);
    try {
      setReplayBusy(true);
      setReplayNotice("서버에서 Replay 미리보기를 계산하는 중입니다…");
      const payload = await apiSend("/api/replay/preview", "POST", {
        rules: synced.nextRules,
        thresholds: synced.nextThresholds,
        actions: synced.nextActions
      });
      setReplayResult(payload);
      setReplayDashboard(payload.dashboard);
      setReplayUpdatedAt(new Date().toLocaleTimeString());
      setReplayDirty(false);
      const comparison = payload.comparison || {};
      setReplayNotice(
        `Replay 완료 (${new Date().toLocaleTimeString()}). 기존 ${comparison.current_count ?? 0}건 → 미리보기 ${comparison.preview_count ?? 0}건 (Δ ${comparison.delta_count ?? 0}). 확정하려면 아래 «전체 저장»을 누르세요.`
      );
      setError("");
    } catch (replayError) {
      setReplayNotice("");
      setError(replayError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  function selectReplayRule(ruleId) {
    setReplayRuleId(ruleId);
    setReplayNewRuleId(ruleId);
    setReplayRuleEditor(JSON.stringify(replayRules?.[ruleId] || defaultRuleDefinition(), null, 2));
  }

  function startReplayNewRule() {
    setReplayRuleId("");
    setReplayNewRuleId("E-NEW");
    setReplayRuleEditor(JSON.stringify(defaultRuleDefinition(), null, 2));
  }

  async function deleteReplayRule() {
    try {
      if (!replayRuleId) {
        setError("삭제할 Rule을 선택하세요.");
        return;
      }
      const nextRules = { ...(replayRules || {}) };
      delete nextRules[replayRuleId];
      const nextRuleId = Object.keys(nextRules)[0] || "";
      setReplayRules(nextRules);
      setReplayRuleId(nextRuleId);
      setReplayNewRuleId(nextRuleId);
      setReplayRuleEditor(JSON.stringify(nextRules[nextRuleId] || defaultRuleDefinition(), null, 2));
      markReplayDirty("Rule이 삭제되었습니다. «Replay 실행»으로 탐지 변화를 확인하세요.");
    } catch (deleteError) {
      setError(deleteError.message);
    }
  }

  function selectReplayAction(actionId) {
    setReplayActionId(actionId);
    setReplayNewActionId(actionId);
    setReplayActionEditor(
      JSON.stringify(replayActions?.[actionId] || defaultActionDefinition(), null, 2)
    );
  }

  function startReplayNewAction() {
    setReplayActionId("");
    setReplayNewActionId("A-NEW");
    setReplayActionEditor(JSON.stringify(defaultActionDefinition(), null, 2));
  }

  async function deleteReplayAction() {
    try {
      if (!replayActionId) {
        setError("삭제할 Action을 선택하세요.");
        return;
      }
      const nextActions = { ...(replayActions || {}) };
      delete nextActions[replayActionId];
      const nextActionId = Object.keys(nextActions)[0] || "";
      setReplayActions(nextActions);
      setReplayActionId(nextActionId);
      setReplayNewActionId(nextActionId);
      setReplayActionEditor(
        JSON.stringify(nextActions[nextActionId] || defaultActionDefinition(), null, 2)
      );
      markReplayDirty("Action이 삭제되었습니다. «Replay 실행»으로 탐지 변화를 확인하세요.");
    } catch (deleteError) {
      setError(deleteError.message);
    }
  }

  async function applyReplayConfig() {
    const synced = syncReplayDrafts();
    if (!synced.ok) {
      setError(`JSON 형식 오류: ${synced.error}`);
      return;
    }
    applySyncedReplayState(synced);
    try {
      setReplayBusy(true);
      setReplayNotice(
        "Rule/Action/Threshold를 파일에 저장한 뒤, 누적된 텔레메트리 전체를 MAIntegratedDetector로 재분석하는 중입니다…"
      );
      const payload = await apiSend("/api/replay/apply", "POST", {
        rules: synced.nextRules,
        thresholds: synced.nextThresholds,
        actions: synced.nextActions
      });
      if (!payload.ok) {
        setError(payload.error || "전체 저장에 실패했습니다.");
        return;
      }
      setDashboard(payload.dashboard);
      setReplayMode(false);
      setReplayDashboard(null);
      setReplayResult(null);
      setReplayNotice("");
      await loadRules();
      await loadDashboard({ resetToLatest: true, clearCode: true });
      setError("");
    } catch (applyError) {
      setError(applyError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  function markReplayDirty(notice) {
    setReplayDirty(true);
    setReplayResult(null);
    setReplayUpdatedAt("");
    if (notice) {
      setReplayNotice(notice);
    }
  }

  function closeReplayMode() {
    setReplayMode(false);
    setReplayDashboard(null);
    setReplayResult(null);
    setReplayNotice("");
    setRulesOpen(true);
  }

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(() => loadDashboard({ preserveSnapshot: true }), 5000);
    return () => clearInterval(timer);
  }, []);

  const selectedCommunication = useMemo(() => {
    const targetAt = selectedCommunicationAt || dashboard?.latest_communication?.communicated_at;
    return dashboard?.communications?.find((communication) => communication.communicated_at === targetAt)
      || dashboard?.latest_communication;
  }, [dashboard, selectedCommunicationAt]);

  if (!dashboard) {
    return (
      <main className={ui.shell}>
        <div className={ui.loadingCard}>MA 통합 탐지 대시보드를 불러오는 중...</div>
      </main>
    );
  }

  if (replayMode) {
    return (
      <main className={ui.shell}>
        <header className={ui.topbar}>
          <div>
            <h1 className="text-2xl font-bold">Replay 결과</h1>
          </div>
          <div className={ui.btnRow}>
            <button type="button" className={ui.btnPill} onClick={closeReplayMode}>
              닫기
            </button>
          </div>
        </header>
        {error ? <section className={ui.errorBanner}>{error}</section> : null}
        <ReplayWorkspace
          comparison={replayResult?.comparison}
          replayNotice={replayNotice}
          replayRules={replayRules}
          replayThresholdDraft={replayThresholdDraft}
          replayRuleId={replayRuleId}
          replayNewRuleId={replayNewRuleId}
          replayRuleEditor={replayRuleEditor}
          replayActions={replayActions}
          replayActionId={replayActionId}
          replayNewActionId={replayNewActionId}
          replayActionEditor={replayActionEditor}
          replayBusy={replayBusy}
          replayUpdatedAt={replayUpdatedAt}
          replayDirty={replayDirty}
          onRuleSelect={selectReplayRule}
          onNewRuleIdChange={(value) => {
            setReplayNewRuleId(value);
            markReplayDirty();
          }}
          onRuleEditorChange={(value) => {
            setReplayRuleEditor(value);
            markReplayDirty();
          }}
          onThresholdDraftChange={(value) => {
            setReplayThresholdDraft(value);
            markReplayDirty();
          }}
          onStartNewRule={startReplayNewRule}
          onDeleteRule={deleteReplayRule}
          onActionSelect={selectReplayAction}
          onNewActionIdChange={(value) => {
            setReplayNewActionId(value);
            markReplayDirty();
          }}
          onActionEditorChange={(value) => {
            setReplayActionEditor(value);
            markReplayDirty();
          }}
          onStartNewAction={startReplayNewAction}
          onDeleteAction={deleteReplayAction}
          onReplay={runReplayPreview}
          onApplyAll={applyReplayConfig}
        />
      </main>
    );
  }

  return (
    <main className={ui.shell}>
      <header className={ui.topbar}>
        <div>
          <p className={ui.eyebrow}>MATADOR Ground Station</p>
          <h1 className="text-2xl font-bold">MA 통합 탐지 대시보드</h1>
        </div>
        <button
          type="button"
          className={ui.btnPill}
          onClick={async () => {
            setRulesOpen(!rulesOpen);
            if (!rules) {
              await loadRules();
            }
          }}
        >
          {rulesOpen ? "닫기" : "Rule/Threshold/Action"}
        </button>
      </header>

      {error ? <section className={ui.errorBanner}>{error}</section> : null}
      {dashboard.ingest_error ? (
        <section className={ui.errorBanner}>패킷 검증: {dashboard.ingest_error}</section>
      ) : null}

      {rulesOpen ? (
        <RulePanel
          rules={rules}
          ruleDraft={ruleDraft}
          selectedRuleId={selectedRuleId}
          ruleEditor={ruleEditor}
          selectedActionId={selectedActionId}
          actionEditor={actionEditor}
          onRuleSelect={selectRule}
          onActionSelect={selectAction}
          onReload={loadRules}
          onReplay={openReplayMode}
        />
      ) : null}

      <section className={ui.dashboardGrid}>
        <BlueprintPanel
          blueprint={dashboard.blueprint}
          recentThreats={dashboard.recent_threats}
          latestCommunication={dashboard.latest_communication}
          onSelect={loadDetail}
        />
        <RightPanel
          dashboard={dashboard}
          selectedCommunication={selectedCommunication}
          selectedCommunicationAt={selectedCommunicationAt}
          selectedId={selectedId}
          selectedDetail={selectedDetail}
          onSelect={loadDetail}
          onCommunicationSelect={selectCommunication}
          onCodeClear={clearSelectedCode}
          onResetLatest={resetToLatestCommunication}
        />
      </section>
    </main>
  );
}

function BlueprintPanel({ blueprint, recentThreats, latestCommunication, onSelect }) {
  return (
    <section className={ui.panel}>
      <div className={ui.panelHeading}>
        <div className="text-center">
          <p className={ui.eyebrow}>최근 5회 통신 기반 위성체 Blueprint</p>
        </div>
      </div>

      <div className="grid grid-cols-6 gap-4 w-full">
  {Object.values(blueprint).map((subsystem, index) => (
    <article
      key={subsystem.name}
      className={cn(
        // 상단 3개는 6칸 중 2칸씩(col-span-2), 하단 2개는 3칸씩(col-span-3) 차지
        index < 3 ? "col-span-2" : "col-span-3",
        "flex flex-col justify-between min-h-[140px]", 
        severityCardClass(subsystem.severity), 
        subsystemAreaClass(subsystem.name)
      )}
    >
      {/* 1. 타이틀 영역 */}
      <div className={ui.subsystemTitle}>
        <strong>{subsystem.name}</strong>
        <span className={severityTextClass(subsystem.severity)}>
          {severityLabel[subsystem.severity]}
        </span>
      </div>
      
      {/* 2. 버튼 및 상태 영역 (생략 없이 복구 완료!) */}
      <div className={ui.codeStack}>
        {subsystem.detections.length ? (
          subsystem.detections.slice(-3).map((detection) => (
            <button
              type="button"
              key={`${subsystem.name}-${detection.detect_id}`}
              className={ui.codeChip}
              onClick={() => onSelect(detection.detect_id)}
            >
              <span className="text-s font-mono">{detection.ma_code}</span>
              <b className="text-[var(--accent)] not-italic">P{detection.phase}</b>
              <em className="text-[var(--accent)] not-italic">{detection.confidence}%</em>
            </button>
          ))
        ) : (
          <span className={ui.muted}>최근 위협 없음</span>
        )}
      </div>
    </article>
  ))}
</div>

      <section className={ui.recentThreats}>
        <div className={ui.recentThreatHeading}>
          <h3 className="m-0 mb-3">최근 5회 위협</h3>
        </div>
        {recentThreats?.length ? (
          <div className={ui.recentThreatTrack}>
            {recentThreats.map((threat) => (
              <button
                type="button"
                key={threat.detect_id}
                className={cn(ui.threatRow, severityCardClass(threat.severity))}
                onClick={() => onSelect(threat.detect_id)}
              >
                <span className="text-s font-mono"><strong>{threat.ma_code}</strong></span>
                {threat.action_mapping_status === "undefined" ? (
                  <span className={statusPillClass("undefined")}>Action 미매핑</span>
                ) : null}
                <span className={ui.muted}>{(threat.subsystems || [threat.module]).join(" · ")}</span>
                <em className="text-[var(--accent)] not-italic">
                  P{threat.phase} · {threat.confidence}% · {threat.grade}
                </em>
                <span className={ui.muted}>{threat.detect_time}</span>
              </button>
            ))}
          </div>
        ) : (
          <p className={ui.muted}>최근 위협이 없습니다.</p>
        )}
      </section>
    </section>
  );
}

function RightPanel({
  dashboard,
  selectedCommunication,
  selectedCommunicationAt,
  selectedId,
  selectedDetail,
  onSelect,
  onCommunicationSelect,
  onCodeClear,
  onResetLatest
}) {
  const latest = dashboard.latest_communication;
  return (
    <section className={ui.panel}>
      <div className={ui.selectorRow}>
        <label className={cn(ui.searchBox, "min-w-[360px] flex-[1.2_1_360px]")}>
          <select
            className={ui.searchSelect}
            value={selectedCommunicationAt || latest.communicated_at || ""}
            onChange={(event) => onCommunicationSelect(event.target.value)}
          >
            {(dashboard.communications || []).map((communication) => (
              <option key={communication.communicated_at} value={communication.communicated_at}>
                {communication.received_at || communication.communicated_at}
                {" · "}
                {(communication.anomaly_count || 0) > 0
                  ? `MA ${communication.anomaly_count}건`
                  : "정상"}
              </option>
            ))}
          </select>
        </label>
        <label className={ui.searchBox}>
          <span aria-hidden="true">🔍</span>
          <select
            className={ui.searchSelect}
            value={selectedId || ""}
            onChange={(event) => {
              if (event.target.value) {
                onSelect(event.target.value);
              } else {
                onCodeClear();
              }
            }}
          >
            <option value="">MA 코드 선택 안 함</option>
            {dashboard.detections.map((detection) => (
              <option key={detection.detect_id} value={detection.detect_id}>
                {detection.ma_code}
              </option>
            ))}
          </select>
        </label>
        <button type="button" className={cn(ui.btnPill, "min-w-[126px]")} onClick={onResetLatest}>
          초기화
        </button>
      </div>

      {selectedDetail ? (
        <DetailPanel selectedDetail={selectedDetail} />
      ) : (
        <CommunicationSummary communication={selectedCommunication} onSelect={onSelect} />
      )}
    </section>
  );
}

function CommunicationSummary({ communication, onSelect }) {
  if (!communication) {
    return <div className={cn(ui.detailCard, ui.muted)}>통신 기록이 없습니다.</div>;
  }

  return (
    <div className={ui.detailCard}>
      <div className={ui.detailHeading}>
        <div>
          <h3 className="m-0">{communication.received_at || communication.communicated_at}</h3>
          {communication.onboard_snapshot_at ? (
            <p className={cn(ui.muted, "m-0 mt-1 text-sm")}>
            </p>
          ) : null}
        </div>
        <strong className={ui.detailAccent}>
          {(communication.anomaly_count || 0) > 0 ? `MA ${communication.anomaly_count}건` : "정상"}
        </strong>
      </div>
      {(communication.detections || []).length ? (
        <div className={ui.codeList}>
          {communication.detections.map((detection, index) => (
            <button
              type="button"
              key={detection.detect_id}
              className={cn(ui.codeButton, severityCardClass(detection.severity))}
              onClick={() => onSelect(detection.detect_id)}
            >
              <span className={ui.muted}>{index + 1}번째 발생</span>
              <strong>{detection.ma_code}</strong>
              <em className="text-[var(--accent)] not-italic">
                Phase {detection.phase} · 신뢰도 {detection.confidence}%
              </em>
            </button>
          ))}
        </div>
      ) : (
        <p className={ui.muted}>해당 통신은 정상입니다.</p>
      )}
    </div>
  );
}

function DetailPanel({ selectedDetail }) {
  if (!selectedDetail) {
    return <div className={cn(ui.detailCard, ui.muted)}>코드를 선택하면 Rule 근거가 표시됩니다.</div>;
  }

  const frame = selectedDetail.snapshot_frame;
  const isUndefinedAction = selectedDetail.action_mapping_status === "undefined";

  return (
    <div className={ui.detailCard}>
      {selectedDetail.novel_attack_advisory ? (
        <section className={ui.advisoryBanner}>
          <strong>{selectedDetail.novel_attack_advisory.title}</strong>
          <p className="mt-1.5 mb-0">{selectedDetail.novel_attack_advisory.message}</p>
          {selectedDetail.novel_attack_advisory.register_action_hint ? (
            <p className={ui.advisoryHint}>{selectedDetail.novel_attack_advisory.register_action_hint}</p>
          ) : null}
          {(selectedDetail.unregistered_action_ids || []).length ? (
            <p className={ui.muted}>
              Rule에만 있고 registry에 없는 Action ID:{" "}
              {selectedDetail.unregistered_action_ids.join(", ")}
            </p>
          ) : null}
        </section>
      ) : null}
      <div className={ui.detailHeading}>
        <div>
          <p className={ui.eyebrow}>선택 코드 상세</p>
          <h3 className="m-0">{selectedDetail.ma_code}</h3>
          {isUndefinedAction ? (
            <span className={statusPillClass("undefined")}>Action 미매핑</span>
          ) : null}
          {selectedDetail.is_new_pattern && !isUndefinedAction ? (
            <span className={statusPillClass("new")}>신규 MA 코드</span>
          ) : null}
        </div>
        <strong className={ui.detailAccent}>{selectedDetail.confidence_score}%</strong>
      </div>
      <div className={ui.filterGrid}>
        <span className={ui.filterCell}>위성체 판정: {selectedDetail.satellite_filter?.result || "-"}</span>
        <span className={ui.filterCell}>가중치: {selectedDetail.satellite_filter?.weight || "-"}</span>
        <span className={ui.filterCell}>대상: {selectedDetail.satellite_filter?.target_subsystem || "-"}</span>
        <span className={ui.filterCell}>이벤트: {selectedDetail.satellite_filter?.event_id || "-"}</span>
      </div>
      {frame?.current_at ? (
        <p className={ui.muted}>
          직전 스냅샷: {frame.previous_at || "-"} → 현재: {frame.current_at}
        </p>
      ) : null}

      <div>
        {(selectedDetail.rule_details || []).map((rule) => (
          <article key={rule.rule_id} className={ui.ruleDetail}>
            <div>
              <strong>
                {rule.rule_id} · {rule.name}
              </strong>
              <span className={cn(ui.muted, "block")}>
                최초 활성화: {rule.first_triggered_at}
                {rule.rule_score !== undefined && rule.rule_score !== null
                  ? ` · Rule 점수 ${rule.rule_score}`
                  : ""}
              </span>
            </div>
            {(rule.unmapped_actions || []).length ? (
              <div className={ui.actionMapGrid}>
                <p className={ui.muted}>미등록 Action (contributes_to에만 존재)</p>
                {rule.unmapped_actions.map((action) => (
                  <div
                    key={action.action_id}
                    className={cn(ui.columnCard, "border border-red-400/55")}
                  >
                    <b>{action.action_id}</b>
                    <span className={ui.muted}>이름: {action.name}</span>
                    <span className={ui.muted}>가중치: {action.weight}</span>
                    <em className="text-[var(--accent)] not-italic">action_registry.json에 추가 필요</em>
                  </div>
                ))}
              </div>
            ) : null}
            {(rule.mapped_actions || []).length ? (
              <div className={ui.actionMapGrid}>
                <p className={ui.muted}>등록된 Action 기여</p>
                {rule.mapped_actions.map((action) => (
                  <div key={action.action_id} className={ui.columnCard}>
                    <b>
                      {action.action_id} · {action.name}
                    </b>
                    <span className={ui.muted}>
                      module: {action.module} · P{action.phase}
                    </span>
                    <span className={ui.muted}>가중치: {action.weight}</span>
                  </div>
                ))}
              </div>
            ) : null}
            {Object.entries(rule.columns || {}).length ? (
              <div className={ui.columnGrid}>
                {(isUndefinedAction
                  ? Object.entries(rule.columns)
                  : getVisibleRuleColumns(rule.columns)
                ).map(([column, value]) => (
                  <div key={column} className={ui.columnCard}>
                    <b>{column}</b>
                    <span className={ui.muted}>관측: {String(value.observed ?? "-")}</span>
                    <span className={ui.muted}>
                      직전 스냅샷: {String(value.previous_observed ?? "-")}
                    </span>
                    <span className={ui.muted}>비교 기준: {String(value.normal ?? "-")}</span>
                    <em className="text-[var(--accent)] not-italic">
                      직전 1초 대비 변화율: {formatStepMetricLabel(value.abnormal_percent)}
                    </em>
                  </div>
                ))}
              </div>
            ) : null}
          </article>
        ))}
      </div>
    </div>
  );
}

function RulePanel({
  rules,
  ruleDraft,
  selectedRuleId,
  ruleEditor,
  selectedActionId,
  actionEditor,
  onRuleSelect,
  onActionSelect,
  onReload,
  onReplay
}) {
  return (
    <section className={cn(ui.panel, ui.rulePanel)}>
      <div className={ui.panelHeading}>
        <div className="font-semibold gap-2 flex ml-auto">
          <button type="button" className={ui.btnPill} onClick={onReload}>
            새로고침
          </button>
          <button type="button" className={ui.btnPill} onClick={onReplay}>
            Replay
          </button>
        </div>
      </div>

      <div className={ui.ruleGrid}>
        <div>
          <h3 className="m-0 mb-3">Rule 목록</h3>
          <div className={ui.ruleList}>
            {rules ? (
              Object.entries(rules.rules).map(([ruleId, rule]) => (
                <button
                  type="button"
                  key={ruleId}
                  className={cn(
                    ui.ruleListItem,
                    selectedRuleId === ruleId && ui.ruleListItemActive
                  )}
                  onClick={() => onRuleSelect(ruleId)}
                >
                  <strong>
                    {ruleId} · {rule.name}
                  </strong>
                  <span className={ui.muted}>
                    {rule.enabled ? "활성" : "비활성"} · {rule.subsystems.join(", ")}
                  </span>
                </button>
              ))
            ) : (
              <p className={ui.muted}>Rule을 불러오는 중입니다.</p>
            )}
          </div>
        </div>
        <div>
          <h3 className="m-0 mb-3">Rule JSON</h3>
          <textarea
            className={cn(ui.jsonArea, ui.jsonAreaReadOnly)}
            value={ruleEditor}
            readOnly
          />
        </div>
        <div>
          <h3 className="m-0 mb-3">Threshold JSON</h3>
          <textarea className={cn(ui.jsonArea, ui.jsonAreaReadOnly)} value={ruleDraft} readOnly />
        </div>
      </div>

      <div className={ui.ruleGridTwo}>
        <div>
          <h3 className="m-0 mb-3">Action 목록</h3>
          <div className={ui.ruleList}>
            {rules ? (
              Object.entries(rules.actions || {}).map(([actionId, action]) => (
                <button
                  type="button"
                  key={actionId}
                  className={cn(
                    ui.ruleListItem,
                    selectedActionId === actionId && ui.ruleListItemActive
                  )}
                  onClick={() => onActionSelect(actionId)}
                >
                  <strong>
                    {actionId} · {action.name}
                  </strong>
                  <span className={ui.muted}>
                    {action.module} · P{action.phase}
                  </span>
                </button>
              ))
            ) : (
              <p className={ui.muted}>Action을 불러오는 중입니다.</p>
            )}
          </div>
        </div>
        <div className="min-w-0">
          <h3 className="m-0 mb-3">Action JSON</h3>
          <textarea className={cn(ui.jsonArea, ui.jsonAreaReadOnly)} value={actionEditor} readOnly />
        </div>
      </div>
    </section>
  );
}

function ReplayWorkspace({
  comparison,
  replayNotice,
  replayRules,
  replayThresholdDraft,
  replayRuleId,
  replayNewRuleId,
  replayRuleEditor,
  replayActions,
  replayActionId,
  replayNewActionId,
  replayActionEditor,
  replayBusy,
  replayUpdatedAt,
  replayDirty,
  onRuleSelect,
  onNewRuleIdChange,
  onRuleEditorChange,
  onThresholdDraftChange,
  onStartNewRule,
  onDeleteRule,
  onActionSelect,
  onNewActionIdChange,
  onActionEditorChange,
  onStartNewAction,
  onDeleteAction,
  onReplay,
  onApplyAll
}) {
  const actionCount = Object.keys(replayActions || {}).length;
  const ruleCount = Object.keys(replayRules || {}).length;

  return (
    <section className={ui.replayLayout}>
      {replayNotice ? (
        <section
          className={cn(
            ui.infoBanner,
            replayDirty && !replayBusy && "border-yellow-400/40 bg-yellow-400/15"
          )}
        >
          {replayBusy ? <span className={cn(ui.replaySpinner, "mr-2")} aria-hidden /> : null}
          {replayNotice}
        </section>
      ) : null}
      <p className={cn(ui.muted, "m-0 text-sm")}>
        Rule {ruleCount}개 · Action {actionCount}개
        {replayDirty ? " · 변경됨 (Replay 실행 필요)" : ""}
        {replayBusy ? " · 서버 처리 중…" : ""}
      </p>
      <section className={cn(ui.panel, ui.rulePanel)}>
        <div className={ui.panelHeading}>
          <div>
          </div>
          <div className={ui.btnRow}>
            <button type="button" className={ui.btnPill} onClick={onStartNewRule}>
              Rule 추가
            </button>
            <button type="button" className={ui.btnPill} onClick={onDeleteRule}>
              Rule 삭제
            </button>
            <button type="button" className={ui.btnPill} onClick={onReplay} disabled={replayBusy}>
              {replayBusy ? "Replay 실행 중..." : "Replay 실행"}
            </button>
          </div>
        </div>
        <div className={ui.ruleGrid}>
          <div>
            <h3 className="m-0 mb-3">Rule</h3>
            <div className={ui.ruleListEdit}>
              {Object.entries(replayRules || {}).map(([ruleId, rule]) => (
                <button
                  type="button"
                  key={ruleId}
                  className={cn(
                    ui.ruleListItem,
                    (replayNewRuleId || replayRuleId) === ruleId && ui.ruleListItemActive
                  )}
                  onClick={() => onRuleSelect(ruleId)}
                >
                  <strong>
                    {ruleId} · {rule.name}
                  </strong>
                  <span className={ui.muted}>
                    {rule.enabled ? "활성" : "비활성"} · {(rule.subsystems || []).join(", ")}
                  </span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <h3 className="m-0 mb-3">Rule JSON</h3>
            <label className={ui.thresholdInline}>
              <input
                className={ui.ruleIdInput}
                placeholder="Rule ID"
                value={replayNewRuleId || replayRuleId || ""}
                onChange={(event) => onNewRuleIdChange(event.target.value)}
              />
              <span className={ui.muted}>활성화 임계값(score_threshold)</span>
              <input
                className={ui.ruleIdInput}
                type="number"
                step="0.05"
                value={readRuleThreshold(replayRuleEditor)}
                onChange={(event) =>
                  onRuleEditorChange(updateRuleThreshold(replayRuleEditor, event.target.value))
                }
              />
            </label>
            <textarea
              className={ui.jsonArea}
              value={replayRuleEditor}
              onChange={(event) => onRuleEditorChange(event.target.value)}
            />
          </div>
          <div>
            <h3 className="m-0 mb-3">Threshold JSON</h3>
            <textarea
              className={ui.jsonAreaEdit}
              value={replayThresholdDraft}
              onChange={(event) => onThresholdDraftChange(event.target.value)}
            />
          </div>
        </div>

        <div className={cn(ui.btnRow, "mt-4")}>
          <input
            className={cn(ui.ruleIdInput, "mb-0 flex-1")}
            placeholder="Action ID (예: A015)"
            value={replayNewActionId || replayActionId || ""}
            onChange={(event) => onNewActionIdChange(event.target.value)}
          />
          <button type="button" className={ui.btnPill} onClick={onStartNewAction}>
            Action 추가
          </button>
          <button type="button" className={ui.btnPill} onClick={onDeleteAction}>
            Action 삭제
          </button>
        </div>

        <div className={ui.ruleGridTwo}>
          <div>
            <h3 className="m-0 mb-3">Action</h3>
            <div className={ui.ruleList}>
              {Object.entries(replayActions || {}).map(([actionId, action]) => (
                <button
                  type="button"
                  key={actionId}
                  className={cn(
                    ui.ruleListItem,
                    (replayNewActionId || replayActionId) === actionId && ui.ruleListItemActive
                  )}
                  onClick={() => onActionSelect(actionId)}
                >
                  <strong>
                    {actionId} · {action.name}
                  </strong>
                  <span className={ui.muted}>
                    {action.module} · P{action.phase}
                  </span>
                </button>
              ))}
            </div>
          </div>
          <div className="min-w-0">
            <h3 className="m-0 mb-3">Action JSON</h3>
            <textarea
              className={ui.jsonArea}
              value={replayActionEditor}
              onChange={(event) => onActionEditorChange(event.target.value)}
            />
          </div>
        </div>
      </section>
      <ReplayComparison
        comparison={comparison}
        replayBusy={replayBusy}
        replayDirty={replayDirty}
        replayUpdatedAt={replayUpdatedAt}
        onApplyAll={onApplyAll}
      />
    </section>
  );
}

function ReplayComparison({
  comparison,
  replayBusy,
  replayDirty,
  replayUpdatedAt,
  onApplyAll
}) {
  if (!comparison) {
    return (
      <section className={ui.panel}>
        <h3 className="m-0 mb-3">탐지 결과 비교</h3>
        <div className={cn(ui.replayStatus, replayBusy && ui.replayStatusBusy)}>
          {replayBusy ? (
            <>
              <span className={cn(ui.replaySpinner, "mr-2")} aria-hidden />
              서버에서 Replay 미리보기를 계산하는 중입니다…
            </>
          ) : replayDirty ? (
            "편집 내용이 바뀌었습니다. «Replay 실행»을 누르면 여기에 비교 결과가 표시됩니다."
          ) : (
            "Rule/Action/Threshold JSON을 수정한 뒤 «Replay 실행»을 누르세요."
          )}
        </div>
      </section>
    );
  }

  return (
    <section className={ui.panel}>
      <div className={ui.panelHeading}>
        <div>
          <p className={ui.eyebrow}>Replay Diff</p>
          <h2 className={ui.heading}>기존 탐지 결과 vs Replay 기준 결과</h2>
        </div>
        <button type="button" className={ui.btnPill} onClick={onApplyAll} disabled={replayBusy}>
          {replayBusy ? "전체 저장·재분석 중…" : "전체 저장"}
        </button>
      </div>

      <div className={ui.comparisonSummary}>
        <span className={ui.comparisonSummaryCell}>기존 {comparison.current_count}개</span>
        <span className={ui.comparisonSummaryCell}>Replay {comparison.preview_count}개</span>
        <span className={ui.comparisonSummaryCell}>
          {comparison.delta_count >= 0 ? "+" : ""}
          {comparison.delta_count}개
        </span>
      </div>

      <div className={ui.comparisonGrid}>
        <ComparisonColumn title="추가됨 +" items={comparison.added} kind="added" />
        <ComparisonColumn title="삭제됨 -" items={comparison.removed} kind="removed" />
        <ChangedColumn items={comparison.changed} />
      </div>
    </section>
  );
}

function ComparisonColumn({ title, items, kind }) {
  return (
    <div className={ui.comparisonColumn}>
      <h3 className="m-0 mb-3">{title}</h3>
      {items?.length ? (
        items.map((item) => (
          <article key={`${kind}-${item.ma_code}`} className={comparisonCardClass(kind)}>
            <strong>{item.ma_code}</strong>
            <span className={ui.muted}>
              Phase {item.phase} · {item.confidence}% · {item.grade}
            </span>
            <em className={ui.muted}>{item.detect_time}</em>
          </article>
        ))
      ) : (
        <p className={ui.muted}>변화 없음</p>
      )}
    </div>
  );
}

function ChangedColumn({ items }) {
  return (
    <div className={ui.comparisonColumn}>
      <h3 className="m-0 mb-3">변경됨 ±</h3>
      {items?.length ? (
        items.map((item) => (
          <article key={`changed-${item.ma_code}`} className={comparisonCardClass("changed")}>
            <strong>{item.ma_code}</strong>
            <span className={ui.muted}>
              {item.current.confidence}% → {item.preview.confidence}% (
              {item.confidence_delta >= 0 ? "+" : ""}
              {item.confidence_delta})
            </span>
            <em className={ui.muted}>
              Phase {item.current.phase} → {item.preview.phase}
            </em>
          </article>
        ))
      ) : (
        <p className={ui.muted}>변화 없음</p>
      )}
    </div>
  );
}

function readRuleThreshold(ruleEditor) {
  try {
    const parsed = JSON.parse(ruleEditor);
    return parsed.score_threshold ?? 0;
  } catch {
    return 0;
  }
}

function updateRuleThreshold(ruleEditor, value) {
  try {
    const parsed = JSON.parse(ruleEditor);
    parsed.score_threshold = Number(value);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return ruleEditor;
  }
}

function defaultRuleDefinition() {
  return {
    name: "새 Rule",
    subsystems: ["OBC"],
    columns: [],
    contributes_to: {},
    single_sufficient: false,
    enabled: true,
    score_threshold: 0
  };
}

function defaultActionDefinition() {
  return {
    name: "NEW_ATTACK_PATTERN",
    module: "OBC",
    phase: 1,
    weight: 1.0,
    description: "신규 공격 패턴 — Rule contributes_to와 함께 등록"
  };
}

