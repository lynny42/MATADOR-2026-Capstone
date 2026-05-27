"use client";

import { useEffect, useMemo, useState } from "react";
import { apiGet, apiSend } from "../lib/api";

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
  const percent = columnValue.abnormal_percent;
  if (percent === null || percent === undefined) {
    return true;
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
  const [replayResult, setReplayResult] = useState(null);
  const [replayMode, setReplayMode] = useState(false);
  const [replayDashboard, setReplayDashboard] = useState(null);
  const [replayRules, setReplayRules] = useState(null);
  const [replayThresholds, setReplayThresholds] = useState(null);
  const [replayRuleId, setReplayRuleId] = useState("");
  const [replayNewRuleId, setReplayNewRuleId] = useState("");
  const [replayRuleEditor, setReplayRuleEditor] = useState("");
  const [replayThresholdDraft, setReplayThresholdDraft] = useState("");
  const [replayBusy, setReplayBusy] = useState(false);
  const [replayUpdatedAt, setReplayUpdatedAt] = useState("");
  const [replayDirty, setReplayDirty] = useState(false);
  const [error, setError] = useState("");
  const [snapshotIndex, setSnapshotIndex] = useState(null);

  async function loadDashboard(options = {}) {
    try {
      const payload = await apiGet("/api/dashboard");
      setDashboard(payload);
      const latestAt = payload.latest_communication?.communicated_at || "";
      const communicationAt = options.resetToLatest
        ? latestAt
        : (options.communicationAt ?? selectedCommunicationAt) || latestAt;
      const targetId = options.clearCode ? null : options.detectId ?? selectedId;
      setSelectedCommunicationAt(communicationAt);
      setSelectedId(targetId);
      if (targetId) {
        await loadDetail(targetId);
      } else {
        setSelectedDetail(null);
        setSnapshotIndex(null);
      }
      setError("");
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  async function loadDetail(detectId, frameIndex = null) {
    try {
      const query =
        frameIndex !== null && frameIndex !== undefined
          ? `?snapshot_index=${frameIndex}`
          : "";
      const detail = await apiGet(`/api/detections/${detectId}${query}`);
      setSelectedDetail(detail);
      setSelectedId(detectId);
      if (detail.snapshot_frame) {
        setSnapshotIndex(detail.snapshot_frame.index);
      } else {
        setSnapshotIndex(null);
      }
      if (detail.detect_time) {
        setSelectedCommunicationAt(detail.detect_time);
      }
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  function stepSnapshotFrame(direction) {
    const frame = selectedDetail?.snapshot_frame;
    if (!frame || selectedId == null) {
      return;
    }
    const nextIndex = Math.max(0, Math.min(frame.index + direction, frame.total - 1));
    if (nextIndex === frame.index) {
      return;
    }
    loadDetail(selectedId, nextIndex);
  }

  function selectCommunication(communicatedAt) {
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
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  function selectRule(ruleId) {
    setSelectedRuleId(ruleId);
    setRuleEditor(JSON.stringify(rules?.rules?.[ruleId] || defaultRuleDefinition(), null, 2));
  }

  async function openReplayMode() { /* 처음 리플레이 누르고 들어간 거면 로딩이 걸릴 필요가 없지 */
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
      setReplayNewRuleId("");
      setReplayRuleEditor(JSON.stringify(rulesCopy[firstRule] || defaultRuleDefinition(), null, 2));
      setReplayThresholdDraft(JSON.stringify(thresholdCopy, null, 2));
      setReplayDashboard(true);
      setReplayResult(null);
      setReplayUpdatedAt("");
      setReplayDirty(false);
      setRulesOpen(false);
      setReplayMode(true);
    } catch (replayError) {
      setError(replayError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  async function runReplayPreview(nextRules = replayRules, nextThresholds = replayThresholds) {
    try {
      setReplayBusy(true);
      const payload = await apiSend("/api/replay/preview", "POST", {
        rules: nextRules,
        thresholds: nextThresholds
      });
      setReplayResult(payload);
      setReplayDashboard(payload.dashboard);
      setReplayUpdatedAt(new Date().toLocaleTimeString());
      setReplayDirty(false);
      setError("");
    } catch (replayError) {
      setError(replayError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  function selectReplayRule(ruleId) {
    setReplayRuleId(ruleId);
    setReplayNewRuleId("");
    setReplayRuleEditor(JSON.stringify(replayRules?.[ruleId] || defaultRuleDefinition(), null, 2));
  }

  function startReplayNewRule() {
    setReplayRuleId("");
    setReplayNewRuleId("E-NEW");
    setReplayRuleEditor(JSON.stringify(defaultRuleDefinition(), null, 2));
  }

  async function saveReplayRule() {
    try {
      const ruleId = (replayNewRuleId || replayRuleId).trim();
      if (!ruleId) {
        setError("저장할 임시 Rule ID가 필요합니다.");
        return;
      }
      const nextRules = { ...(replayRules || {}) };
      nextRules[ruleId] = JSON.parse(replayRuleEditor);
      setReplayRules(nextRules);
      setReplayRuleId(ruleId);
      setReplayNewRuleId("");
      markReplayDirty();
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  async function deleteReplayRule() {
    try {
      if (!replayRuleId) {
        setError("삭제할 임시 Rule을 선택하세요.");
        return;
      }
      const nextRules = { ...(replayRules || {}) };
      delete nextRules[replayRuleId];
      const nextRuleId = Object.keys(nextRules)[0] || "";
      setReplayRules(nextRules);
      setReplayRuleId(nextRuleId);
      setReplayRuleEditor(JSON.stringify(nextRules[nextRuleId] || defaultRuleDefinition(), null, 2));
      markReplayDirty();
    } catch (deleteError) {
      setError(deleteError.message);
    }
  }

  async function saveReplayThresholds() {
    try {
      const nextThresholds = JSON.parse(replayThresholdDraft);
      setReplayThresholds(nextThresholds);
      markReplayDirty();
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  function markReplayDirty() {
    setReplayDirty(true);
    setReplayDashboard(null);
    setReplayResult(null);
    setReplayUpdatedAt("");
  }

  async function applyReplayConfig() {
    try {
      setReplayBusy(true);
      const payload = await apiSend("/api/replay/apply", "POST", {
        rules: replayRules,
        thresholds: replayThresholds
      });
      setDashboard(payload.dashboard);
      setReplayMode(false);
      setReplayDashboard(null);
      setReplayResult(null);
      await loadRules();
      await loadDashboard({ resetToLatest: true, clearCode: true });
    } catch (applyError) {
      setError(applyError.message);
    } finally {
      setReplayBusy(false);
    }
  }

  function closeReplayMode() {
    setReplayMode(false);
    setReplayDashboard(null);
    setReplayResult(null);
    setRulesOpen(true);
  }

  useEffect(() => {
    loadDashboard();
    const timer = setInterval(() => loadDashboard(), 5000);
    return () => clearInterval(timer);
  }, [selectedId, selectedCommunicationAt]);

  const selectedCommunication = useMemo(() => {
    const targetAt = selectedCommunicationAt || dashboard?.latest_communication?.communicated_at;
    return dashboard?.communications?.find((communication) => communication.communicated_at === targetAt)
      || dashboard?.latest_communication;
  }, [dashboard, selectedCommunicationAt]);

  if (!dashboard) {
    return (
      <main className="page-shell">
        <div className="loading-card">MA 통합 탐지 대시보드를 불러오는 중...</div>
      </main>
    );
  }

  if (replayMode) {
    return (
      <main className="page-shell">
        <header className="topbar">
          <div>
            <p className="eyebrow">Temporary Replay</p>
            <h1>Replay 임시 결과</h1>
          </div>
          <div className="rule-actions">
            <button onClick={applyReplayConfig}>설정</button>
            <button onClick={closeReplayMode}>닫기</button>
          </div>
        </header>
        {error ? <section className="error-banner">{error}</section> : null}
        <ReplayWorkspace
          dashboard={replayDashboard}
          comparison={replayResult?.comparison}
          replayRules={replayRules}
          replayThresholdDraft={replayThresholdDraft}
          replayRuleId={replayRuleId}
          replayNewRuleId={replayNewRuleId}
          replayRuleEditor={replayRuleEditor}
          replayBusy={replayBusy}
          replayUpdatedAt={replayUpdatedAt}
          replayDirty={replayDirty}
          onRuleSelect={selectReplayRule}
          onNewRuleIdChange={setReplayNewRuleId}
          onRuleEditorChange={setReplayRuleEditor}
          onThresholdDraftChange={setReplayThresholdDraft}
          onStartNewRule={startReplayNewRule}
          onSaveRule={saveReplayRule}
          onDeleteRule={deleteReplayRule}
          onSaveThresholds={saveReplayThresholds}
          onReplay={() => runReplayPreview()}
        />
      </main>
    );
  }

  return (
    <main className="page-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">MATADOR Ground Station</p>
          <h1>MA 통합 탐지 대시보드</h1>
        </div>
        <button
          className="rule-button"
          onClick={async () => {
            setRulesOpen(!rulesOpen);
            if (!rules) {
              await loadRules();
            }
          }}
        >
          {rulesOpen ? "닫기" : "Rule"}
        </button>
      </header>

      {error ? <section className="error-banner">{error}</section> : null}
      {dashboard.ingest_error ? (
        <section className="error-banner">패킷 검증: {dashboard.ingest_error}</section>
      ) : null}

      {rulesOpen ? (
        <RulePanel
          rules={rules}
          ruleDraft={ruleDraft}
          selectedRuleId={selectedRuleId}
          ruleEditor={ruleEditor}
          onRuleSelect={selectRule}
          onReload={loadRules}
          onReplay={openReplayMode}
        />
      ) : null}

      <section className="dashboard-grid">
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
          snapshotIndex={snapshotIndex}
          onSelect={loadDetail}
          onCommunicationSelect={selectCommunication}
          onCodeClear={clearSelectedCode}
          onResetLatest={resetToLatestCommunication}
          onSnapshotPrev={() => stepSnapshotFrame(-1)}
          onSnapshotNext={() => stepSnapshotFrame(1)}
        />
      </section>
    </main>
  );
}

function BlueprintPanel({ blueprint, recentThreats, latestCommunication, onSelect }) {
  return (
    <section className="panel blueprint-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">최근 5회 통신 기반</p>
          <h2>위성체 Blueprint</h2>
        </div>
      </div>

      <div className="satellite-map">
        {Object.values(blueprint).map((subsystem) => (
          <article
            key={subsystem.name}
            className={`subsystem-card severity-${subsystem.severity}`}
          >
            <div className="subsystem-title">
              <strong>{subsystem.name}</strong>
              <span>{severityLabel[subsystem.severity]}</span>
            </div>
            <div className="code-stack">
              {subsystem.detections.length ? (
                subsystem.detections.slice(-3).map((detection) => (
                  <button
                    key={`${subsystem.name}-${detection.detect_id}`}
                    className="code-chip"
                    onClick={() => onSelect(detection.detect_id)}
                  >
                    <span>{detection.ma_code}</span>
                    <b>P{detection.phase}</b>
                    <em>{detection.confidence}%</em>
                  </button>
                ))
              ) : (
                <span className="no-code">최근 위협 없음</span>
              )}
            </div>
          </article>
        ))}
      </div>

      <section className="recent-threats">
        <div className="recent-threat-heading">
          <h3>최근 5회 위협</h3>
          <span>{recentThreats?.length || 0}건</span>
        </div>
        {recentThreats?.length ? (
          <div className="recent-threat-track">
            {recentThreats.map((threat) => (
              <button
                type="button"
                key={threat.detect_id}
                className={`threat-row severity-${threat.severity}`}
                onClick={() => onSelect(threat.detect_id)}
              >
                <strong>{threat.ma_code}</strong>
                <span>{(threat.subsystems || [threat.module]).join(" · ")}</span>
                <em>
                  P{threat.phase} · {threat.confidence}% · {threat.grade}
                </em>
                <span>{threat.detect_time}</span>
              </button>
            ))}
          </div>
        ) : (
          <p className="muted">최근 위협이 없습니다.</p>
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
  snapshotIndex,
  onSelect,
  onCommunicationSelect,
  onCodeClear,
  onResetLatest,
  onSnapshotPrev,
  onSnapshotNext
}) {
  const latest = dashboard.latest_communication;
  return (
    <section className="panel right-panel">
      <div className="selector-row">
        <label className="search-box communication-select">
          <span className="">통신</span>
          <select
            value={selectedCommunicationAt || latest.communicated_at || ""}
            onChange={(event) => onCommunicationSelect(event.target.value)}
          >
            {(dashboard.communications || []).map((communication) => (
              <option key={communication.communicated_at} value={communication.communicated_at}>
                {communication.communicated_at} · {communication.anomaly_count}개
              </option>
            ))}
          </select>
        </label>
        <label className="search-box">
          <span aria-hidden="true">🔍</span>
          <select
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
        <button className="reset-button" onClick={onResetLatest}>
          초기화
        </button>
      </div>

      {selectedDetail ? (
        <DetailPanel
          selectedDetail={selectedDetail}
          snapshotIndex={snapshotIndex}
          onSnapshotPrev={onSnapshotPrev}
          onSnapshotNext={onSnapshotNext}
        />
      ) : (
        <CommunicationSummary communication={selectedCommunication} onSelect={onSelect} />
      )}
    </section>
  );
}

function CommunicationSummary({ communication, onSelect }) {
  if (!communication) {
    return <div className="detail-card muted">통신 기록이 없습니다.</div>;
  }

  return (
    <div className="detail-card">
      <div className="detail-heading">
        <div>
          <h3>{communication.communicated_at}</h3>
        </div>
        <strong>{communication.anomaly_count || 0}개</strong>
      </div>
      {(communication.detections || []).length ? (
        <div className="communication-code-list">
          {communication.detections.map((detection, index) => (
            <button
              type="button"
              key={detection.detect_id}
              className={`communication-code severity-${detection.severity}`}
              onClick={() => onSelect(detection.detect_id)}
            >
              <span>{index + 1}번째 발생</span>
              <strong>{detection.ma_code}</strong>
              <em>Phase {detection.phase} · 신뢰도 {detection.confidence}%</em>
            </button>
          ))}
        </div>
      ) : (
        <p className="muted">해당 통신은 정상입니다.</p>
      )}
    </div>
  );
}

function DetailPanel({ selectedDetail, snapshotIndex, onSnapshotPrev, onSnapshotNext }) {
  if (!selectedDetail) {
    return <div className="detail-card muted">코드를 선택하면 Rule 근거가 표시됩니다.</div>;
  }

  const frame = selectedDetail.snapshot_frame;
  const frameLabel =
    frame && frame.total > 0
      ? `스냅샷 ${(snapshotIndex ?? frame.index) + 1} / ${frame.total} (10분·1초 시리즈)`
      : null;

  return (
    <div className="detail-card">
      <div className="detail-heading">
        <div>
          <p className="eyebrow">선택 코드 상세</p>
          <h3>{selectedDetail.ma_code}</h3>
        </div>
        <strong>{selectedDetail.confidence_score}%</strong>
      </div>
      <div className="filter-grid">
        <span>위성체 판정: {selectedDetail.satellite_filter?.result || "-"}</span>
        <span>가중치: {selectedDetail.satellite_filter?.weight || "-"}</span>
        <span>대상: {selectedDetail.satellite_filter?.target_subsystem || "-"}</span>
        <span>이벤트: {selectedDetail.satellite_filter?.event_id || "-"}</span>
      </div>
      {frameLabel ? (
        <div className="snapshot-nav">
          <button type="button" onClick={onSnapshotPrev} disabled={!frame || frame.index <= 0}>
            이전 1초
          </button>
          <p className="muted">{frameLabel}</p>
          <button
            type="button"
            onClick={onSnapshotNext}
            disabled={!frame || frame.index >= frame.total - 1}
          >
            다음 1초
          </button>
        </div>
      ) : null}
      {frame?.current_at ? (
        <p className="muted">
          직전 스냅샷: {frame.previous_at || "(없음)"} → 현재: {frame.current_at}
        </p>
      ) : null}

      <div className="rule-detail-list">
        {(selectedDetail.rule_details || []).map((rule) => (
          <article key={rule.rule_id} className="rule-detail">
            <div>
              <strong>{rule.rule_id} · {rule.name}</strong>
              <span>최초 활성화: {rule.first_triggered_at}</span>
            </div>
            {getVisibleRuleColumns(rule.columns).length ? (
              <div className="column-grid">
                {getVisibleRuleColumns(rule.columns).map(([column, value]) => (
                  <div key={column} className="column-card">
                    <b>{column}</b>
                    <span>관측: {String(value.observed)}</span>
                    <span>직전 스냅샷: {String(value.previous_observed ?? "-")}</span>
                    <span>비교 기준: {String(value.normal)}</span>
                    <em>직전 1초 대비 변화율: {formatStepMetricLabel(value.abnormal_percent)}</em>
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
  onRuleSelect,
  onReload,
  onReplay
}) {
  return (
    <section className="panel rule-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Rule Lab</p>
          <h2>Rule / Threshold 수정 및 Replay</h2>
        </div>
        <div className="rule-actions">
          <button onClick={onReload}>새로고침</button>
          <button onClick={onReplay}>Replay</button>
        </div>
      </div>

      <div className="rule-grid">
        <div>
          <h3>현재 Rule</h3>
          <div className="rule-list">
            {rules ? (
              Object.entries(rules.rules).map(([ruleId, rule]) => (
                <button
                  key={ruleId}
                  className={`rule-list-item ${selectedRuleId === ruleId ? "active" : ""}`}
                  onClick={() => onRuleSelect(ruleId)}
                >
                  <strong>{ruleId} · {rule.name}</strong>
                  <span>{rule.enabled ? "활성" : "비활성"} · {rule.subsystems.join(", ")}</span>
                </button>
              ))
            ) : (
              <p className="muted">Rule을 불러오는 중입니다.</p>
            )}
          </div>
        </div>
        <div>
          <h3>Rule JSON</h3>
          <textarea value={ruleEditor} readOnly />
        </div>
        <div>
          <h3>Threshold JSON</h3>
          <textarea value={ruleDraft} readOnly />
        </div>
      </div>
    </section>
  );
}

function ReplayWorkspace({
  dashboard,
  comparison,
  replayRules,
  replayThresholdDraft,
  replayRuleId,
  replayNewRuleId,
  replayRuleEditor,
  replayBusy,
  replayUpdatedAt,
  replayDirty,
  onRuleSelect,
  onNewRuleIdChange,
  onRuleEditorChange,
  onThresholdDraftChange,
  onStartNewRule,
  onSaveRule,
  onDeleteRule,
  onSaveThresholds,
  onReplay
}) {
  if (!dashboard) {
    return <section className="panel">replay 결과를 생성하는 중입니다. "퍼센트 안 알려주면 언제까지 기다려 라고 생각할 듯"</section>;
  }

  return (
    <section className="replay-layout">
      <section className="panel rule-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Temporary Rule Edit</p>
            <h2>Replay</h2>
          </div>
          <div className="rule-actions /* 초기화 버튼 필요함 + 추가/삭제 진행 시 자동 Replay 실행 삭제 + 저장 버튼 삭제 + 실행 시 자동 저장*/">
            <button onClick={onStartNewRule}>Rule 추가</button>
            <button onClick={onSaveRule}>Rule 저장</button>
            <button onClick={onDeleteRule}>Rule 삭제</button>
            <button onClick={onSaveThresholds}>Threshold 저장</button>
            <button onClick={onReplay} disabled={replayBusy}>
              {replayBusy ? "Replay 실행 중..." : "Replay 실행"}
            </button>
          </div>
        </div>
        <div className="rule-grid">
          <div>
            <h3>Rule</h3>
            <div className="rule-list">
              {Object.entries(replayRules || {}).map(([ruleId, rule]) => (
                <button
                  key={ruleId}
                  className={`rule-list-item ${replayRuleId === ruleId ? "active" : ""}`}
                  onClick={() => onRuleSelect(ruleId)}
                >
                  <strong>{ruleId} · {rule.name}</strong>
                  <span>{rule.enabled ? "활성" : "비활성"} · {(rule.subsystems || []).join(", ")}</span>
                </button>
              ))}
            </div>
          </div>
          <div>
            <h3>Rule JSON</h3>
            <label className="threshold-inline">
              <input
              className="rule-id-input"
              placeholder="새 Rule ID"
              value={replayNewRuleId}
              onChange={(event) => onNewRuleIdChange(event.target.value)}
            />
              <span>활성화 임계값(score_threshold)</span>
              <input
                type="number"
                step="0.05"
                value={readRuleThreshold(replayRuleEditor)}
                onChange={(event) => onRuleEditorChange(updateRuleThreshold(replayRuleEditor, event.target.value))}
              />
            </label>
            <textarea value={replayRuleEditor} onChange={(event) => onRuleEditorChange(event.target.value)} />
          </div>
          <div>
            <h3>Threshold JSON</h3>
            <textarea value={replayThresholdDraft} onChange={(event) => onThresholdDraftChange(event.target.value)} />
          </div>
        </div>
      </section>
      <ReplayComparison
        comparison={comparison}
        replayBusy={replayBusy}
        replayDirty={replayDirty}
        replayUpdatedAt={replayUpdatedAt}
      />
    </section>
  );
}

function ReplayComparison({ comparison, replayBusy, replayDirty, replayUpdatedAt }) {
  if (!comparison) {
    return (
      <section className="panel replay-comparison empty">
        <div className={`replay-status ${replayBusy ? "busy" : ""}`}>
          {replayBusy
            ? "Replay 실행 중..."
            : replayDirty
              ? "변경사항이 있습니다. Replay 실행을 눌러 비교 결과를 생성하세요."
              : "Rule/Threshold를 수정한 뒤 Replay 실행"}
        </div>
      </section>
    );
  }

  return (
    <section className="panel replay-comparison">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">Replay Diff</p>
          <h2>기존 탐지 결과 vs 임시 기준 결과</h2>
        </div>
        <div className={`replay-status ${replayBusy ? "busy" : ""}`}>
          {replayBusy ? "Replay 실행 중..." : `반영 ${replayUpdatedAt || ""}`}
        </div>
      </div>

      <div className="comparison-summary">
        <span>기존 {comparison.current_count}개</span>
        <span>Replay {comparison.preview_count}개</span>
        <span>{comparison.delta_count >= 0 ? "+" : ""}{comparison.delta_count}개</span>
      </div>

      <div className="comparison-grid">
        <ComparisonColumn title="추가됨 +" items={comparison.added} kind="added" />
        <ComparisonColumn title="삭제됨 -" items={comparison.removed} kind="removed" />
        <ChangedColumn items={comparison.changed} />
      </div>
    </section>
  );
}

function ComparisonColumn({ title, items, kind }) {
  return (
    <div className="comparison-column">
      <h3>{title}</h3>
      {items?.length ? (
        items.map((item) => (
          <article key={`${kind}-${item.ma_code}`} className={`comparison-card ${kind}`}>
            <strong>{item.ma_code}</strong>
            <span>Phase {item.phase} · {item.confidence}% · {item.grade}</span>
            <em>{item.detect_time}</em>
          </article>
        ))
      ) : (
        <p className="muted">변화 없음</p>
      )}
    </div>
  );
}

function ChangedColumn({ items }) {
  return (
    <div className="comparison-column">
      <h3>변경됨 ±</h3>
      {items?.length ? (
        items.map((item) => (
          <article key={`changed-${item.ma_code}`} className="comparison-card changed">
            <strong>{item.ma_code}</strong>
            <span>
              {item.current.confidence}% → {item.preview.confidence}%
              {" "}({item.confidence_delta >= 0 ? "+" : ""}{item.confidence_delta})
            </span>
            <em>Phase {item.current.phase} → {item.preview.phase}</em>
          </article>
        ))
      ) : (
        <p className="muted">변화 없음</p>
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

