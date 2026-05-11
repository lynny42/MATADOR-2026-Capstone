"use client";

import { useEffect, useMemo, useState } from "react";
import { apiGet, apiSend } from "../lib/api";

const severityLabel = {
  normal: "정상",
  watch: "관찰",
  warning: "주의",
  critical: "위험"
};

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
  const [error, setError] = useState("");

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
      }
      setError("");
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  async function loadDetail(detectId) {
    try {
      const detail = await apiGet(`/api/detections/${detectId}`);
      setSelectedDetail(detail);
      setSelectedId(detectId);
      if (detail.detect_time) {
        setSelectedCommunicationAt(detail.detect_time);
      }
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  function selectCommunication(communicatedAt) {
    setSelectedCommunicationAt(communicatedAt);
    setSelectedId(null);
    setSelectedDetail(null);
  }

  function clearSelectedCode() {
    setSelectedId(null);
    setSelectedDetail(null);
  }

  function resetToLatestCommunication() {
    const latestAt = dashboard?.latest_communication?.communicated_at || "";
    setSelectedCommunicationAt(latestAt);
    setSelectedId(null);
    setSelectedDetail(null);
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
      setReplayNewRuleId("");
      setReplayRuleEditor(JSON.stringify(rulesCopy[firstRule] || defaultRuleDefinition(), null, 2));
      setReplayThresholdDraft(JSON.stringify(thresholdCopy, null, 2));
      setRulesOpen(false);
      setReplayMode(true);
      await runReplayPreview(rulesCopy, thresholdCopy);
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
      await runReplayPreview(nextRules, replayThresholds);
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
      await runReplayPreview(nextRules, replayThresholds);
    } catch (deleteError) {
      setError(deleteError.message);
    }
  }

  async function saveReplayThresholds() {
    try {
      const nextThresholds = JSON.parse(replayThresholdDraft);
      setReplayThresholds(nextThresholds);
      await runReplayPreview(replayRules, nextThresholds);
    } catch (saveError) {
      setError(saveError.message);
    }
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
          replayRules={replayRules}
          replayThresholdDraft={replayThresholdDraft}
          replayRuleId={replayRuleId}
          replayNewRuleId={replayNewRuleId}
          replayRuleEditor={replayRuleEditor}
          replayBusy={replayBusy}
          replayUpdatedAt={replayUpdatedAt}
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

      <div className="recent-threats">
        <div className="recent-threat-heading">
          <h3>최근 위협 탐지</h3>
          <span>
            {latestCommunication?.communicated_at || "통신 없음"} : {latestCommunication?.anomaly_count || 0}개
          </span>
        </div>
        {recentThreats.length ? (
          <div className="recent-threat-track" aria-label="최근 위협 탐지 코드 슬라이더">
            {recentThreats.map((detection) => (
              <button
                key={detection.detect_id}
                className="threat-row"
                onClick={() => onSelect(detection.detect_id)}
              >
                <span>{detection.detect_time}</span>
                <strong>{detection.ma_code}</strong>
                <em>{detection.confidence}% / P{detection.phase}</em>
              </button>
            ))}
          </div>
        ) : (
          <p className="muted">최근 5회 통신 내 위협 탐지가 없습니다.</p>
        )}
      </div>
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
    <section className="panel right-panel">
      <div className="selector-row">
        <label className="search-box communication-select">
          <span>통신</span>
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
        <DetailPanel selectedDetail={selectedDetail} />
      ) : (
        <CommunicationSummary communication={selectedCommunication} />
      )}
    </section>
  );
}

function CommunicationSummary({ communication }) {
  if (!communication) {
    return <div className="detail-card muted">통신 기록이 없습니다.</div>;
  }

  return (
    <div className="detail-card">
      <div className="detail-heading">
        <div>
          <p className="eyebrow">통신 단위 요약</p>
          <h3>{communication.communicated_at}</h3>
        </div>
        <strong>{communication.anomaly_count || 0}개</strong>
      </div>
      {(communication.detections || []).length ? (
        <div className="communication-code-list">
          {communication.detections.map((detection, index) => (
            <article key={detection.detect_id} className={`communication-code severity-${detection.severity}`}>
              <span>{index + 1}번째 발생</span>
              <strong>{detection.ma_code}</strong>
              <em>Phase {detection.phase} · 신뢰도 {detection.confidence}%</em>
            </article>
          ))}
        </div>
      ) : (
        <p className="muted">해당 통신은 정상입니다.</p>
      )}
    </div>
  );
}

function DetailPanel({ selectedDetail }) {
  if (!selectedDetail) {
    return <div className="detail-card muted">코드를 선택하면 Rule 근거가 표시됩니다.</div>;
  }

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

      <div className="rule-detail-list">
        {(selectedDetail.rule_details || []).map((rule) => (
          <article key={rule.rule_id} className="rule-detail">
            <div>
              <strong>{rule.rule_id} · {rule.name}</strong>
              <span>최초 활성화: {rule.first_triggered_at}</span>
            </div>
            <div className="column-grid">
              {Object.entries(rule.columns || {}).map(([column, value]) => (
                <div key={column} className="column-card">
                  <b>{column}</b>
                  <span>관측: {String(value.observed)}</span>
                  <span>정상: {String(value.normal)}</span>
                  <em>이상률: {value.abnormal_percent ?? "Flag"}%</em>
                </div>
              ))}
            </div>
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
          <h3>Rule JSON 읽기 전용</h3>
          <textarea value={ruleEditor} readOnly />
          <p className="muted">수정은 Replay 실행 후 임시 편집 화면에서만 가능합니다.</p>
        </div>
        <div>
          <h3>Threshold JSON 읽기 전용</h3>
          <textarea value={ruleDraft} readOnly />
          <p className="muted">Replay에서 임시 threshold를 저장해 결과를 확인할 수 있습니다.</p>
        </div>
        <div>
          <h3>Replay 안내</h3>
          <pre>Replay 실행을 누르면 임시 Rule/Threshold 편집 화면으로 이동합니다.</pre>
        </div>
      </div>
    </section>
  );
}

function ReplayWorkspace({
  dashboard,
  replayRules,
  replayThresholdDraft,
  replayRuleId,
  replayNewRuleId,
  replayRuleEditor,
  replayBusy,
  replayUpdatedAt,
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
  const [previewCommunicationAt, setPreviewCommunicationAt] = useState("");
  const selectedCommunication = useMemo(() => {
    const targetAt = previewCommunicationAt || dashboard?.latest_communication?.communicated_at;
    return dashboard?.communications?.find((communication) => communication.communicated_at === targetAt)
      || dashboard?.latest_communication;
  }, [dashboard, previewCommunicationAt]);

  if (!dashboard) {
    return <section className="panel">임시 replay 결과를 생성하는 중입니다.</section>;
  }

  return (
    <section className="replay-layout">
      <section className="panel rule-panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">Temporary Rule Edit</p>
            <h2>임시 Rule / Threshold 편집</h2>
          </div>
          <div className="rule-actions">
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
            <h3>임시 Rule</h3>
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
            <h3>임시 Rule JSON</h3>
            <label className="threshold-inline">
              <span>활성화 임계값(score_threshold)</span>
              <input
                type="number"
                step="0.05"
                value={readRuleThreshold(replayRuleEditor)}
                onChange={(event) => onRuleEditorChange(updateRuleThreshold(replayRuleEditor, event.target.value))}
              />
            </label>
            <input
              className="rule-id-input"
              placeholder="새 Rule ID"
              value={replayNewRuleId}
              onChange={(event) => onNewRuleIdChange(event.target.value)}
            />
            <textarea value={replayRuleEditor} onChange={(event) => onRuleEditorChange(event.target.value)} />
          </div>
          <div>
            <h3>임시 Threshold JSON</h3>
            <textarea value={replayThresholdDraft} onChange={(event) => onThresholdDraftChange(event.target.value)} />
          </div>
          <div>
            <h3>임시 결과 안내</h3>
            <div className={`replay-status ${replayBusy ? "busy" : ""}`}>
              {replayBusy ? "Replay 생성 중..." : `임시 대시보드 반영됨 ${replayUpdatedAt || ""}`}
            </div>
            <p className="muted">아래 대시보드는 저장된 원시 수신 history 전체를 임시 Rule/Threshold로 다시 판단한 결과입니다.</p>
          </div>
        </div>
      </section>
      <section className="dashboard-grid">
        <BlueprintPanel
          blueprint={dashboard.blueprint}
          recentThreats={dashboard.recent_threats}
          latestCommunication={dashboard.latest_communication}
          onSelect={() => {}}
        />
        <section className="panel right-panel">
          <div className="selector-row">
            <label className="search-box communication-select">
              <span>통신</span>
              <select
                value={previewCommunicationAt || dashboard.latest_communication?.communicated_at || ""}
                onChange={(event) => setPreviewCommunicationAt(event.target.value)}
              >
                {(dashboard.communications || []).map((communication) => (
                  <option key={communication.communicated_at} value={communication.communicated_at}>
                    {communication.communicated_at} · {communication.anomaly_count}개
                  </option>
                ))}
              </select>
            </label>
          </div>
          <CommunicationSummary communication={selectedCommunication} />
        </section>
      </section>
    </section>
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

