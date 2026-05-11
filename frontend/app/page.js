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
  const [newRuleId, setNewRuleId] = useState("");
  const [ruleEditor, setRuleEditor] = useState("");
  const [replayResult, setReplayResult] = useState(null);
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
    setNewRuleId("");
    setRuleEditor(JSON.stringify(rules?.rules?.[ruleId] || defaultRuleDefinition(), null, 2));
  }

  function startNewRule() {
    setSelectedRuleId("");
    setNewRuleId("E-NEW");
    setRuleEditor(JSON.stringify(defaultRuleDefinition(), null, 2));
  }

  async function saveRule() {
    try {
      const ruleId = (newRuleId || selectedRuleId).trim();
      if (!ruleId) {
        setError("저장할 Rule ID가 필요합니다.");
        return;
      }
      const definition = JSON.parse(ruleEditor);
      await apiSend("/api/rules", "POST", { rule_id: ruleId, definition });
      setSelectedRuleId(ruleId);
      setNewRuleId("");
      await loadRules(ruleId);
      await runReplay();
      setError("");
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  async function deleteRule() {
    try {
      if (!selectedRuleId) {
        setError("삭제할 Rule을 선택하세요.");
        return;
      }
      await apiSend(`/api/rules/${selectedRuleId}`, "DELETE", {});
      setSelectedRuleId("");
      setNewRuleId("");
      setRuleEditor(JSON.stringify(defaultRuleDefinition(), null, 2));
      await loadRules();
      await runReplay();
      setError("");
    } catch (deleteError) {
      setError(deleteError.message);
    }
  }

  async function saveThresholds() {
    try {
      const parsed = JSON.parse(ruleDraft);
      const updates = flattenThresholds(parsed);
      for (const update of updates) {
        await apiSend("/api/thresholds", "PATCH", update);
      }
      await loadRules();
      await runReplay();
      setError("");
    } catch (saveError) {
      setError(saveError.message);
    }
  }

  async function runReplay() {
    try {
      const payload = await apiSend("/api/replay", "POST", {});
      setReplayResult(payload);
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  async function updateHardThreshold() {
    try {
      await apiSend("/api/thresholds", "PATCH", {
        category: "z_score",
        key: "HARD",
        value: 2.8
      });
      await loadRules();
      await runReplay();
    } catch (loadError) {
      setError(loadError.message);
    }
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
          Rule
        </button>
      </header>

      {error ? <section className="error-banner">{error}</section> : null}

      {rulesOpen ? (
        <RulePanel
          rules={rules}
          ruleDraft={ruleDraft}
          selectedRuleId={selectedRuleId}
          newRuleId={newRuleId}
          ruleEditor={ruleEditor}
          replayResult={replayResult}
          onDraftChange={setRuleDraft}
          onRuleSelect={selectRule}
          onNewRuleIdChange={setNewRuleId}
          onRuleEditorChange={setRuleEditor}
          onStartNewRule={startNewRule}
          onSaveRule={saveRule}
          onDeleteRule={deleteRule}
          onSaveThresholds={saveThresholds}
          onReload={loadRules}
          onReplay={runReplay}
          onQuickThreshold={updateHardThreshold}
        />
      ) : null}

      <section className="dashboard-grid">
        <BlueprintPanel
          blueprint={dashboard.blueprint}
          recentThreats={dashboard.recent_threats}
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

function BlueprintPanel({ blueprint, recentThreats, onSelect }) {
  return (
    <section className="panel blueprint-panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">최근 5회 통신 기반</p>
          <h2>위성체 Blueprint</h2>
        </div>
        <span className="refresh-pill">자동 새로고침 5초</span>
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
        <h3>최근 위협 탐지</h3>
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

      <div className={`latest-card ${latest.status === "NORMAL" ? "normal" : "anomaly"}`}>
        <p className="eyebrow">가장 최근 통신 결과</p>
        <h2>{latest.communicated_at || "통신 기록 없음"}</h2>
        <p>
          {latest.status === "NORMAL"
            ? "정상 통신입니다."
            : `${latest.anomaly_count}개의 이상 코드가 감지되었습니다.`}
        </p>
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
  newRuleId,
  ruleEditor,
  replayResult,
  onDraftChange,
  onRuleSelect,
  onNewRuleIdChange,
  onRuleEditorChange,
  onStartNewRule,
  onSaveRule,
  onDeleteRule,
  onSaveThresholds,
  onReload,
  onReplay,
  onQuickThreshold
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
          <button onClick={onStartNewRule}>Rule 추가</button>
          <button onClick={onSaveRule}>Rule 저장</button>
          <button onClick={onDeleteRule}>Rule 삭제</button>
          <button onClick={onSaveThresholds}>Threshold 저장</button>
          <button onClick={onQuickThreshold}>HARD 임계치 2.8 적용</button>
          <button onClick={onReplay}>Replay 실행</button>
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
          <input
            className="rule-id-input"
            placeholder="새 Rule ID"
            value={newRuleId}
            onChange={(event) => onNewRuleIdChange(event.target.value)}
          />
          <textarea value={ruleEditor} onChange={(event) => onRuleEditorChange(event.target.value)} />
          <p className="muted">
            Rule을 선택하거나 새 Rule ID를 입력한 뒤 JSON을 수정하고 저장/삭제할 수 있습니다.
          </p>
        </div>
        <div>
          <h3>Threshold JSON</h3>
          <textarea value={ruleDraft} onChange={(event) => onDraftChange(event.target.value)} />
          <p className="muted">수정 후 Threshold 저장을 누르면 replay로 결과를 확인합니다.</p>
        </div>
        <div>
          <h3>Replay 결과</h3>
          <pre>{replayResult ? JSON.stringify(replayResult, null, 2) : "Replay 결과 없음"}</pre>
        </div>
      </div>
    </section>
  );
}

function defaultRuleDefinition() {
  return {
    name: "새 Rule",
    subsystems: ["OBC"],
    columns: [],
    contributes_to: {},
    single_sufficient: false,
    enabled: true
  };
}

function flattenThresholds(thresholds) {
  return Object.entries(thresholds).flatMap(([category, values]) => {
    if (!values || typeof values !== "object" || Array.isArray(values)) {
      return [];
    }
    return Object.entries(values)
      .filter(([, value]) => typeof value === "number")
      .map(([key, value]) => ({ category, key, value }));
  });
}
