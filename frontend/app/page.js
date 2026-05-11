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
  const [selectedId, setSelectedId] = useState(null);
  const [selectedDetail, setSelectedDetail] = useState(null);
  const [rulesOpen, setRulesOpen] = useState(false);
  const [rules, setRules] = useState(null);
  const [ruleDraft, setRuleDraft] = useState("");
  const [replayResult, setReplayResult] = useState(null);
  const [error, setError] = useState("");

  async function loadDashboard(nextSelectedId = selectedId) {
    try {
      const payload = await apiGet("/api/dashboard");
      setDashboard(payload);
      const fallbackId = payload.selected_detection?.detect_id || null;
      const targetId = nextSelectedId || fallbackId;
      setSelectedId(targetId);
      if (targetId) {
        await loadDetail(targetId);
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
    } catch (loadError) {
      setError(loadError.message);
    }
  }

  async function loadRules() {
    try {
      const payload = await apiGet("/api/rules");
      setRules(payload);
      setRuleDraft(JSON.stringify(payload.thresholds, null, 2));
    } catch (loadError) {
      setError(loadError.message);
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
    loadDashboard(null);
    const timer = setInterval(() => loadDashboard(selectedId), 5000);
    return () => clearInterval(timer);
  }, [selectedId]);

  const selectedLabel = useMemo(() => {
    if (selectedDetail?.ma_code) {
      return selectedDetail.ma_code;
    }
    return dashboard?.latest_communication?.communicated_at || "최근 통신 없음";
  }, [dashboard, selectedDetail]);

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
          replayResult={replayResult}
          onDraftChange={setRuleDraft}
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
          selectedLabel={selectedLabel}
          selectedId={selectedId}
          selectedDetail={selectedDetail}
          onSelect={loadDetail}
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
          recentThreats.map((detection) => (
            <button
              key={detection.detect_id}
              className="threat-row"
              onClick={() => onSelect(detection.detect_id)}
            >
              <span>{detection.detect_time}</span>
              <strong>{detection.ma_code}</strong>
              <em>{detection.confidence}% / P{detection.phase}</em>
            </button>
          ))
        ) : (
          <p className="muted">최근 5회 통신 내 위협 탐지가 없습니다.</p>
        )}
      </div>
    </section>
  );
}

function RightPanel({ dashboard, selectedLabel, selectedId, selectedDetail, onSelect }) {
  const latest = dashboard.latest_communication;
  return (
    <section className="panel right-panel">
      <div className="selector-row">
        <label className="search-box">
          <span aria-hidden="true">🔍</span>
          <select
            value={selectedId || ""}
            onChange={(event) => onSelect(event.target.value)}
          >
            {dashboard.detections.map((detection) => (
              <option key={detection.detect_id} value={detection.detect_id}>
                {detection.ma_code}
              </option>
            ))}
          </select>
        </label>
        <div className="selected-code">
          <span>선택 코드</span>
          <strong>{selectedLabel}</strong>
        </div>
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

      <div className="timeline">
        <h3>이상 코드 타임라인</h3>
        {dashboard.detections.length ? (
          dashboard.detections.map((detection) => (
            <button
              key={detection.detect_id}
              className={`timeline-item severity-${detection.severity}`}
              onClick={() => onSelect(detection.detect_id)}
            >
              <span>{detection.detect_time}</span>
              <strong>{detection.ma_code}</strong>
              <em>신뢰도 {detection.confidence}% · Phase {detection.phase}</em>
            </button>
          ))
        ) : (
          <p className="muted">이상 코드가 없습니다.</p>
        )}
      </div>

      <DetailPanel selectedDetail={selectedDetail} />
    </section>
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
  replayResult,
  onDraftChange,
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
                <article key={ruleId}>
                  <strong>{ruleId} · {rule.name}</strong>
                  <span>{rule.enabled ? "활성" : "비활성"} · {rule.subsystems.join(", ")}</span>
                </article>
              ))
            ) : (
              <p className="muted">Rule을 불러오는 중입니다.</p>
            )}
          </div>
        </div>
        <div>
          <h3>Threshold JSON</h3>
          <textarea value={ruleDraft} onChange={(event) => onDraftChange(event.target.value)} />
          <p className="muted">
            현재 UI는 빠른 임계치 수정과 replay 실행을 제공합니다. 세부 Rule CRUD는 API로 연결되어 있습니다.
          </p>
        </div>
        <div>
          <h3>Replay 결과</h3>
          <pre>{replayResult ? JSON.stringify(replayResult, null, 2) : "Replay 결과 없음"}</pre>
        </div>
      </div>
    </section>
  );
}
