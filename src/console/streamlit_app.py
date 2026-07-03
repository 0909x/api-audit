import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import streamlit as st
import pandas as pd
from datetime import datetime
from src.engine.alert import ALERT_TYPE_LABELS, SEVERITY_MAP

st.set_page_config(page_title="API安全审计控制台", layout="wide")

SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "info": "#17a2b8",
}

STATUS_LABELS = {
    "preliminary": ("待确认", "#ffc107"),
    "confirmed": ("已确认", "#28a745"),
    "dismissed": ("已忽略", "#6c757d"),
}


def get_store():
    from src.engine.alert_store import AlertStore
    if "alert_store" not in st.session_state:
        st.session_state.alert_store = AlertStore()

    if "demo_alerts" not in st.session_state:
        _add_demo_alerts(st.session_state.alert_store)
        st.session_state.demo_alerts = True

    return st.session_state.alert_store


def _add_demo_alerts(store):
    from src.engine.alert import Alert, AlertExplanation, RawFeatures
    now = datetime.now().strftime("%Y-%m-%dT%H:%M:%S+08:00")
    alerts = [
        Alert(
            alert_id="ALT-20250703-001",
            timestamp=now,
            severity="high",
            anomaly_type="traversal",
            confidence=0.94,
            session_id="sess_a1b2c3d4",
            source_ip="10.0.1.15",
            affected_endpoints=["GET /api/v1/users/{id}"],
            explanation=AlertExplanation(
                summary="检测到用户'zhangsan'在12秒内对'/api/v1/users/{id}'端点发起了28次请求，参数'id'从10001连续递增至10028，符合参数遍历攻击的典型模式。",
                chain_of_thought="分析该会话的调用序列：第一步，检查调用频率，28次/12秒，正常用户均值2次/分钟，频率异常偏高。第二步，检查参数分布，参数'id'从10001到10028严格线性递增，Shannon熵为6.98（接近理论最大值7.0），呈典型的枚举分布。第三步，检查响应码，404占比46%，表明大量请求命中了不存在的资源ID。综合以上三个维度，判定为参数遍历攻击。",
                key_indicators=[
                    "请求频率异常：28次/12秒，远超正常用户行为（均值2次/分钟）",
                    "参数分布均匀：参数'id'呈严格线性递增，Shannon熵为6.98（接近理论最大值7.0）",
                    "响应码异常：404占比46%，表明大量请求命中了不存在的资源ID",
                ],
                risk_assessment="攻击者可能正在批量枚举用户ID，试图获取未授权的用户信息。该行为可能导致用户隐私数据泄露。",
                recommendation="建议立即对该IP实施速率限制，并检查'/api/v1/users/{id}'端点是否缺少基于用户身份的授权校验。",
            ),
            raw_features=RawFeatures(
                request_count=28,
                time_window_sec=12.0,
                param_entropy=6.98,
                not_found_ratio=0.46,
                param_pattern="sequential_increment",
            ),
        ),
        Alert(
            alert_id="ALT-20250703-002",
            timestamp=now,
            severity="critical",
            anomaly_type="bola",
            confidence=0.88,
            session_id="sess_e5f6g7h8",
            source_ip="10.0.1.20",
            affected_endpoints=["POST /api/v1/login", "GET /api/v1/users/orders/12345"],
            explanation=AlertExplanation(
                summary="检测到用户B使用自身Token访问了用户A的订单ID(12345)，服务端返回200，存在BOLA越权漏洞。",
                chain_of_thought="第一步，用户A登录后获取了订单ID 12345。第二步，用户A登出。第三步，用户B登录。第四步，用户B使用自身Token访问了订单ID 12345。第五步，服务端返回200而非403，说明未对资源所属做校验。判定为BOLA越权。",
                key_indicators=[
                    "用户A获取资源ID后，用户B使用自身Token访问同一ID",
                    "服务端返回200而非403，确认越权",
                    "跨用户身份切换后访问相同资源",
                ],
                risk_assessment="BOLA是OWASP API Top 10排名第一的风险，攻击者可越权访问任意用户的订单信息，导致大规模数据泄露。",
                recommendation="建议立即检查该端点是否在参数级别实施了基于用户身份的授权校验。可参考OWASP API Security Top 10 #1（BOLA）进行修复。",
            ),
            raw_features=RawFeatures(
                request_count=5,
                time_window_sec=30.0,
                param_entropy=0.0,
                not_found_ratio=0.0,
                param_pattern="",
            ),
        ),
        Alert(
            alert_id="ALT-20250703-003",
            timestamp=now,
            severity="medium",
            anomaly_type="abuse",
            confidence=0.72,
            session_id="sess_i9j0k1l2",
            source_ip="10.0.1.99",
            affected_endpoints=["GET /api/v1/export/all"],
            explanation=AlertExplanation(
                summary="检测到IP 10.0.1.99在5秒内对批量导出接口发起了50次请求，频率为正常行为的25倍。",
                chain_of_thought="该会话在5秒内对同一批量导出接口连续调用50次，平均间隔0.1秒。正常用户行为平均间隔约2.5秒。频率超出正常均值25倍，判定为接口滥用。",
                key_indicators=[
                    "调用频率极高：50次/5秒，均值0.1秒间隔",
                    "单一接口集中调用，无其他业务操作",
                    "频率为正常用户的25倍",
                ],
                risk_assessment="异常高频的接口调用可能导致后端服务过载，同时也可能是大规模数据爬取行为。",
                recommendation="建议对该IP实施临时封禁，并检查批量导出接口是否存在未做限流控制的缺陷。",
            ),
            raw_features=RawFeatures(
                request_count=50,
                time_window_sec=5.0,
                param_entropy=0.0,
                not_found_ratio=0.0,
                param_pattern="",
            ),
        ),
    ]
    for a in alerts:
        store.add(a)


def main():
    store = get_store()

    st.title("API安全审计控制台")

    col1, col2, col3, col4, col5 = st.columns(5)
    stats = store.count()
    with col1:
        st.metric("总告警数", stats["total"])
    with col2:
        sev = stats.get("by_severity", {})
        st.metric("严重告警", sev.get("critical", 0))
    with col3:
        st.metric("高危告警", sev.get("high", 0))
    with col4:
        st.metric("中危告警", sev.get("medium", 0))
    with col5:
        by_status = stats.get("by_status", {})
        st.metric("待确认", by_status.get("preliminary", 0))

    tab1, tab2 = st.tabs(["告警列表", "告警统计"])

    with tab1:
        severity_filter = st.selectbox(
            "筛选严重级别",
            ["全部", "critical", "high", "medium", "info"],
            index=0,
        )

        all_alerts = store.get_all(limit=200)
        if severity_filter != "全部":
            all_alerts = [a for a in all_alerts if a.severity == severity_filter]

        if not all_alerts:
            st.info("暂无告警")
        else:
            for alert in all_alerts:
                with st.container(border=True):
                    sev_color = SEVERITY_COLORS.get(alert.severity, "#6c757d")
                    cols = st.columns([1, 2, 2, 1, 4])
                    with cols[0]:
                        st.markdown(
                            f"<span style='color:{sev_color};font-weight:bold'>{alert.severity.upper()}</span>",
                            unsafe_allow_html=True,
                        )
                    with cols[1]:
                        st.markdown(f"**{alert.alert_id}**")
                    with cols[2]:
                        label = ALERT_TYPE_LABELS.get(alert.anomaly_type, alert.anomaly_type)
                        st.markdown(f"{label}")
                    with cols[3]:
                        status_label, status_color = STATUS_LABELS.get(alert.status, ("未知", "#6c757d"))
                        st.markdown(
                            f"<span style='color:{status_color};font-weight:bold'>[{status_label}]</span>",
                            unsafe_allow_html=True,
                        )
                    with cols[4]:
                        st.markdown(alert.explanation.summary[:80] + "...")

                    with st.expander("查看详情"):
                        st.subheader("基本信息")
                        detail_cols = st.columns(3)
                        with detail_cols[0]:
                            st.markdown(f"**告警ID**: {alert.alert_id}")
                            st.markdown(f"**时间**: {alert.timestamp}")
                            status_label, _ = STATUS_LABELS.get(alert.status, ("未知", "#6c757d"))
                            st.markdown(f"**状态**: {status_label}")
                            st.markdown(f"**严重级别**: {alert.severity}")
                        with detail_cols[1]:
                            st.markdown(f"**告警类型**: {ALERT_TYPE_LABELS.get(alert.anomaly_type, alert.anomaly_type)}")
                            st.markdown(f"**置信度**: {alert.confidence:.0%}")
                            st.markdown(f"**会话ID**: {alert.session_id[:24]}")
                        with detail_cols[2]:
                            st.markdown(f"**源IP**: {alert.source_ip}")
                            st.markdown(f"**影响端点**: {', '.join(alert.affected_endpoints)}")

                        st.subheader("解释详情")
                        st.markdown(f"**摘要**: {alert.explanation.summary}")
                        if alert.explanation.chain_of_thought:
                            st.markdown(f"**推理过程**: {alert.explanation.chain_of_thought}")
                        if alert.explanation.key_indicators:
                            st.markdown("**关键指标**:")
                            for ind in alert.explanation.key_indicators:
                                st.markdown(f"- {ind}")
                        st.markdown(f"**风险评估**: {alert.explanation.risk_assessment}")
                        st.markdown(f"**处置建议**: {alert.explanation.recommendation}")

                        st.subheader("原始特征")
                        rf = alert.raw_features
                        feat_cols = st.columns(4)
                        with feat_cols[0]:
                            st.metric("请求数", rf.request_count)
                        with feat_cols[1]:
                            st.metric("时间窗口", f"{rf.time_window_sec:.1f}s")
                        with feat_cols[2]:
                            st.metric("参数熵值", rf.param_entropy)
                        with feat_cols[3]:
                            st.metric("404占比", f"{rf.not_found_ratio:.0%}")

    with tab2:
        st.subheader("告警类型分布")
        by_type = stats.get("by_type", {})
        if by_type:
            type_df = pd.DataFrame([
                {"类型": ALERT_TYPE_LABELS.get(k, k), "数量": v}
                for k, v in by_type.items()
            ])
            st.bar_chart(type_df.set_index("类型"))

        st.subheader("严重级别分布")
        by_sev = stats.get("by_severity", {})
        if by_sev:
            sev_df = pd.DataFrame([
                {"级别": k, "数量": v}
                for k, v in by_sev.items()
            ])
            st.bar_chart(sev_df.set_index("级别"))

        st.subheader("告警状态分布")
        by_status = stats.get("by_status", {})
        if by_status:
            status_df = pd.DataFrame([
                {"状态": k, "数量": v}
                for k, v in by_status.items()
            ])
            st.bar_chart(status_df.set_index("状态"))


if __name__ == "__main__":
    main()
