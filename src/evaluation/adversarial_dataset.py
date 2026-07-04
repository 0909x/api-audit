"""
LLM对抗数据集：专攻规则引擎盲区。
所有样本设计原则：规则引擎漏检（FN），LLM可检出。
"""
import hashlib
import random
import structlog
from dataclasses import field
from typing import Optional
from src.evaluation.real_dataset import RealSample

logger = structlog.get_logger()


class AdversarialGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def _sub_rng(self, tag: str) -> random.Random:
        h = hashlib.md5(tag.encode()).hexdigest()
        return random.Random(int(h[:8], 16))

    def _make_record(self, method: str, path: str, status: int = 200,
                     query_params: Optional[dict] = None, delta_sec: float = 0,
                     body: Optional[str] = None) -> dict:
        record = {
            "method": method, "path": path, "status_code": status,
            "query_params": query_params or {}, "timestamp_delta": delta_sec,
        }
        if body is not None:
            record["body"] = body
        return record

    def generate(self, samples_per_type: int = 4) -> list[RealSample]:
        samples = []
        samples.extend(self._gen_body_bola(samples_per_type))
        samples.extend(self._gen_b64_traversal(samples_per_type))
        samples.extend(self._gen_biz_anomaly(samples_per_type))
        samples.extend(self._gen_low_freq_abuse(samples_per_type))
        samples.extend(self._gen_noise_mixed(samples_per_type))
        samples.extend(self._gen_version_traversal(samples_per_type))
        self.rng.shuffle(samples)
        logger.info("adversarial_dataset_generated", total=len(samples))
        return samples

    def _gen_body_bola(self, n: int) -> list[RealSample]:
        """Type A: Body-ID BOLA — 资源ID藏在POST body或query param中，路径无数字ID"""
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"body_bola_{i}")
            resource_id = rng.randint(10000, 99999)
            records = []
            t = 0
            records.append(self._make_record("POST", "/api/auth/login", 200,
                           query_params={"user": "userA"}, delta_sec=t))
            t += rng.uniform(0.5, 2.0)
            records.append(self._make_record("POST", "/api/orders", 201,
                           body=f'{{"orderId":{resource_id},"items":[1,2,3]}}',
                           delta_sec=t))
            t += rng.uniform(0.5, 1.0)
            records.append(self._make_record("POST", "/api/auth/logout", 200, delta_sec=t))
            t += rng.uniform(0.5, 1.5)
            records.append(self._make_record("POST", "/api/auth/login", 200,
                           query_params={"user": "userB"}, delta_sec=t))
            t += rng.uniform(0.5, 2.0)
            records.append(self._make_record("GET", "/api/orders/detail", 200,
                           query_params={"id": str(resource_id)}, delta_sec=t))
            samples.append(RealSample(
                session_id=f"adv_body_bola_{i:04d}", records=records,
                label="bola", sub_type="bola", spec_name="adversarial/body_bola",
            ))
        return samples

    def _gen_b64_traversal(self, n: int) -> list[RealSample]:
        """Type B: Base64-like paths with letter+number, bypassing numeric-only patterns"""
        prefixes = ["Ab", "Cd", "Ef", "Gh"]
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"b64_trav_{i}")
            prefix = rng.choice(prefixes)
            count = rng.randint(8, 12)
            records = []
            t = 0
            base_id = 1000 + i * 100
            for j in range(count):
                uid = f"{prefix}{base_id + j}"
                status = 200 if j % 7 != 0 else 404
                records.append(self._make_record("GET", f"/api/notes/{uid}", status, delta_sec=t))
                t += rng.uniform(5.0, 10.0)
            samples.append(RealSample(
                session_id=f"adv_b64_trav_{i:04d}", records=records,
                label="traversal", sub_type="traversal",
                spec_name="adversarial/b64_traversal",
            ))
        return samples

    def _gen_biz_anomaly(self, n: int) -> list[RealSample]:
        """Type C: 业务逻辑异常 — 单请求违反正常业务流，所有规则均需2+条件，无触发可能"""
        base_spec_summary = "API: ECommerceAPI v1.0, 8 endpoints"
        base_spec_detail = (
            "标准业务流程: POST /api/cart/add → POST /api/checkout → POST /api/payments/charge\n"
            "  POST /api/cart/add: 添加商品到购物车 [需认证] path_params=(无)\n"
            "  POST /api/checkout: 结算购物车 [需认证] 必须在 POST /api/cart/add 之后\n"
            "  POST /api/payments/charge: 执行支付 [需认证] 必须在 POST /api/checkout 之后\n"
            "  DELETE /api/articles/force: 强制删除文章 [管理员权限] 普通用户不可用\n"
            "  GET /api/v1/reports/summary: 获取全局报表 [管理员权限] range=all 返回所有数据\n"
            "  GET /api/products: 商品列表 [公开]\n"
            "  GET /api/categories: 分类列表 [公开]\n"
            "  POST /api/auth/login: 用户登录\n"
            "  POST /api/auth/logout: 用户登出"
        )
        scenarios = [
            {"method": "POST", "path": "/api/checkout", "status": 200},
            {"method": "POST", "path": "/api/payments/charge", "status": 200,
             "body": '{"amount":9999,"currency":"USD"}'},
            {"method": "DELETE", "path": "/api/articles/force", "status": 204},
            {"method": "GET", "path": "/api/v1/reports/summary", "status": 200,
             "query_params": {"range": "all"}},
        ]
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"biz_anom_{i}")
            scenario = rng.choice(scenarios)
            is_report = (scenario.get("path", "") == "/api/v1/reports/summary")
            if is_report:
                records = [
                    self._make_record("POST", "/api/auth/login", 200,
                                      query_params={"user": "joe"}, delta_sec=0),
                    self._make_record(delta_sec=rng.uniform(0.5, 1.5), **scenario),
                ]
            else:
                records = [self._make_record(delta_sec=0, **scenario)]
            samples.append(RealSample(
                session_id=f"adv_biz_anom_{i:04d}", records=records,
                label="abuse", sub_type="abuse",
                spec_name="adversarial/biz_anomaly",
                spec_summary=base_spec_summary,
                spec_detail=base_spec_detail,
            ))
        return samples

    def _gen_low_freq_abuse(self, n: int) -> list[RealSample]:
        """Type D: 低频敏感操作 — 调用次数低于频率阈值，路径不含敏感关键词"""
        sensitive_endpoints = [
            {"method": "GET", "path": "/api/v1/export", "query_params": {"format": "csv"}},
            {"method": "POST", "path": "/api/v1/batch/process", "query_params": {"action": "sync"}},
            {"method": "GET", "path": "/api/v1/logs/audit", "query_params": {"level": "verbose"}},
            {"method": "POST", "path": "/api/v1/import/data", "query_params": {"type": "users"}},
        ]
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"low_freq_{i}")
            ep = rng.choice(sensitive_endpoints)
            count = rng.randint(10, 14)
            records = []
            t = 0
            for j in range(count):
                records.append(self._make_record(
                    ep["method"], ep["path"], 200,
                    query_params=ep.get("query_params"),
                    delta_sec=t))
                t += rng.uniform(5.0, 10.0)
            samples.append(RealSample(
                session_id=f"adv_low_freq_{i:04d}", records=records,
                label="abuse", sub_type="abuse",
                spec_name="adversarial/low_freq_abuse",
            ))
        return samples

    def _gen_noise_mixed(self, n: int) -> list[RealSample]:
        """Type E: 噪声混合 — 正常序列中穿插攻击请求"""
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"noise_{i}")
            records = []
            t = 0
            attack_type = rng.choice(["bola", "traversal"])

            if attack_type == "bola":
                resource_id = rng.randint(10000, 99999)
                normal_steps = [
                    {"method": "POST", "path": "/api/auth/login", "status": 200,
                     "query_params": {"user": "alice"}},
                    {"method": "GET", "path": "/api/products", "status": 200},
                    {"method": "GET", "path": "/api/categories", "status": 200},
                ]
                for step in normal_steps:
                    records.append(self._make_record(delta_sec=t, **step))
                    t += rng.uniform(1.0, 3.0)
                records.append(self._make_record("GET", "/api/orders/detail", 200,
                               query_params={"id": str(resource_id)}, delta_sec=t))
                t += rng.uniform(1.0, 3.0)
                records.append(self._make_record("POST", "/api/auth/logout", 200, delta_sec=t))
                t += rng.uniform(2.0, 5.0)
                records.append(self._make_record("POST", "/api/auth/login", 200,
                               query_params={"user": "bob"}, delta_sec=t))
                t += rng.uniform(1.0, 3.0)
                records.append(self._make_record("GET", "/api/orders/detail", 200,
                               query_params={"id": str(resource_id)}, delta_sec=t))
                t += rng.uniform(1.0, 2.0)
                records.append(self._make_record("GET", "/api/products/search", 200,
                               query_params={"q": "laptop"}, delta_sec=t))
            else:
                base_id = 10000 + i * 100
                normal_steps = [
                    {"method": "POST", "path": "/api/auth/login", "status": 200,
                     "query_params": {"user": "alice"}},
                    {"method": "GET", "path": "/api/profile", "status": 200},
                    {"method": "GET", "path": "/api/settings", "status": 200},
                ]
                for step in normal_steps:
                    records.append(self._make_record(delta_sec=t, **step))
                    t += rng.uniform(1.0, 3.0)
                for j in range(6):
                    uid = base_id + j
                    status = 200 if j % 6 != 0 else 404
                    records.append(self._make_record("GET", f"/api/users/{uid}", status, delta_sec=t))
                    t += rng.uniform(3.0, 6.0)
                records.append(self._make_record("GET", "/api/products", 200, delta_sec=t))

            samples.append(RealSample(
                session_id=f"adv_noise_{i:04d}", records=records,
                label="mixed", sub_type=attack_type,
                spec_name="adversarial/noise_mixed",
            ))
        return samples

    def _gen_version_traversal(self, n: int) -> list[RealSample]:
        """Type F: API version traversal with incremental versions, bypassing digit patterns"""
        samples = []
        for i in range(n):
            rng = self._sub_rng(f"ver_trav_{i}")
            count = rng.randint(10, 15)
            resource = rng.choice(["/users", "/orders", "/products", "/payments"])
            records = []
            t = 0
            base_ver = rng.randint(0, 3)
            for j in range(count):
                ver = base_ver + j * 0.1
                path = f"/api/v{ver:.1f}{resource}"
                status = 200 if j % 10 != 0 else 404
                records.append(self._make_record("GET", path, status, delta_sec=t))
                t += rng.uniform(3.0, 6.0)
            samples.append(RealSample(
                session_id=f"adv_ver_trav_{i:04d}", records=records,
                label="traversal", sub_type="traversal",
                spec_name="adversarial/version_traversal",
            ))
        return samples
