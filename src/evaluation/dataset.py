import random
import structlog
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Literal

logger = structlog.get_logger()


@dataclass
class Sample:
    session_id: str
    records: list[dict]
    label: str
    sub_type: str = ""


class DatasetGenerator:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate(self, samples_per_type: int = 20) -> list[Sample]:
        all_samples = []
        all_samples.extend(self._generate_normal(samples_per_type))
        all_samples.extend(self._generate_bola(samples_per_type))
        all_samples.extend(self._generate_traversal(samples_per_type))
        all_samples.extend(self._generate_abuse(samples_per_type))
        all_samples.extend(self._generate_mixed(samples_per_type))
        self.rng.shuffle(all_samples)
        logger.info("dataset_generated", total=len(all_samples), types={
            "normal": samples_per_type,
            "bola": samples_per_type,
            "traversal": samples_per_type,
            "abuse": samples_per_type,
            "mixed": samples_per_type,
        })
        return all_samples

    def _make_record(self, method: str, path: str, status: int = 200,
                     query_params: Optional[dict] = None, delta_sec: float = 0) -> dict:
        return {
            "method": method,
            "path": path,
            "status_code": status,
            "query_params": query_params or {},
            "timestamp_delta": delta_sec,
        }

    def _generate_normal(self, n: int) -> list[Sample]:
        samples = []
        login_paths = ["/api/v1/login", "/api/v1/auth", "/api/v1/signin"]
        browse_paths = ["/api/v1/products", "/api/v1/categories", "/api/v1/search"]
        order_paths = ["/api/v1/cart", "/api/v1/orders", "/api/v1/checkout"]

        for i in range(n):
            records = []
            t = 0
            records.append(self._make_record("POST", self.rng.choice(login_paths), 200, delta_sec=t))
            t += self.rng.uniform(0.5, 3.0)
            records.append(self._make_record("GET", self.rng.choice(browse_paths), 200,
                           query_params={"page": str(self.rng.randint(1, 5))}, delta_sec=t))
            t += self.rng.uniform(0.5, 2.0)
            records.append(self._make_record("GET", self.rng.choice(browse_paths), 200, delta_sec=t))
            t += self.rng.uniform(1.0, 5.0)
            records.append(self._make_record("POST", self.rng.choice(order_paths), 200, delta_sec=t))
            t += self.rng.uniform(1.0, 3.0)
            records.append(self._make_record("GET", "/api/v1/users/profile", 200, delta_sec=t))

            samples.append(Sample(
                session_id=f"normal_{i:04d}",
                records=records,
                label="normal",
                sub_type="normal",
            ))
        return samples

    def _generate_bola(self, n: int) -> list[Sample]:
        samples = []
        for i in range(n):
            resource_id = str(self.rng.randint(10000, 99999))
            records = []
            t = 0
            records.append(self._make_record("POST", "/api/v1/login", 200,
                           query_params={"user": "userA"}, delta_sec=t))
            t += 1.0
            records.append(self._make_record("GET", f"/api/v1/users/orders/{resource_id}", 200, delta_sec=t))
            t += 0.5
            records.append(self._make_record("POST", "/api/v1/logout", 200, delta_sec=t))
            t += 1.0
            records.append(self._make_record("POST", "/api/v1/login", 200,
                           query_params={"user": "userB"}, delta_sec=t))
            t += 0.5
            records.append(self._make_record("GET", f"/api/v1/users/orders/{resource_id}", 200, delta_sec=t))

            samples.append(Sample(
                session_id=f"bola_{i:04d}",
                records=records,
                label="bola",
                sub_type="bola",
            ))
        return samples

    def _generate_traversal(self, n: int) -> list[Sample]:
        samples = []
        base_id = 10000
        for i in range(n):
            records = []
            t = 0
            for j in range(self.rng.randint(15, 30)):
                uid = base_id + i * 100 + j
                status = 200 if j % 3 != 0 else 404
                records.append(self._make_record(
                    "GET", f"/api/v1/users/{uid}", status, delta_sec=t
                ))
                t += self.rng.uniform(0.1, 0.5)

            samples.append(Sample(
                session_id=f"trav_{i:04d}",
                records=records,
                label="traversal",
                sub_type="traversal",
            ))
        return samples

    def _generate_abuse(self, n: int) -> list[Sample]:
        samples = []
        for i in range(n):
            records = []
            t = 0
            count = self.rng.randint(30, 60)
            for j in range(count):
                records.append(self._make_record(
                    "GET", "/api/v1/export/all", 200,
                    query_params={"format": "json"},
                    delta_sec=t,
                ))
                t += self.rng.uniform(0.05, 0.3)

            samples.append(Sample(
                session_id=f"abuse_{i:04d}",
                records=records,
                label="abuse",
                sub_type="abuse",
            ))
        return samples

    def _generate_mixed(self, n: int) -> list[Sample]:
        samples = []
        for i in range(n):
            choice = self.rng.choice(["bola", "traversal", "abuse"])
            if choice == "bola":
                base = self._generate_bola(1)[0]
            elif choice == "traversal":
                base = self._generate_traversal(1)[0]
            else:
                base = self._generate_abuse(1)[0]
            base.label = "mixed"
            base.sub_type = choice
            base.session_id = f"mixed_{i:04d}"
            samples.append(base)
        return samples


def samples_to_chain(sample: Sample) -> "ApiCallChain":
    from src.sequence.chain_builder import ApiCallChain
    from src.ingestion.models import RequestRecord
    from datetime import datetime

    base_time = datetime.now()
    chain = ApiCallChain(session_id=sample.session_id)
    for rec in sample.records:
        delta = timedelta(seconds=rec.get("timestamp_delta", 0))
        chain.records.append(RequestRecord(
            timestamp=base_time + delta,
            method=rec.get("method", "GET"),
            path=rec.get("path", "/"),
            query_params=rec.get("query_params", {}),
            status_code=rec.get("status_code", 200),
            session_id=sample.session_id,
        ))
    return chain
