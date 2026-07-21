import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

src, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
asof = date(2026, 7, 21)
url = "https://seshat.datasd.org/development_permits/approvals_created_2026_datasd.csv"
page = "https://data.sandiego.gov/datasets/development-permits/"
norm = lambda s: re.sub(r"[^A-Z0-9]+", "_", str(s or "").strip().upper()).strip("_")
clean = lambda s: re.sub(r"\s+", " ", str(s or "").strip())


def dt(value):
    value = clean(value)
    try:
        return date.fromisoformat(value[:10])
    except Exception:
        return None


def num(value):
    try:
        return float(clean(value).replace("$", "").replace(",", "") or 0)
    except Exception:
        return 0.0


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1_048_576), b""):
            digest.update(block)
    return digest.hexdigest()


biz = re.compile(
    r"\b(construction|contractor|contracting|builders?|roofing|plumb|electric|hvac|"
    r"landscap|concrete|masonry|framing|drywall|architect|engineer|developer|development|"
    r"realty|realtor|properties|company|inc|llc|corp|partners|group|associates|holdings|"
    r"city of|county of|department|district|government|university|school|church|hospital|"
    r"foundation|association|hoa|services|solutions|consulting)\b",
    re.I,
)
commercial = re.compile(
    r"\b(commercial|tenant improvement|office|retail|restaurant|hotel|warehouse|industrial|"
    r"school|hospital|church|mixed[- ]use|multi[- ]family|multifamily|apartment|assisted living|suite)\b",
    re.I,
)
trade = re.compile(
    r"\b(solar|photovoltaic|\bpv\b|battery energy|ev charger|evse|service panel|panel upgrade|"
    r"reroof|re-roof|roof replacement|mechanical only|electrical only|plumbing only|water heater|"
    r"furnace|air condition|sewer lateral|fire alarm|fire sprinkler|sign permit|cell site|telecom|"
    r"antenna|traffic control|pool only|spa only|demolition only|retaining wall only|"
    r"window replacement only|siding only)\b",
    re.I,
)


def holder(value):
    value = clean(value)
    if not value:
        return "unknown"
    if biz.search(value) or any(char.isdigit() for char in value):
        return "business_or_government"
    if re.fullmatch(r"[A-Za-z][A-Za-z .,'\-]{2,80}", value) and 2 <= len(value.split()) <= 5:
        return "person_like"
    return "unknown"


def category(value):
    text = clean(value).lower()
    if re.search(r"\b(accessory dwelling unit|adu|jadu)\b", text):
        return "adu_jadu", 105
    if "garage" in text and re.search(r"\b(convert|conversion)\b", text):
        return "garage_conversion", 98
    if re.search(r"\b(whole[- ]house|whole[- ]home|full[- ]home|full[- ]house)\b", text):
        return "whole_home_remodel", 110
    kitchen = "kitchen" in text
    bath = bool(re.search(r"\b(bath|bathroom|restroom)\b", text))
    if kitchen and bath:
        return "kitchen_and_bath_remodel", 102
    if kitchen:
        return "kitchen_remodel", 94
    if bath:
        return "bathroom_remodel", 90
    if re.search(r"\b(room addition|home addition|residential addition|addition to|additions? and alterations?)\b", text):
        return "residential_addition", 96
    if re.search(r"\b(remodel|renovat|alteration|add/alt|addition)\b", text):
        return "residential_remodel", 82
    return None, 0


def recent(value):
    if not value:
        return 0
    days = max(0, (asof - value).days)
    return 32 if days <= 7 else 29 if days <= 14 else 25 if days <= 30 else 20 if days <= 60 else 12 if days <= 120 else 4


def valuation_points(value):
    return 30 if value >= 500000 else 26 if value >= 250000 else 22 if value >= 100000 else 17 if value >= 50000 else 12 if value >= 25000 else 7 if value >= 10000 else 2


def status_points(value):
    text = value.lower()
    return 24 if "issued" in text else 18 if "created" in text else 15 if "pending" in text or "invoice" in text else 12 if "review" in text else 8


counts = Counter()
best = {}
with src.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
    reader = csv.DictReader(handle)
    mapping = {norm(key): key for key in reader.fieldnames or []}

    def get(row, key):
        return clean(row.get(mapping.get(norm(key), ""), ""))

    required = {"PROJECT_ID", "APPROVAL_ID", "APPROVAL_TYPE", "APPROVAL_STATUS", "APPROVAL_SCOPE", "GIS_ADDRESS"}
    missing = required - set(mapping)
    if missing:
        raise SystemExit("missing columns: " + str(sorted(missing)))

    for raw_row in reader:
        counts["raw_rows"] += 1
        approval_type = get(raw_row, "APPROVAL_TYPE")
        status = get(raw_row, "APPROVAL_STATUS")
        if "building permit" not in approval_type.lower():
            counts["excluded_nonbuilding"] += 1
            continue
        if any(token in status.lower() for token in ("closed", "completed", "expired", "cancel", "withdraw", "void", "denied", "rejected")):
            counts["excluded_inactive"] += 1
            continue

        scope = get(raw_row, "APPROVAL_SCOPE") or get(raw_row, "PROJECT_SCOPE")
        project_category, category_points = category(scope)
        if not project_category:
            counts["excluded_nonpriority"] += 1
            continue
        if trade.search(scope) and project_category == "residential_remodel":
            counts["excluded_trade_only"] += 1
            continue

        evidence = " ".join((scope, get(raw_row, "JOB_BC_CODE_DESCRIPTION"), get(raw_row, "PROJECT_TITLE")))
        residential = re.search(r"\b(sdu|single[- ]family|1 or 2 fam|residence|residential|dwelling|duplex|home|house|adu|jadu|garage)\b", evidence, re.I)
        if commercial.search(evidence) or not residential:
            counts["excluded_not_residential"] += 1
            continue

        holder_class = holder(get(raw_row, "APPROVAL_PERMIT_HOLDER"))
        if holder_class == "business_or_government":
            counts["excluded_business_or_government"] += 1
            continue

        address = get(raw_row, "GIS_ADDRESS")
        if not address:
            counts["excluded_missing_address"] += 1
            continue

        project_id = get(raw_row, "PROJECT_ID")
        approval_id = get(raw_row, "APPROVAL_ID")
        identity = project_id or approval_id or hashlib.sha256((address + scope).encode()).hexdigest()[:16]
        approval_created = dt(get(raw_row, "APPROVAL_CREATE_DATE"))
        project_created = dt(get(raw_row, "PROJECT_CREATE_DATE"))
        issued = dt(get(raw_row, "APPROVAL_ISSUE_DATE"))
        expires = dt(get(raw_row, "APPROVAL_EXPIRE_DATE"))
        reference_date = approval_created or project_created or issued
        valuation = num(get(raw_row, "APPROVAL_VALUATION"))
        processing = (get(raw_row, "APPROVAL_PROCESSING_CODE") or get(raw_row, "PROJECT_PROCESSING_CODE")).lower()
        score = category_points + status_points(status) + valuation_points(valuation) + recent(reference_date) + (15 if holder_class == "person_like" else 0) + (5 if processing in ("expedite", "express") else 0)
        zip_match = re.search(r"\b(9\d{4})\b", address)
        zip_code = zip_match.group(1) if zip_match else ""
        holder_raw = get(raw_row, "APPROVAL_PERMIT_HOLDER")
        holder_hash = hashlib.sha256(holder_raw.casefold().encode()).hexdigest()[:16] if holder_raw else ""

        row = {
            "rank": 0,
            "project_id": project_id,
            "approval_id": approval_id,
            "approval_type": approval_type,
            "approval_status": status,
            "project_create_date": project_created.isoformat() if project_created else "",
            "approval_create_date": approval_created.isoformat() if approval_created else "",
            "approval_issue_date": issued.isoformat() if issued else "",
            "approval_expire_date": expires.isoformat() if expires else "",
            "address": address,
            "zip_code": zip_code,
            "project_category": project_category,
            "project_scope": scope,
            "approval_valuation": round(valuation, 2),
            "permit_holder_classification": holder_class,
            "permit_holder_hash": holder_hash,
            "research_state": "research_only" if holder_class == "person_like" else "needs_human_context",
            "selection_score": score,
            "selection_reason": f"{project_category}; active {status}; residential evidence; holder {holder_class}; valuation ${valuation:,.0f}",
            "grounded_personalization_note": f"Public City permit {approval_id or project_id} lists {project_category.replace('_', ' ')} work in ZIP {zip_code or 'unknown'}, created {reference_date.isoformat() if reference_date else 'unknown'}, status {status}, valuation ${valuation:,.0f}. Internal research only.",
            "prohibited_claim": "Do not claim inquiry, consent, homeowner identity, contractor search, quote request, or prior contact.",
            "source_dataset_page": page,
            "source_download_url": url,
            "dataset_retrieved_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "duplicate_key": hashlib.sha256(f"{project_id}|{approval_id}|{address.casefold()}".encode()).hexdigest()[:20],
            "outbound_authorized": False,
            "_date": reference_date.isoformat() if reference_date else "",
            "_score": score,
            "_valuation": valuation,
        }
        old = best.get(identity)
        if old is None or (row["_score"], row["_date"], row["_valuation"]) > (old["_score"], old["_date"], old["_valuation"]):
            if old is not None:
                counts["deduped_approval_rows"] += 1
            best[identity] = row
        else:
            counts["deduped_approval_rows"] += 1

candidates = list(best.values())
counts["eligible_unique_projects"] = len(candidates)
candidates.sort(key=lambda item: (item["_score"], item["_date"], item["_valuation"]), reverse=True)
selected = [item for item in candidates if item["permit_holder_classification"] == "person_like"] + [item for item in candidates if item["permit_holder_classification"] == "unknown"]
selected = selected[:50]
if len(selected) != 50:
    raise SystemExit(f"needed 50, found {len(selected)}")

for index, item in enumerate(selected, 1):
    item["rank"] = index
    for key in ("_date", "_score", "_valuation"):
        item.pop(key)

base = "cali_dream_permit_research_50_20260721"
fields = list(selected[0])
with (out / (base + ".csv")).open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(selected)

payload = {
    "schema_version": "1.0",
    "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "brand_id": "calidream",
    "purpose": "permit research candidates; not send targets",
    "record_count": 50,
    "outbound_authorized": False,
    "source": {"dataset_page": page, "download_url": url, "input_sha256": sha(src)},
    "filter_counts": dict(counts),
    "records": selected,
}
(out / (base + ".json")).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

markdown = [
    "# Cali Dream Construction — 50 Permit Research Candidates",
    "",
    f"- Generated: `{payload['generated_at_utc']}`",
    "- Records: **50 exactly**",
    "- Public permit research only; not consent, not an inquiry, not a send list.",
    "- Permit-holder names are deliberately omitted.",
    "- Outbound actions: **0**.",
    "",
    "## Counts",
    "",
] + [f"- `{key}`: {value}" for key, value in sorted(counts.items())] + [
    "",
    "## Selected",
    "",
    "|#|Permit|Created|Status|ZIP|Category|Value|Holder class|State|",
    "|--:|---|---|---|---|---|---:|---|---|",
]
for item in selected:
    created = item["approval_create_date"] or item["project_create_date"] or item["approval_issue_date"]
    markdown.append(f"|{item['rank']}|{item['approval_id']}|{created}|{item['approval_status']}|{item['zip_code']}|{item['project_category']}|${item['approval_valuation']:,.0f}|{item['permit_holder_classification']}|{item['research_state']}|")
markdown += ["", "Public permit data alone never authorizes ‘I saw your request,’ quote-request, consent, or prior-contact wording.", ""]
(out / (base + ".md")).write_text("\n".join(markdown), encoding="utf-8")

manifest = {
    "schema_version": "1.0",
    "record_count": 50,
    "outbound_actions": {"email": 0, "sms": 0, "calls": 0, "ads": 0, "public_posts": 0},
    "input": {"url": url, "sha256": sha(src), "bytes": src.stat().st_size},
    "outputs": {},
}
for output_path in out.glob(base + ".*"):
    manifest["outputs"][output_path.name] = {"sha256": sha(output_path), "bytes": output_path.stat().st_size}
(out / (base + "_manifest.json")).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

print(json.dumps({
    "status": "success",
    "record_count": 50,
    "person_like": sum(item["permit_holder_classification"] == "person_like" for item in selected),
    "unknown": sum(item["permit_holder_classification"] == "unknown" for item in selected),
    "outbound_actions": 0,
}))
