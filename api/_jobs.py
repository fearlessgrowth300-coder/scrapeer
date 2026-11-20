"""Background runs on the server (VPS): searches and sending keep going when the phone sleeps or the app is closed.
One row per run in scrapeer_jobs; the app only starts, watches and stops them. Threads live in server.py's process;
a run that was going when the server restarted is picked up again (resume()). Not for Vercel (no long-lived process)."""
import concurrent.futures as cf
import random
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from _auth import Bad, db

RUNNING = set()  # job ids with a live thread in this process
LOCK = threading.Lock()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def save(job_id, **fields):
    db("PATCH", "scrapeer_jobs", {"id": f"eq.{job_id}"}, body={**fields, "updated_at": now_iso()}, prefer="return=minimal")


def status_of(job_id):
    rows = db("GET", "scrapeer_jobs", {"id": f"eq.{job_id}", "select": "status"}) or []
    return rows[0]["status"] if rows else "stopped"


def start_thread(job):
    with LOCK:
        if job["id"] in RUNNING:
            return
        RUNNING.add(job["id"])
    target = run_search if job["kind"] == "search" else run_send

    def go():
        try:
            target(job)
        except Exception as e:  # never leave a run stuck on "running"
            save(job["id"], status="error", progress={**(job.get("progress") or {}), "msg": f"Stopped by an error: {type(e).__name__}: {str(e)[:200]}"})
        finally:
            RUNNING.discard(job["id"])
    threading.Thread(target=go, daemon=True).start()


def resume():
    """After a server restart: carry on with every run that was still going."""
    for job in db("GET", "scrapeer_jobs", {"status": "eq.running", "select": "*"}) or []:
        start_thread(job)


# ---------------- search ----------------
def run_search(job):
    from _scout import scout
    sites, res = job["input"]["sites"], job.get("result") or {}
    results, failed, done = res.get("results", []), res.get("failed", []), set(res.get("done", []))
    seen, last = {e["email"] for e in results}, 0.0

    def one(site):
        try:
            return site, scout(site)
        except Exception as e:
            return site, {"error": str(e)[:100]}

    def flush(final=False):
        save(job["id"], result={"results": results, "failed": failed, "done": sorted(done)},
             progress={"done": len(done), "total": len(sites), "emails": len(results), "failed": len(failed)},
             **({"status": "done"} if final else {}))

    todo = [s for s in sites if s not in done]
    with cf.ThreadPoolExecutor(6) as pool:
        for fut in cf.as_completed([pool.submit(one, s) for s in todo]):
            site, data = fut.result()
            done.add(site)
            if data.get("error"):
                failed.append(site)
            for e in data.get("emails") or []:
                if e["email"] not in seen:
                    seen.add(e["email"]); results.append(e)
            if time.time() - last > 3:
                last = time.time()
                if status_of(job["id"]) != "running":  # stopped from the app
                    pool.shutdown(wait=False, cancel_futures=True)
                    return flush()
                flush()
    flush(final=True)


# ---------------- sending ----------------
def in_hours(tz, at=None):
    try:
        t = (at or datetime.now(timezone.utc)).astimezone(ZoneInfo(tz))
    except Exception:
        t = (at or datetime.now(timezone.utc)).astimezone(ZoneInfo("America/New_York"))
    return t.weekday() < 5 and 8 <= t.hour < 17


def next_window(tzs):
    t = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    t += timedelta(minutes=15 - t.minute % 15)
    for _ in range(8 * 96):
        if any(in_hours(z, t) for z in tzs):
            return t
        t += timedelta(minutes=15)
    return None


def load_state(uid):
    return (db("GET", "scrapeer_state", {"user_id": f"eq.{uid}", "select": "data"}) or [{}])[0].get("data") or {}


def write_state(uid, entries, sent_keys, count_keys):
    """Merge this run's history into the account's saved data (same merge the app uses, so nothing is lost).
    Every write re-adds ALL of this run's lines: if an open tab's save raced one away, the next write puts it back."""
    from me import merge_state
    cur = load_state(uid)
    counts = dict(cur.get("counts") or {})
    for k, n in count_keys.items():
        counts[k] = max(counts.get(k, 0), n)
    state = merge_state(cur, {"log": entries, "sent": sent_keys, "counts": counts})
    db("POST", "scrapeer_state?on_conflict=user_id", body={"user_id": uid, "data": state, "updated_at": now_iso()},
       prefer="return=minimal,resolution=merge-duplicates")
    return state


def host(site):
    return re.sub(r"^https?://", "", str(site or "").lower()).removeprefix("www.").split("/")[0].split("?")[0]


FULL = re.compile(r"daily|limit|quota|exceeded", re.I)
BROKEN = re.compile(r"Login refused|connect to|API key|domain|verified|not allowed|suspend", re.I)


def run_send(job):
    from send import handle as send_one
    uid, inp = job["user_id"], job["input"]
    items, cfg = inp["items"], inp["settings"]
    pr = job.get("progress") or {}
    res = job.get("result") or {}
    entries, sent_keys, base_counts = res.get("entries", []), res.get("sent", {}), res.get("counts", {})
    i, sent, failed, rounds = pr.get("i", 0), pr.get("sent", 0), pr.get("failed", 0), pr.get("rounds", {})
    full, broken, run_sent, fails_in_row = set(), set(), [e["email"] for e in entries if e["status"] == "sent"], 0
    pool, started = cfg["pool"], job["created_at"]

    def progress(msg, **kw):
        save(job["id"], progress={"i": i, "sent": sent, "failed": failed, "total": len(items), "rounds": rounds, "msg": msg, **kw},
             result={"entries": entries, "sent": sent_keys, "counts": base_counts})

    def wait(seconds, msg, **kw):
        """Sleep in short steps so Pause in the app takes effect within ~10 s."""
        progress(msg, **kw)
        end = time.time() + seconds
        while time.time() < end:
            time.sleep(min(10, max(0, end - time.time())))
            if status_of(job["id"]) != "running":
                return False
        return True

    def record(item, status, note, via, subj="", body="", mid=""):
        nonlocal entries
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        e = {"when": datetime.now(timezone.utc).strftime("%m/%d/%Y, %H:%M UTC"), "date": today, "ts": int(time.time() * 1000),
             "email": item["email"], "status": status, "note": note, "via": via}
        if subj: e["subj"] = subj[:200]
        if body: e["snip"] = body[:3000]
        if mid: e["mid"] = str(mid).lower()
        if item.get("fu"): e["fu"] = item["fu"]
        entries = [e] + entries
        if status == "sent":
            sent_keys[item["email"]] = today
            if host(item.get("site")): sent_keys["site:" + host(item["site"])] = today
            k = f"{today}|{via}"
            base_counts[k] = base_counts.get(k) or (load_state(uid).get("counts") or {}).get(k, 0)
            base_counts[k] += 1
        if status == "skipped":  # no mail server: never again
            st = load_state(uid)
            if item["email"] not in str(st.get("dne") or ""):  # dne is a plain text list
                db("POST", "scrapeer_state?on_conflict=user_id", prefer="return=minimal,resolution=merge-duplicates",
                   body={"user_id": uid, "data": {**st, "dne": (str(st.get("dne") or "").strip() + "\n" + item["email"]).strip()}, "updated_at": now_iso()})
        return write_state(uid, entries, sent_keys, base_counts)

    state = load_state(uid)
    while i < len(items):
        if status_of(job["id"]) != "running":
            return progress(f"Paused. {sent} sent. Press Start to continue with the rest.")
        # the brake: 3 of the latest 20 emails of this run bounced → stop, the list is bad
        recent = run_sent[-20:]
        if recent:
            bounced = {e["contact"] for e in db("GET", "scrapeer_events", {"user_id": f"eq.{uid}", "type": "eq.email.bounced",
                                                                               "created_at": f"gt.{started}", "select": "contact"}) or []}
            if sum(1 for e in recent if e in bounced) >= 3:
                save(job["id"], status="stopped")
                return progress(f"Stopped to protect your domain: 3 of your latest 20 emails bounced. {sent} sent. Check your list before sending more.")
        if cfg.get("workhours"):
            j = next((k for k in range(i, len(items)) if in_hours(items[k].get("tz") or "America/New_York")), None)
            if j is None:
                nw = next_window({it.get("tz") or "America/New_York" for it in items[i:]})
                secs = max(60, (nw - datetime.now(timezone.utc)).total_seconds() + 5) if nw else 900
                if not wait(secs, f"Outside working hours for everyone left (Mon–Fri, 8 AM–5 PM their time). {sent} sent so far. "
                                  "Sending starts by itself — you can close the app.", next_at=nw.isoformat() if nw else None):
                    pass
                continue
            if j > i:
                items.insert(i, items.pop(j))
        it = items[i]
        state = load_state(uid)
        dne = set(re.split(r"[\s,;]+", str(state.get("dne") or "").lower()))
        if it["email"] in dne or (not it.get("fu") and (state.get("sent") or {}).get(it["email"])):
            i += 1
            continue
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log = state.get("log") or []
        sent_today = lambda label=None: sum(1 for l in log if l.get("date") == today and l.get("status") == "sent" and (label is None or l.get("via") == label))
        if cfg.get("cap") and sent_today() >= cfg["cap"] or all(a["id"] in full or a["id"] in broken or sent_today(a["label"]) >= a["cap"] for a in pool):
            if len(broken) == len(pool):
                save(job["id"], status="stopped")
                return progress(f"None of your accounts can send right now — check them in step 1 (details in the log). {sent} sent.")
            until = (datetime.now(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=1, second=0, microsecond=0)
            if wait((until - datetime.now(timezone.utc)).total_seconds(), f"Today's limit is reached. {sent} sent. Continues by itself after midnight UTC — you can close the app.",
                    next_at=until.isoformat()):
                full.clear()
            continue
        d, acct = None, None
        for a in pool:  # first account in your order with room today; a full/broken one hands the same person on
            if a["id"] in full or a["id"] in broken or sent_today(a["label"]) >= a["cap"]:
                continue
            acct = a
            progress(f"Sending to {it['email']} via {a['label']}…")
            try:
                d = send_one({"account_id": a["id"], "to": it["email"], "subject": it["subject"], "body": it["body"], "reply_to": cfg.get("reply_to") or "",
                              "signature": cfg.get("signature"), "plain": bool(cfg.get("plain")), "check": True, "in_reply_to": it.get("in_reply_to") or ""}, {"id": uid})
            except Bad as e:
                d = {"error": str(e)}
            except Exception as e:
                d = {"error": f"{type(e).__name__}: {str(e)[:150]}"}
            if d.get("error") and FULL.search(d["error"]):
                full.add(a["id"]); record(it, "failed", "account full today: " + d["error"], a["label"]); acct = None; continue
            if d.get("error") and BROKEN.search(d["error"]):
                broken.add(a["id"]); record(it, "failed", "account skipped: " + d["error"], a["label"]); acct = None; continue
            break
        if acct is None:
            continue  # loop top decides: wait for tomorrow / all broken
        if d.get("skipped"):
            record(it, "skipped", d["skipped"], acct["label"]); i += 1
            continue
        if d.get("error"):
            failed += 1; fails_in_row += 1; record(it, "failed", d["error"], acct["label"])
            if fails_in_row >= 5:
                save(job["id"], status="stopped")
                return progress(f"Stopped after 5 failures in a row: {d['error']} ({sent} sent)")
        else:
            sent += 1; fails_in_row = 0; run_sent.append(it["email"])
            record(it, "sent", f"follow-up {it['fu']}" if it.get("fu") else "", acct["label"], it["subject"], it["body"], d.get("message_id") or d.get("id") or "")
            if it.get("round") is not None:
                rounds[str(it["round"])] = rounds.get(str(it["round"]), 0) + 1
        i += 1
        if i < len(items):
            lo, hi = cfg.get("lo", 60), cfg.get("hi", 120)
            w = round(lo + random.random() * max(0, hi - lo))
            wait(w, f"Sent {sent} of {len(items)}. Next email in {w}s — this runs on the server, you can close the app.")
    save(job["id"], status="done")
    progress(f"Done — {sent} sent, {failed} failed.")


# ---------------- what the app calls ----------------
def handle(body, user):
    action, uid = body.get("action"), user["id"]
    if action == "status":  # latest run of each kind; for searches, only results the app doesn't have yet
        out = {}
        for kind in ("search", "send"):
            rows = db("GET", "scrapeer_jobs", {"user_id": f"eq.{uid}", "kind": f"eq.{kind}", "order": "created_at.desc", "limit": "1",
                                               "select": "id,kind,status,progress,result,created_at,updated_at,input"}) or []
            if not rows:
                continue
            j = rows[0]
            if kind == "search":
                have = int(body.get("have") or 0) if body.get("job") == j["id"] else 0
                r = j.get("result") or {}
                j = {**j, "input": {"sites": (j["input"] or {}).get("sites", [])} if body.get("job") != j["id"] else {},
                     "result": {"results": r.get("results", [])[have:], "failed": r.get("failed", [])}}
            else:
                j = {**j, "input": {"plan_base": (j["input"] or {}).get("plan_base")}, "result": {}}
            out[kind] = j
        return out
    if action == "stop":
        db("PATCH", "scrapeer_jobs", {"user_id": f"eq.{uid}", "status": "eq.running", "kind": f"eq.{body.get('kind')}"},
           body={"status": "stopped", "updated_at": now_iso()}, prefer="return=minimal")
        return {"ok": True}
    if action in ("start_search", "start_send"):
        kind = "search" if action == "start_search" else "send"
        if db("GET", "scrapeer_jobs", {"user_id": f"eq.{uid}", "kind": f"eq.{kind}", "status": "eq.running", "select": "id"}):
            raise Bad("One is already running — pause it first." if kind == "send" else "A search is already running.")
        if kind == "search":
            sites = [str(s)[:300] for s in (body.get("sites") or []) if s and not re.search(r"\s", str(s))][:500]
            if not sites:
                raise Bad("Paste at least one website.")
            inp = {"sites": sites}
        else:
            items = body.get("items") or []
            if not items or len(items) > 3000:
                raise Bad("Nothing to send.")
            keep = ("email", "subject", "body", "site", "tz", "fu", "round", "in_reply_to")
            items = [{k: it.get(k) for k in keep} for it in items if isinstance(it, dict) and it.get("email") and it.get("subject") and it.get("body")]
            s = body.get("settings") or {}
            pool = [{"id": str(a["id"]), "label": str(a["label"]), "cap": max(1, int(a.get("cap") or 100))} for a in (s.get("pool") or [])][:20]
            if not pool:
                raise Bad("Add a sending account in step 1 first.")
            mine = {r["id"] for r in db("GET", "scrapeer_accounts", {"user_id": f"eq.{uid}", "select": "id"}) or []}
            if any(a["id"] not in mine for a in pool):
                raise Bad("Unknown account.")
            inp = {"items": items, "plan_base": body.get("plan_base"),
                   "settings": {"pool": pool, "lo": max(5, int(s.get("lo") or 60)), "hi": max(5, int(s.get("hi") or 120)), "cap": int(s["cap"]) if s.get("cap") else None,
                                "workhours": bool(s.get("workhours")), "plain": bool(s.get("plain")), "signature": s.get("signature"), "reply_to": str(s.get("reply_to") or "")[:200]}}
        job = db("POST", "scrapeer_jobs", body={"user_id": uid, "kind": kind, "status": "running", "input": inp, "progress": {}, "result": {}})[0]
        start_thread(job)
        return {"job": job["id"]}
    raise Bad("Unknown action.")


if __name__ == "__main__":
    assert in_hours("Europe/Berlin", datetime(2026, 11, 20, 9, 0, tzinfo=timezone.utc))      # Fri 10:00 Berlin
    assert not in_hours("Europe/Berlin", datetime(2026, 11, 20, 17, 0, tzinfo=timezone.utc))  # Fri 18:00
    assert not in_hours("Europe/Berlin", datetime(2026, 11, 21, 10, 0, tzinfo=timezone.utc))  # Saturday
    assert host("https://www.Shop.de/x") == "shop.de"
    print("selfcheck ok")
