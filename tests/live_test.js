// Runs the page's real script with a fake DOM and feeds it real event data (scanner opens, separate chats).
// usage (from the repo root): node tests/live_test.js
const fs = require("fs");
const html = fs.readFileSync(__dirname + "/../index.html", "utf8");
const src = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
const el = () => new Proxy({value: "", textContent: "", innerHTML: "", hidden: false, dataset: {}, style: {}, classList: {add() {}, remove() {}, toggle() {}},
  addEventListener() {}, append() {}, focus() {}, scrollIntoView() {}, closest() { return null; }}, {get: (t, k) => k in t ? t[k] : () => {}, set: (t, k, v) => (t[k] = v, true)});
const els = {};
global.document = {getElementById: id => els[id] || (els[id] = el()), addEventListener() {}, createElement: () => el(), hidden: false};
global.window = {supabase: null}; global.location = {hash: "", origin: "x", pathname: "/"}; global.history = {replaceState() {}};
global.localStorage = {getItem: () => null, setItem() {}, removeItem() {}}; global.sessionStorage = global.localStorage;
global.fetch = async () => ({json: async () => ({})}); global.confirm = () => true; global.navigator = {clipboard: {}};
const code = src + `
;module.exports = {set: (a, ev) => { accounts = a; signedIn = true; hooksChecked = true; post = async (u, b) => b.action === "events" ? {events: ev} : {}; },
  pollEvents: () => pollEvents(), lastSeen: () => lastSeen, statuses: c => statuses(c), chatKey, isReading: c => isReading(c)};`;
const m = {exports: {}}; new Function("module", "require", code)(m, require); const P = m.exports;
const MJ = "mj-acc", RS = "rs-acc", who = "harpergvn@gmail.com";
const accs = [{id: MJ, label: "Mailjet · adebayor@legacyfalcon.tech", provider: "mailjet"}, {id: RS, label: "Resend · adebayor@legacyfalcon.tech", provider: "resend"}];
// real events from 2026-11-10; the Mailjet "opened" is listed BEFORE its "delivered" on purpose
P.set(accs, [
  {account_id: RS, type: "email.delivered", contact: who, email_id: "re-1", at: "2026-11-10T19:41:54Z", created_at: "2026-11-10T19:41:56Z"},
  {account_id: RS, type: "email.opened", contact: who, email_id: "re-1", at: "2026-11-10T19:41:55Z", created_at: "2026-11-10T19:41:57Z"},
  {account_id: MJ, type: "email.opened", contact: who, at: "2026-11-10T21:42:13Z", created_at: "2026-11-10T21:42:27.1Z"},
  {account_id: MJ, type: "email.delivered", contact: who, at: "2026-11-10T21:42:10Z", created_at: "2026-11-10T21:42:27.2Z"},
]);
(async () => {
  const ok = (c, msg) => { console.log((c ? "PASS " : "FAIL ") + msg); if (!c) process.exitCode = 1; };
  await P.pollEvents();
  const ls = P.lastSeen();
  ok(!ls[P.chatKey(MJ, who)] && !ls[P.chatKey(RS, who)], "scanner opens (1–3 s after delivery) don't count as 'seen'");
  const mjChat = {key: P.chatKey(MJ, who), msgs: [{id: "log-0", dir: "out", at: Date.parse("2026-11-10T21:42:09Z"), status: "other"}]};
  ok(P.statuses(mjChat).get(mjChat.msgs[0]) === "delivered", "Mailjet test shows grey ✓✓ delivered, not blue");
  const rsChat = {key: P.chatKey(RS, who), msgs: [{id: "re-1", key: 0, dir: "out", at: Date.parse("2026-11-10T19:41:53Z"), status: "opened"}]};
  ok(P.statuses(rsChat).get(rsChat.msgs[0]) === "delivered", "Resend's own 'opened' is overridden when it was a scanner");
  const brChat = {key: "br-acc|" + who, msgs: [{id: "log-1", dir: "out", at: Date.parse("2026-11-10T21:22:57Z"), status: "other"}]};
  ok(P.statuses(brChat).get(brChat.msgs[0]) === "other", "Brevo chat gets no ticks from Mailjet's events (separate chats)");
  P.set(accs, [{account_id: MJ, type: "email.opened", contact: who, at: new Date(Date.now() - 30000).toISOString(), created_at: new Date().toISOString()}]);
  await P.pollEvents();
  ok(P.isReading(mjChat), "a person opening later → 👀 Reading now");
  mjChat.msgs.push({id: "log-2", dir: "out", at: Date.now() - 60000, status: "other"});
  ok(P.statuses(mjChat).get(mjChat.msgs[1]) === "opened", "…and that message turns blue ✓✓");
})();

// Reply placement: the user's three real replies on 2026-11-10 must land in Resend, Mailjet and Brevo chats.
(async () => {
  const ok = (c, msg) => { console.log((c ? "PASS " : "FAIL ") + msg); if (!c) process.exitCode = 1; };
  const BR = "br-acc", who = "harpergvn@gmail.com";
  const accs = [{id: "rs-acc", label: "Resend · adebayor@legacyfalcon.tech", provider: "resend", from: "adebayor@legacyfalcon.tech"},
                {id: "mj-acc", label: "Mailjet · adebayor@legacyfalcon.tech", provider: "mailjet", from: "adebayor@legacyfalcon.tech"},
                {id: BR, label: "Brevo · adebayo@legacyfalcon.tech", provider: "brevo", from: "adebayo@legacyfalcon.tech"}];
  const sent = {emails: [{id: "re-1", key: 0, account_id: "rs-acc", to: who, subject: "[TEST] OKAY NA ME", last_event: "delivered",
                          created_at: "2026-11-10 22:11:42+00", message_id: "<RES-1@resend.dev>"}]};
  const replies = {replies: [
    {id: "in-1", key: 0, account_id: "rs-acc", from: who, subject: "Re: [TEST] OKAY NA ME", created_at: "2026-11-10T22:19:08Z"},
    {id: "in-2", key: 0, account_id: "rs-acc", from: who, subject: "Re: [TEST] OKAY NA ME", created_at: "2026-11-10T22:19:25Z"},
    {id: "in-3", key: 0, account_id: "rs-acc", from: who, subject: "Re: [TEST] why are you here", created_at: "2026-11-10T22:19:36Z"}]};
  const refs = {"in-1": ["<res-1@resend.dev>"], "in-2": ["<mj-rewritten-by-mailjet@mailjet.com>"], "in-3": ["<brevo-own-id@smtp-brevo.com>"]};
  const log = [  // newest first, as the app stores it; Mailjet/Brevo IDs were rewritten so ours don't match
    {status: "test", email: who, via: accs[1].label, subj: "[TEST] OKAY NA ME", snip: "HELLO ME", ts: Date.parse("2026-11-10T22:10:30Z"), mid: "<ours-1@legacyfalcon.tech>"},
    {status: "test", email: who, via: accs[2].label, subj: "[TEST] why are you here", snip: "hi", ts: Date.parse("2026-11-10T22:08:20Z")}];
  const P2 = (() => { const m = {exports: {}}; new Function("module", "require", src + `
;module.exports = {go: async (a, l, s, r, f) => { accounts = a; log = l; signedIn = true;
  post = async (u, b) => b.action === "sent" ? s : b.action === "inbox" ? r : b.action === "refs" ? {refs: f} : {};
  state = {}; await loadInbox(true); clearInterval(inboxTimer); return convos; }};`)(m, require); return m.exports; })();
  const convos = await P2.go(accs, log, sent, replies, refs);
  const where = id => [...convos.values()].find(c => c.msgs.some(m => m.id === id))?.account_id;
  ok(where("in-1") === "rs-acc", "reply quoting the Resend email → Resend chat");
  ok(where("in-2") === "mj-acc", "reply to the Mailjet email → Mailjet chat (Resend ruled out by its ID)");
  ok(where("in-3") === BR, "reply to the Brevo email → Brevo chat (subject match)");
})();
(async () => {
  const ok = (c, msg) => { console.log((c ? "PASS " : "FAIL ") + msg); if (!c) process.exitCode = 1; };
  const m = {exports: {}}; new Function("module", "require", src + `
;module.exports = {go: async () => { signedIn = true; let done; post = () => new Promise(r => done = r);
    const saving = saveState(); record("mid@shop.com", "sent", "", "Resend");
    done({log: [], sent: {}, read: [], refs: {}}); await saving; clearTimeout(saveTimer);
    return {log, sent: state.sent}; }};`)(m, require);
  const r = await m.exports.go();
  ok(r.log.some(e => e.email === "mid@shop.com"), "an email sent during a save stays in the log");
  ok(r.sent["mid@shop.com"], "...and that person stays marked as emailed");
})();
(async () => {
  const ok = (c, msg) => { console.log((c ? "PASS " : "FAIL ") + msg); if (!c) process.exitCode = 1; };
  const m = {exports: {}}; new Function("module", "require", src + ";module.exports = {tooManyBounces, isFreeMail, realName, enrich};")(m, require);
  const {tooManyBounces: b, isFreeMail: f, realName: n, enrich: e} = m.exports, set = new Set(["a", "b", "c"]);
  ok(!b(["a", "b", "x"], set), "2 bounces don't stop the run");
  ok(b(["a", "b", "c"], set), "3 bounces stop the run");
  ok(!b(["a", "b", "c", ...Array(20).fill("x")], set), "old bounces outside the latest 20 don't count");
  ok(f("x@gmail.com") && f("x@outlook.fr") && !f("x@gmailshop.com") && !f("x@legacyfalcon.tech"), "Gmail/Outlook detection");
  ok(n("Tanya") === "Tanya" && n("Kontakt") === "" && n("Www") === "" && n("Designs") === "", "only real first names are used");
  ok(!e({email: "designs-swivels.25@icloud.com", type: "person"}).first_name, "no made-up name from a business address");
  ok(e({email: "elsa.chiao@gmail.com", type: "person"}).first_name === "Elsa", "real first.last still gets a name");
  ok(e({email: "a@b.com", first_name: "Zaccai"}).first_name === "Zaccai", "a name you upload yourself is kept");
})();
