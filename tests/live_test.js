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
