import { parseOperation } from "./contract.js";

const element = <T extends HTMLElement>(id: string): T => {
  const e = document.getElementById(id);
  if (!e) throw new Error(id);
  return e as T;
};
const input = element<HTMLTextAreaElement>("input");
const token = element<HTMLInputElement>("token");
let last: Record<string, unknown> = {};
const set = (v: unknown) => {
  input.value = JSON.stringify(v, null, 2);
};
element<HTMLSelectElement>("identity").addEventListener("change", (event) => {
  token.value = (event.target as HTMLSelectElement).value;
});
async function submit(value: unknown): Promise<void> {
  try {
    const op = parseOperation(value);
    const r = await fetch("/api/operate", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token.value}` },
      body: JSON.stringify(op),
    });
    const data = (await r.json()) as Record<string, unknown>;
    element("output").textContent = JSON.stringify(data, null, 2);
    element("decision").textContent = r.ok
      ? String(data.state ?? data.status ?? data.integrity ?? "Tenant records")
      : String(data.error ?? "Request rejected");
    element("decision").classList.toggle("bad", !r.ok);
    if (r.ok && !["list", "evidence"].includes(op.operation)) last = data;
  } catch (error) {
    element("decision").textContent = error instanceof Error ? error.message : "Invalid operation";
    element("decision").classList.add("bad");
  }
}
function next(): unknown {
  if (last.state === "open")
    return {
      operation: "propose",
      record_id: last.id,
      data: {
        target_revision: "b".repeat(40),
        artifact_sha256: "9047b391770ca346eb5ec1991f958c41e88d11b2fa877f1f31b8ad75bd557a89",
        fix: "Upgrade synthetic-parser to 2.0.0",
        diff: "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-synthetic-parser==1.0.0\n+synthetic-parser==2.0.0\n",
      },
    };
  if (last.state === "proposed")
    return { operation: "approve", record_id: last.id, data: { digest: last.proposal_sha256 } };
  if (last.state === "approved") return { operation: "rescan", record_id: last.id };
  if (last.state === "rescan_ready")
    return { operation: "close", record_id: last.id, data: last.rescan };
  return { operation: "list" };
}
async function reset(): Promise<void> {
  const r = await fetch("/api/sample", { headers: { Authorization: `Bearer ${token.value}` } });
  const data = (await r.json()) as Record<string, unknown>;
  if (!r.ok) {
    element("decision").textContent = String(data.error ?? "Authentication required");
    return;
  }
  const id = `demo-${Date.now().toString(36)}`;
  (data.finding as Record<string, unknown>).id = id;
  set({ operation: "ingest", data });
  last = {};
}
element("submit").addEventListener("click", () => {
  try {
    void submit(JSON.parse(input.value));
  } catch {
    element("decision").textContent = "Invalid JSON";
  }
});
element("next").addEventListener("click", () => set(next()));
element("reset").addEventListener("click", () => void reset());
element("list").addEventListener("click", () => void submit({ operation: "list" }));
element("evidence").addEventListener("click", () => void submit({ operation: "evidence" }));
void reset();
