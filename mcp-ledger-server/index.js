import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { google } from "googleapis";

const SHEET_ID = process.env.LEDGER_SHEET_ID;;
const SHEET_NAME = "Sheet1";
const KEY_FILE = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;

const auth = new google.auth.GoogleAuth({
  keyFile: KEY_FILE,
  scopes: ["https://www.googleapis.com/auth/spreadsheets"],
});
const sheets = google.sheets({ version: "v4", auth });

async function readLedger(n = 20) {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A:J`,
  });
  const rows = res.data.values || [];
  if (rows.length === 0) return "Ledger is empty.";
  const headers = rows[0];
  const data = rows.slice(1).slice(-n);
  return data.map(row =>
    headers.map((h, i) => `${h}: ${row[i] || ""}`).join(" | ")
  ).join("\n");
}

async function writeLedger(agent, type, task, files, matched_plan, drift_reason, next, commit, session_id) {
  const timestamp = new Date().toISOString();
  const row = [timestamp, agent, type, task, files, matched_plan, drift_reason, next, commit, session_id];
  await sheets.spreadsheets.values.append({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A:J`,
    valueInputOption: "RAW",
    requestBody: { values: [row] },
  });
  return `✅ Logged: [${agent}] ${type} — ${task}`;
}

async function checkDrift() {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A:J`,
  });
  const rows = res.data.values || [];
  if (rows.length < 2) return "Not enough entries to check drift.";
  const data = rows.slice(1).slice(-50);
  const driftEntries = data.filter(row => row[5] === "no" || row[5] === "partial");
  if (driftEntries.length === 0) return "✅ No drift detected in last 50 entries.";
  return driftEntries.map(row =>
    `⚠️ DRIFT | Agent: ${row[1]} | Task: ${row[3]} | Reason: ${row[6]}`
  ).join("\n");
}

async function getCurrentTask() {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A:J`,
  });
  const rows = res.data.values || [];
  if (rows.length < 2) return "No tasks logged yet.";
  const last = rows[rows.length - 1];
  return `Current Task: ${last[3]} | Agent: ${last[1]} | Next: ${last[7]} | Session: ${last[9]}`;
}

async function initHeaders() {
  const res = await sheets.spreadsheets.values.get({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A1:J1`,
  });
  const existing = res.data.values;
  if (existing && existing[0] && existing[0][0] === "Timestamp") return;
  await sheets.spreadsheets.values.update({
    spreadsheetId: SHEET_ID,
    range: `${SHEET_NAME}!A1:J1`,
    valueInputOption: "RAW",
    requestBody: {
      values: [["Timestamp", "Agent", "Type", "Task", "Files", "Matched_Plan", "Drift_Reason", "Next", "Commit", "Session_ID"]],
    },
  });
}

const server = new Server(
  { name: "mcp-ledger-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "ledger_read",
      description: "Read the last N entries from the AI-SOC Sentinel Decision Ledger. Use this at the start of every session to get current project state.",
      inputSchema: {
        type: "object",
        properties: {
          n: { type: "number", description: "Number of recent entries to fetch (default 20)" }
        }
      }
    },
    {
      name: "ledger_write",
      description: "Append a new entry to the Decision Ledger. Call this after every completed task.",
      inputSchema: {
        type: "object",
        required: ["agent", "type", "task", "matched_plan"],
        properties: {
          agent: { type: "string", description: "AMPCODE, ANTIGRAVITY, or CLAUDE" },
          type: { type: "string", description: "BUILD, DECISION, RECOMMENDATION, DEVIATION, BUG, FIX" },
          task: { type: "string", description: "Summary of what was done" },
          files: { type: "string", description: "File paths changed (comma separated)" },
          matched_plan: { type: "string", description: "yes, no, or partial" },
          drift_reason: { type: "string", description: "Why it deviated from plan (if applicable)" },
          next: { type: "string", description: "What comes next" },
          commit: { type: "string", description: "Git commit hash if applicable" },
          session_id: { type: "string", description: "Current session identifier" }
        }
      }
    },
    {
      name: "ledger_check_drift",
      description: "Check for drift between what was planned and what was actually built.",
      inputSchema: { type: "object", properties: {} }
    },
    {
      name: "ledger_get_current_task",
      description: "Get the current active task and project state.",
      inputSchema: { type: "object", properties: {} }
    }
  ]
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  try {
    let result;
    if (name === "ledger_read") {
      result = await readLedger(args?.n || 20);
    } else if (name === "ledger_write") {
      result = await writeLedger(
        args.agent, args.type, args.task,
        args.files || "", args.matched_plan,
        args.drift_reason || "", args.next || "",
        args.commit || "", args.session_id || ""
      );
    } else if (name === "ledger_check_drift") {
      result = await checkDrift();
    } else if (name === "ledger_get_current_task") {
      result = await getCurrentTask();
    } else {
      result = `Unknown tool: ${name}`;
    }
    return { content: [{ type: "text", text: result }] };
  } catch (err) {
    return { content: [{ type: "text", text: `Error: ${err.message}` }] };
  }
});

const transport = new StdioServerTransport();
await initHeaders();
await server.connect(transport);