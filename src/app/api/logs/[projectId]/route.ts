import { NextRequest, NextResponse } from "next/server";
import { readFileSync } from "fs";
import path from "path";

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ projectId: string }> }
) {
  const { projectId } = await params;

  if (!/^[a-z0-9-]+$/.test(projectId)) {
    return NextResponse.json({ error: "Invalid project ID" }, { status: 400 });
  }

  const logPath = path.join(process.cwd(), "logs", `${projectId}.log`);

  try {
    const content = readFileSync(logPath, "utf-8");
    const lines = content.split("\n").filter((l) => l.trim() !== "");
    const tail = lines.slice(-10).join("\n");
    return new NextResponse(tail, { headers: { "Content-Type": "text/plain" } });
  } catch {
    return new NextResponse("Log file not found or empty.", {
      headers: { "Content-Type": "text/plain" },
    });
  }
}
