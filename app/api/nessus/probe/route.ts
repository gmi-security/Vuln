import { NextResponse } from "next/server";
import {
  nessusListFolders,
  nessusListScans,
  nessusServerStatus,
} from "@/lib/nessus";

export const dynamic = "force-dynamic";

// Temporary READ-ONLY diagnostic: lists the scanner's folders and per-folder
// scan counts so we can verify the import source without mutating anything.
export async function GET() {
  const status = await nessusServerStatus();
  if (!status.reachable) {
    return NextResponse.json({ status, folders: [], scanCount: 0 });
  }
  try {
    const [folders, scans] = await Promise.all([
      nessusListFolders(),
      nessusListScans(),
    ]);
    const countByFolder = new Map<number, number>();
    for (const sc of scans) {
      countByFolder.set(sc.folderId, (countByFolder.get(sc.folderId) ?? 0) + 1);
    }
    return NextResponse.json({
      status,
      scanCount: scans.length,
      folders: folders.map((f) => ({
        name: f.name,
        type: f.type,
        scans: countByFolder.get(f.id) ?? 0,
      })),
    });
  } catch (err) {
    return NextResponse.json({
      status,
      error: err instanceof Error ? err.message : "probe failed",
      folders: [],
      scanCount: 0,
    });
  }
}
