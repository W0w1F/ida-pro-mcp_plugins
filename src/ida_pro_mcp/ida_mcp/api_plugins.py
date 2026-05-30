"""Plugin management operations for IDA Pro MCP.

This module provides operations for inspecting some IDA Pro plugins.
"""
# mcp
from .rpc import tool
from .sync import idasync
# ida
import os
import ida_loader
import idc

# bindiff
import subprocess
import sqlite3
from pathlib import Path
from typing import Annotated, TypedDict
from pydantic import Field    


# ============================================================================
# BinDiff
# ============================================================================

class ExportFileEntry(TypedDict):
    """A single .BinExport file entry."""

    index: int
    name: str
    path: str

class ListExportsResult(TypedDict):
    """Result of scanning workspace for BinExport files."""

    workspace_dir: str
    current_idb: str
    total: int
    files: list[ExportFileEntry]
    instruction: str


@tool
@idasync
def list_exports() -> ListExportsResult:
    """Scan the current workspace directory for other available '.BinExport' files.
    Excludes the current opened binary from the list to avoid self-comparison."""
    current_idb = idc.get_idb_path()
    p = Path(current_idb)
    workspace_dir = str(p.parent).replace("\\", "/")

    full_path = p.parent / p.stem
    if full_path.suffix:
        full_path = full_path.with_name(full_path.stem)

    current_file_name = f"{full_path.name}.BinExport"
    all_binexports = list(Path(workspace_dir).glob("*.BinExport"))

    target_files = [
        {
            "index": idx,
            "name": f.name,
            "path": str(f).replace("\\", "/"),
        }
        for idx, f in enumerate(all_binexports, start=1)
        if current_file_name != f.name
    ]

    if not target_files:
        return {
            "workspace_dir": workspace_dir,
            "current_idb": str(p).replace("\\", "/"),
            "total": 0,
            "files": [],
            "instruction": (
                f"Notice: No other '.BinExport' target files were found in the workspace: '{workspace_dir}'.\n\n"
                "[Agent Action Required]: Explicitly inform the user that the current directory is ready, "
                "but no reference binaries (or their .BinExport dumps) were found in this folder. "
                "Ask the user to manually place reference files/dumps into this folder. "
                "Once the user replies that they have done so, tell them you will re-run this tool to refresh."
            ),
        } 
        
    else:
        return {
            "workspace_dir": workspace_dir,
            "current_idb": str(p).replace("\\", "/"),
            "total": len(target_files),
            "files": target_files,
            "instruction": (
                "Show the above files to the user. Ask which one to compare. "
                "When the user picks a number, call bindiff with "
                "secondary_path set to that file's path from the list above. "
                "DO NOT search for the file again — the path is already in this result."
            ),
        }
        


@tool
@idasync
def exports_analyse(
    secondary_path: Annotated[str, Field(description="The absolute path of the secondary .BinExport file to compare with")]
) -> str:
    """
    Perform a headless BinDiff comparison between the currently active IDB and a secondary .BinExport file.
    Returns a Markdown-formatted report showing the top 15 modified functions.
    """
    current_idb = idc.get_idb_path()
    p = Path(current_idb)
    workspace_dir = p.parent

    full_path = p.parent / p.stem
    if full_path.suffix:
        full_path = full_path.with_name(full_path.stem)
    primary_name = f"{full_path.name}.BinExport"

    output_path = workspace_dir / "result.BinDiff"
    temp_dir = output_path.parent
    primary_path = temp_dir / primary_name
    

    ida_loader.load_plugin("bindiff8_ida64")

    secondary_path_obj = Path(secondary_path)
    if not secondary_path_obj.is_file():
        return f"[!] Not found: {secondary_path_obj}"

    safe_primary_string = str(primary_path).replace("\\", "/")
    
    idc.eval_idc(f'BinExportBinary("{safe_primary_string}");')
    
    if not primary_path.is_file():
        return "[!] Export failed. BinExport plugin loaded?"

    be_path = Path(r"C:\Program Files\BinDiff\bin\bindiff.exe")
    be = str(be_path).replace("\\", "/") if be_path.is_file() else "bindiff"

    cmd = [
        be, 
        "--primary", str(primary_path).replace("\\", "/"), 
        "--secondary", str(secondary_path_obj).replace("\\", "/"), 
        "--output_dir", str(temp_dir).replace("\\", "/"),
        "--output_format", "bin"
    ]
    
    print(f"[*] Running CLI: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    found = None
    for f in os.listdir(temp_dir):
        if f.endswith(".BinDiff"):
            fp = temp_dir / f
            if found is None or fp.stat().st_ctime > found.stat().st_ctime:
                found = fp

    if found:
        if found.resolve() != output_path.resolve():
            if output_path.is_file():
                output_path.unlink()
            os.replace(found, output_path)
        try:
            conn = sqlite3.connect(str(output_path))
            cursor = conn.cursor()
            cursor.execute("""
                SELECT address1, address2, similarity, name1, name2 
                FROM function WHERE similarity < 1.0 ORDER BY similarity DESC LIMIT 15;
            """)
            rows = cursor.fetchall()
            conn.close()
            
            report = [f"[+] BinDiff completed successfully! Results saved."]
            report.append(f"{'Current Addr':<12} | {'Target Addr':<12} | {'Similarity':<6} | {'Function Mapping'}")
            report.append("-" * 75)
            for row in rows:
                addr1 = f"0x{row[0]:08X}" if row[0] else "N/A"
                addr2 = f"0x{row[1]:08X}" if row[1] else "N/A"
                report.append(f"{addr1:<12} | {addr2:<12} | {row[2]:.2f}   | {row[3]} -> {row[4]}")
            return "\n".join(report)
        except Exception as e:
            return f"[+] BinDiff Done, but failed to parse result SQLite: {e}"
                
    else:
        error_msg = [f"[!] No .BinDiff output generated."]
        if r.stdout: error_msg.append(f"stdout: {r.stdout[:150]}")
        if r.stderr: error_msg.append(f"stderr: {r.stderr[:150]}")
        return "\n".join(error_msg)