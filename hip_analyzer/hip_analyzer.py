import argparse
import json
from pathlib import Path
from string import Template

import pandas as pd

_TEMPLATE_PATH = Path(__file__).parent / "report_template.html"


def build_html_report(
    df: pd.DataFrame,
    pivot: pd.DataFrame,
) -> str:
    """Build a self-contained HTML page with interactive pivot-like filtering."""
    # Per-device: which objects/profiles matched and how many times
    device_matches = (
        df.groupby(["Machine Name", "os", "matchtype", "matchname"])["count"]
        .sum()
        .reset_index()
    )

    # All unique devices per OS
    all_devices = (
        df.groupby(["Machine Name", "os"])
        .size()
        .reset_index(name="_n")
        .drop(columns="_n")
    )

    # Build pivot data as JSON for dynamic summary filtering
    pivot_records = []
    for (match_type, match_name), row in pivot.fillna(0).iterrows():
        for os_type in row.index:
            val = row[os_type]
            if val:
                pivot_records.append({
                    "matchtype": match_type,
                    "matchname": match_name,
                    "os": os_type,
                    "DeviceCount": int(val),
                })

    template = Template(_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return template.substitute(
        DATA=json.dumps(device_matches.to_dict(orient="records")),
        DEVICES=json.dumps(all_devices.to_dict(orient="records")),
        PIVOT=json.dumps(pivot_records),
    )


def build_pivot(df: pd.DataFrame) -> pd.DataFrame:
    """Build a pivot table counting unique devices per OS/MatchType/MatchName."""
    # Count unique Machine Name per (matchtype, matchname, os)
    counts = (
        df.groupby(["matchtype", "matchname", "os"])["Machine Name"]
        .nunique()
        .reset_index(name="DeviceCount")
    )

    # Pivot to get OS types as columns
    pivot = counts.pivot_table(
        index=["matchtype", "matchname"],
        columns="os",
        values="DeviceCount",
        aggfunc="sum",
    )

    # Sort by matchtype then matchname
    result = pivot.sort_index()

    # Order columns consistently
    col_order = [c for c in ["iOS", "Mac", "Windows"] if c in result.columns]
    result = result[col_order]

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate an interactive HTML report from GlobalProtect HIP match data."
    )
    parser.add_argument("csv_file", type=Path, help="Input CSV file with HIP match data")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Output HTML file path (default: stdout)",
    )
    args = parser.parse_args()

    df = pd.read_csv(args.csv_file, sep=None, engine="python")

    # Normalize column names (support both legacy and new names)
    df = df.rename(columns={
        "HipMatchType": "matchtype",
        "HipMatchName": "matchname",
        "EndpointOSType": "os",
        "EndpointDeviceName": "Machine Name",
    })

    # If 'count' column is missing, default to 1
    if "count" not in df.columns:
        df["count"] = 1

    pivot = build_pivot(df)

    html = build_html_report(df, pivot)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(html, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(html)


if __name__ == "__main__":
    main()
