"""Output formatting and display for scan results.

Provides functions to format scanning results in multiple output formats
(text table, CSV, JSON) and write to either console or file.
"""

import os
import io
import csv
import json

from port_scanner import config as conf
from port_scanner.models.port import Port
from tabulate import tabulate


def display_results(results, output_flag):
    """Display scanning results for all hosts.

    Iterates through scan results and formats output according to the
    specified output flag (format and destination).

    Args:
        results (list): List of tuples (scanner, port_list) or None values.
        output_flag (tuple): (format_or_path, is_file) tuple where format_or_path
                            is the output format or file path, and is_file indicates
                            whether to write to file.
    """
    for result in results:
        if result is None:
            continue
        pscanner, port_list = result
        write_output(port_list, pscanner.display_host(), output_flag)


def write_output(port_list: list[Port], host_ip: str, medium: tuple):
    """Format and write port scan results to specified output medium.

    Formats the scan results in the requested format (txt, csv, json) and
    writes to either a file or console output. File output includes the
    host IP in the filename.

    It can also return json or csv representation if being used in a 
    programmatic context (e.g., API or library usage) instead of printing to console.

    Args:
        port_list (list[Port]): List of Port objects to output.
        host_ip (str): Host IP or hostname for the results.
        medium (tuple): (format_or_path, is_file) where:
                       - format_or_path: Format name (txt/csv/json) or file path
                       - is_file: Boolean indicating file output
    Returns:
        str or None: Formatted output string if outputting to console, else None.
    """
    port_list.sort()

    # Medium is (format_or_path, is_file)
    format_type, is_file = medium
    data = [dict(p) for p in port_list]

    # If writing to a file, build a per-host filename safely
    if is_file:
        base, ext = os.path.splitext(format_type)
        format_type = f"{base}-{host_ip}{ext}"

    # Determine the format keyword (txt/csv/json)
    fmt = (
        os.path.splitext(format_type)[1].lstrip(".").lower()
        if is_file
        else format_type.lower()
    )

    if fmt == conf.TEXT_FORMAT:
        headers = {
            "host": "Host",
            "port": "Port Tested",
            "status": "Port Status",
            "is_open": "Port Is Open",
            "service_banner": "Service Banner",
        }
        results = tabulate(data, headers=headers, tablefmt="grid")

        if is_file:
            with open(format_type, "w") as f:
                f.write(results)
        else:
            print(results)

    elif fmt == conf.CSV_FORMAT:
        fieldnames = ["host", "port", "status", "is_open", "service_banner"]

        if is_file:
            with open(format_type, "w") as csvf:
                writer = csv.DictWriter(csvf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(data)
        else:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
            print(f"\n{buf.getvalue()}")
            return buf.getvalue()

    elif fmt == conf.JSON_FORMAT:
        json_obj = json.dumps(data, indent=5)

        if is_file:
            with open(format_type, "w") as jsonf:
                jsonf.write(json_obj)
        else:
            print(json_obj)
            return json_obj
