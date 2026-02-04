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
        write_output(port_list, pscanner.get_host(), output_flag)


def write_output(port_list: list[Port], host_ip: str, medium: tuple):
    """Format and write port scan results to specified output medium.

    Formats the scan results in the requested format (txt, csv, json) and
    writes to either a file or console output. File output includes the
    host IP in the filename.

    Args:
        port_list (list[Port]): List of Port objects to output.
        host_ip (str): Host IP or hostname for the results.
        medium (tuple): (format_or_path, is_file) where:
                       - format_or_path: Format name (txt/csv/json) or file path
                       - is_file: Boolean indicating file output
    """
    port_list.sort()

    # Medium is (format_or_path, is_file)
    format_type, is_file = medium

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
        headers = [
            "Host",
            "Port Tested",
            "Port Status",
            "Port Is Open",
            "Service Banner",
        ]
        results = tabulate(port_list, headers=headers, tablefmt="grid")

        if is_file:
            with open(format_type, "w") as f:
                f.write(results)
        else:
            print(results)

    elif fmt == conf.CSV_FORMAT:
        data = list(map(lambda p: p.to_dict(), port_list))
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

    elif fmt == conf.JSON_FORMAT:
        data = list(map(lambda p: p.to_dict(), port_list))
        json_obj = json.dumps(data, indent=5)

        if is_file:
            with open(format_type, "w") as jsonf:
                jsonf.write(json_obj)
        else:
            print(json_obj)
