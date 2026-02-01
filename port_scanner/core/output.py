import os
import io
import csv
import json

import config as conf

from models.port import Port
from tabulate import tabulate

def output_results(results, output_flag):
    for result in results:
        if result is None:
            continue
        pscanner, port_list = result
        output_results(port_list, pscanner.get_host(), output_flag)


def write_output(port_list: list[Port], host_ip: str, medium: tuple):
    port_list.sort(key=lambda x: x.get_port())

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
        data = list(map(lambda p: list(p), port_list))
        headers = [
            "Host",
            "Port Tested",
            "Port Status",
            "Port Is Open",
            "Service Banner",
        ]
        results = tabulate(data, headers=headers, tablefmt="grid")

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
