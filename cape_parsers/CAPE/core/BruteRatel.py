from contextlib import suppress


def extract_config(data):
    config = {}

    with suppress(Exception):
        i = 0
        lines = data.decode().split("\n")
        for line in lines:
            if line.startswith("Mozilla"):
                cncs = list(set(lines[i - 2].split(",")))
                port = lines[i - 1]
                uris = lines[i + 3].split(",")
                keys = [lines[i + 1], lines[i + 2]]

                for cnc in cncs:
                    # ToDo need to verify if we have schema and uri has slash
                    for uri in uris:
                        config.setdefault("CNCs", []).append(f"{cnc}:{port}{uri}")

                config["raw"] = {
                    "User Agent": line,
                    "C2": cncs,
                    "Port": port,
                    "URI": uri,
                    # ToDo move to proper field
                    "Keys": keys,
                }
                break
            i += 1

    return config


if __name__ == "__main__":
    import sys
    from pathlib import Path

    filedata = Path(sys.argv[1]).read_bytes()
    print(extract_config(filedata))
