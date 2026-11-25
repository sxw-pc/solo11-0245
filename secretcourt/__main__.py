import argparse
import json
from pathlib import Path
from .store import connect, invoke, replay, rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["material", "grant", "delivery", "demo", "report", "replay"])
    parser.add_argument("--db", default="demo.sqlite")
    parser.add_argument("--fixture")
    args = parser.parse_args()
    if args.command == "replay":
        result = replay(args.db)
    else:
        db = connect(args.db)
        if args.command == "report":
            result = rows(db, "SELECT * FROM events ORDER BY seq")
        elif args.command == "demo":
            result = []
            for subsystem, file in [
                ("material", "material_normal.json"), ("grant", "grant_normal.json"),
                ("delivery", "delivery_normal.json"), ("material", "material_failure.json"),
                ("grant", "grant_failure.json"), ("delivery", "delivery_failure.json")]:
                commands = json.loads((Path("fixtures") / file).read_text(encoding="utf-8"))
                outcomes = [invoke(db, subsystem, command) for command in commands]
                result.append({"fixture": file, "outcomes": outcomes})
        else:
            if not args.fixture:
                parser.error("--fixture required")
            commands = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
            result = [invoke(db, args.command, command) for command in commands]
        db.close()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if args.command == "replay" and not result["verified"]:
        raise SystemExit(2)

if __name__ == "__main__":
    main()
