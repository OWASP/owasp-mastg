import yaml

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Diff the MASTG test cases covered.")
    parser.add_argument("-o", "--old", required=True)
    parser.add_argument("-n", "--new", required=True)

    args = parser.parse_args()

    MASVS_OLD = yaml.safe_load(open(args.old))
    MASVS_NEW = yaml.safe_load(open(args.new))

    updated = 0
    added = 0
    removed = 0

    print("OWASP MAS Checklists Changes")

    for mstg_id, req in MASVS_NEW.items():
        old_links = MASVS_OLD[mstg_id].get("links")
        new_links = req.get("links")

        if old_links and new_links:
            diff = list(set(new_links) - set(old_links))
            updated += 1
            if diff:
                print(f"- [UPDATED] {mstg_id}:")
                for link in diff:
                    print(f"  - {link}")
                print("\n")
        elif old_links is None and new_links:
            added += 1
            print(f"- [ADDED] {mstg_id}:")
            for link in new_links:
                print(f"  - {link}")
            print("\n")
        elif old_links and new_links is None:
            removed += 1
            print(f"- [REMOVED] {mstg_id}\n")

    print(f"\nSUMMARY: removed ({removed}) added ({added}) updated ({updated})")

if __name__ == "__main__":
    main()