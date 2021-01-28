import yaml

with open("POC-Resiliency.yaml", 'r') as stream:
    try:
        doc = yaml.safe_load(stream)
        print(doc["TITLE"])

        static = doc["TESTS"]["STATIC"]

        with open("toCompare.md", "w") as output:
            output.write(static)
    except yaml.YAMLError as exc:
        print(exc)