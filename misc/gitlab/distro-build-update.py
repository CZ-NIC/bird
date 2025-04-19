import subprocess

def update(data):
    print("# update processer running")
    res = subprocess.run(["git", "show", "--stat", "--oneline"], capture_output=True)
    if res.returncode != 0:
        print("Git show failed with return code", res.returncode)
        print(res.stdout.decode())
        print(res.stderr.decode())
        exit(1)

    for line in res.stdout.decode().split('\n')[1:-2]:
        if not line.startswith(" misc/docker/"):
            continue

        file = line[13:].split('/')[0]

        for item in data:
            if item["name"] == file:
                item["rebuild_image"] = True

    return data
