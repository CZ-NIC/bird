#!/usr/bin/python3

import logging
import os
import pathlib
import subprocess
import sys
import yaml

from BIRDDevel import Command, Tag, Version, Job

TARGET_DIR = pathlib.Path("obj/rpm-repo")

logging.basicConfig(format='%(levelname)# 8s | %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    with open(TARGET_DIR / "status.yaml", "r") as f:
        info = yaml.safe_load(f)
except FileNotFoundError:
    info = {
            "tags": { k: "legacy" for k in (
                "3.0-alpha0",
                "v3.0-alpha1",
                "v3.0-alpha2",
                "v2.0.0-pre0",
                "v2.0.0-pre1",
                # we had some bugs in the release machinery for these versions:
                "v2.17.1",
                "v2.18",
                "v3.2.0",
                )}
            }

dva_update = {}

def ziploader(z):
    def zl(name, path):
        with z.open(name) as zf:
            with open(path / (vn := name.split("/")[-1]), "wb") as ff:
                ff.write(zf.read())
    return zl

def fileloader(name, path):
    with open(name, "rb") as rf:
        with open(path / (vn := name.split("/")[-1]), "wb") as wf:
            wf.write(rf.read())

def process_rpms(this, namelist, load):
    pkg = {}
    src = {}

    for name in namelist:
        name = str(name)
        if not name.endswith(".rpm"):
            logging.debug(f"    (not an rpm file: {name}")
            continue

        if name.startswith("pkg/pkgs/") or name.startswith("pkg/srcpkgs"):
            # is a package
            try:
                _, s, dv, _, f = name.split("/")
            except ValueError:
                logging.debug(f"    (too short name {name})")
                continue

            distro, version, *_ = (*dv.split("-"), None)

            if s == "srcpkgs":
                logging.info(f"    For {distro:10s} {version:5s}   (src)  : {name}")
                if (distro, version) in src:
                    src[(distro, version)].append(name)
                else:
                    src[(distro, version)] = [ name ]

            else:
                try:
                    arch = f.split(".")[-2]
                except IndexError:
                    logging.debug(f"    (no arch found in {name})")
                    continue

                logging.info(f"    For {distro:10s} {version:5s} {arch:9s}: {name}")
                if (distro, version, arch) in pkg:
                    pkg[(distro, version, arch)].append(name)
                else:
                    pkg[(distro, version, arch)] = [ name ]

    for k, v in pkg.items():
        distro, version, arch = k
        dva_update[k] = True

        try:
            s = src[(distro, version)]
        except KeyError:
            logging.error(f"    No source package for {distro}-{version}")

        path = TARGET_DIR / distro / version / arch
        path.mkdir(parents=True, exist_ok=True)

        for vv in v:
            load(vv, path)
        for ss in s:
            load(ss, path)

        if this is None:
            continue

        if distro not in this['rpm']:
            this['rpm'][distro] = {}

        if version not in this['rpm'][distro]:
            this['rpm'][distro][version] = {}

        if arch not in this['rpm'][distro][version]:
            this['rpm'][distro][version][arch] = True

for p in sys.argv[1:]:
    process_rpms(None, pathlib.Path(p).rglob('*.rpm'), fileloader)

for name, t in Tag.load().items():
    if name not in info['tags']:
        info['tags'][name] = {}

    if info["tags"][name] == 'legacy':
        continue

    v = t.version
    if v is None or v.major < 2 or v.major == 2 and v.minor == 0:
        logging.info (f"Ignoring legacy version {name}")
        info["tags"][name] = "legacy"
        continue

    this = info['tags'][name]
    logging.info (f"Processing tag {name} of {t.commit_sha}")

    # Find the tag-collect job
    try:
        tag_collect = Job(this['tag-collect']['id'])
    except KeyError:
        tag_collect = [
                p.jobs['tag-collect']
                for p in t.pipelines
                if 'tag-collect' in p.jobs
                ]
        if len(tag_collect) == 0:
            logging.info(f"No tag-collect job for version {name}")
            info["tags"][name] = "legacy"
            continue
        elif len(tag_collect) > 1:
            logging.error(f"Too many tag-collect jobs for version {name}: {tag_collect}")
            continue
        else:
            tag_collect = tag_collect[0]
            this['tag-collect'] = tag_collect.info()

    logging.info(f"  Tag collect job: {tag_collect}")

    # Stream-process its artifacts.zip
    if 'rpm' not in this:
        this['rpm'] = {}
        with tag_collect.artifacts_zipfile() as z:
            process_rpms(this, z.namelist(), ziploader(z))

unsigned = []
for item in TARGET_DIR.rglob('*.rpm'):
    r = subprocess.run([ "rpm", "-qi", item ], capture_output=True)
    q = [ f for f in r.stdout.decode().split("\n") if f.startswith("Signature") ]
    if len(q) != 1:
        logging.error(f"RPM file {item} has weird signature lines: {q}")
    elif q[0].endswith("(none)"):
        unsigned.append(item)

if len(unsigned) > 0:
    try:
        keyid, _ = Command("git", "config", "rpm.key")
        keyid = [ "--key-id", keyid ]
    except:
        keyid = []

    logging.info(f"Found {len(unsigned)} unsigned RPMs")
    for u in unsigned:
        logging.info(f"\t{u}")
    subprocess.run([ "rpmsign", "--addsign", *keyid, *unsigned ])

for distro, version, arch in dva_update:
    logging.info(f"Updating repo info for {distro} / {version} / {arch}")
    if distro == "centos" and version == "7":
        subprocess.run([ "createrepo_c", "--compatibility", str(TARGET_DIR / distro / version / arch) ])
    else:
        subprocess.run([ "createrepo_c", str(TARGET_DIR / distro / version / arch) ])

    with open(TARGET_DIR / distro / version / arch / "bird.repo", "w") as f:
        f.write(f"""[bird]
name=bird (nic.cz)
baseurl=https://pkg.labs.nic.cz/rpm/bird/{distro}/{version}/{arch}
enabled=1
gpgcheck=1
gpgkey=https://pkg.labs.nic.cz/rpm/bird/network.cz.gpg
""")

with open(TARGET_DIR / "status.yaml", "w") as f:
    yaml.safe_dump(info, f)
