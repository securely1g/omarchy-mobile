# SPDX-License-Identifier: MIT
"""Validate and stage a private parent-managed image before fastboot is contacted."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(stream):
    result = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        result.update(chunk)
    return result.hexdigest()


def public_key(value):
    fields = value.split()
    require(len(fields) == 2 and fields[0] == "ssh-ed25519", "expected one uncommented Ed25519 public key")
    data = base64.b64decode(fields[1], validate=True)
    require(len(data) == 51 and data[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", "invalid Ed25519 public key")
    return " ".join(fields)


class Root:
    def __init__(self, image):
        self.image = image

    def query(self, command, path):
        # Paths below are fixed, or contain a separately validated account name.
        result = subprocess.run(["debugfs", "-R", command + " " + path, self.image],
                                check=True, capture_output=True, env={**os.environ, "LC_ALL": "C"})
        errors = result.stderr.splitlines()[1:]
        if len(errors) == 1 and b"File not found by ext2_lookup" in errors[0]:
            return None
        require(not errors, "filesystem inspection failed at " + path)
        return result.stdout

    def read(self, path):
        info = self.query("stat", path)
        require(info is not None and b"Type: regular" in info, "missing or non-regular file: " + path)
        size = re.search(rb"\bSize:\s+(\d+)\b", info)
        require(size and int(size[1]) <= 4 * 1024 * 1024, "unexpected file size: " + path)
        return self.query("cat", path)

    def document(self, path):
        return json.loads(self.read(path))


def inspect_root(raw, receipt, deployment):
    root = Root(raw)
    # Active firstboot answers could replace the carefully prepared account and lock.
    firstboot = "/etc/omamobile/firstboot.conf"
    if root.query("stat", firstboot) is not None:
        require(not any(row.strip() and not row.lstrip().startswith(b"#")
                        for row in root.read(firstboot).splitlines()), "prepared image contains active firstboot answers")
    accounts = root.document("/usr/share/omarch-phone-image/accounts.json")
    daily = accounts["daily"]
    require(isinstance(daily, str) and re.fullmatch("[a-z_][a-z0-9_-]{0,31}", daily)
            and daily not in ("root", "parent") and accounts["parent"] == "parent", "invalid prepared accounts")
    users = {row[0]: row for row in (line.split(":") for line in root.read("/etc/passwd").decode().splitlines())}
    groups = {row[0]: row for row in (line.split(":") for line in root.read("/etc/group").decode().splitlines())}
    wheel = groups["wheel"]
    require(users[daily][2] == "1000" and users["parent"][2] == "1001" and users["parent"][5] == "/home/parent"
            and daily not in wheel[3].split(",") and users[daily][3] != wheel[2]
            and ("parent" in wheel[3].split(",") or users["parent"][3] == wheel[2]), "prepared account privileges differ")
    def row_hash(path, expected):
        require(hashlib.sha256(root.read(path)).hexdigest() == expected, "prepared file digest differs: " + path)
    for path, expected in receipt["managed_files"].items():
        row_hash(path, expected)
    policy = root.document("/etc/omamobile/image-policy.json")
    target = receipt["policy_device"]
    require(policy["dailyUser"] == daily and len(set(policy["allowedDesktopIds"])) == 5
            and root.document("/etc/omamobile/image-profile.json")["allowedDesktopIds"] == policy["allowedDesktopIds"],
            "managed daily user or five-app profile differs")
    require(all(root.document(path)["device"] == target for path in (
        "/etc/omamobile/parent-screen-enrollment.json", "/var/lib/omarch-phone-screen-time/policy.json")),
        "prepared policy belongs to a different device")
    require(root.read("/etc/sudoers.d/90-parent-admin").strip() == b"parent ALL=(ALL:ALL) NOPASSWD: ALL"
            and (daily + " ALL=(ALL:ALL) !ALL").encode() in root.read("/etc/sudoers.d/zz-parent-managed-daily").splitlines(),
            "prepared administrative access differs")
    shell = root.read("/usr/bin/bash")
    require(shell[:6] == b"\x7fELF\x02\x01" and shell[18:20] == b"\xb7\x00", "prepared userspace is not AArch64")
    parent_auth = root.read("/home/parent/.ssh/authorized_keys").decode("ascii").strip().splitlines()
    require(len(parent_auth) == 1 and public_key(" ".join(parent_auth[0].split()[:2])) == receipt["parent_public_key"],
            "parent maintenance authorization differs")
    if deployment:
        require(accounts["synthetic_test_accounts"] is False and accounts["production_enrollment"] is True,
                "production installation requires replacement of synthetic credentials")
        root_auth = "/root/.ssh/authorized_keys"
        if root.query("stat", root_auth) is not None:
            allowed = {receipt["parent_public_key"], receipt["recovery_public_key"]}
            for row in root.read(root_auth).decode("ascii").splitlines():
                if row.strip() and not row.lstrip().startswith("#"):
                    require(public_key(" ".join(row.split()[:2])) in allowed, "unapproved root SSH authorization")
        receiver_home = "/var/lib/omarch-phone-screen-time/ssh"
        require(users["phone-policy"][5] == receiver_home and users["phone-policy"][3] != wheel[2]
                and "phone-policy" not in wheel[3].split(","), "unexpected policy receiver account")
        passwords = {row[0]: row[1] for row in (line.split(":") for line in root.read("/etc/shadow").decode().splitlines())}
        require(passwords["phone-policy"].startswith(("!", "*")) and not passwords[daily].startswith(("!", "*"))
                and passwords[daily].startswith("$"), "prepared login or receiver password state differs")
        require(root.read("/etc/sudoers.d/90-phone-screen-policy").strip()
                == b"phone-policy ALL=(root) NOPASSWD: /usr/local/libexec/omarch-phone-screen-time receive",
                "restricted receiver sudo authorization differs")
        state = root.document("/var/lib/omarch-phone-screen-time/ssh-enrollment/record.json")
        receiver = receipt["receiver_public_key"]
        require(state.get("state") == "ready" and state["device"] == target and state["publicKey"] == receiver,
                "target policy receiver is not enrolled")
        forced = 'restrict,command="/usr/bin/sudo -n /usr/local/libexec/omarch-phone-screen-time receive" '
        auth_path = "/var/lib/omarch-phone-screen-time/ssh/.ssh/authorized_keys"
        require(root.read(auth_path).decode("ascii").strip() == forced + receiver, "restricted receiver authorization differs")


REQUIRED_FILES = {
    "/etc/pam.d/omarchy-lock-password", "/etc/pam.d/omarchy-lock-fingerprint",
    "/etc/pam.d/omarch-phone-screen-password-base", "/etc/pam.d/omarch-phone-screen-fingerprint-base",
    "/etc/omamobile/image-policy.json", "/etc/omamobile/image-profile.json", "/usr/local/libexec/omarch-phone-screen-time",
    "/etc/sudoers.d/90-parent-admin", "/etc/sudoers.d/zz-parent-managed-daily",
}


def load_receipt(path, codename, serial, parts, writing):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.geteuid()) and not info.st_mode & 0o022
                and info.st_size <= 16384, "prepared receipt must be a trusted regular file")
        receipt = json.load(source)
    require(receipt.get("version") == 1 and receipt["device"] == codename, "prepared receipt device mismatch")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", receipt["policy_device"]), "invalid expected policy device")
    require(serial and hashlib.sha256(serial.encode()).hexdigest() == receipt["serial_sha256"],
            "serial differs from the independently supplied prepared receipt")
    purpose = receipt["purpose"]
    require(purpose in ("rehearsal", "production") and (not writing or purpose == "production"),
            "rehearsal receipt is valid only for verify-only or dry-run")
    require(set(receipt["boot_sha256"]) == set(parts) and set(receipt["managed_files"]) == REQUIRED_FILES,
            "prepared receipt does not cover the exact boot and managed file set")
    sums = [receipt["root_sha256"], receipt["raw_sha256"], *receipt["boot_sha256"].values(), *receipt["managed_files"].values()]
    require(all(isinstance(v, str) and re.fullmatch("[0-9a-f]{64}", v) for v in sums), "invalid prepared image digest")
    for name in ["parent_public_key", "recovery_public_key"]:
        require(public_key(receipt[name]) == receipt[name], "invalid prepared public key")
    if purpose == "production":
        require(public_key(receipt["receiver_public_key"]) == receipt["receiver_public_key"]
                and receipt["receiver_public_key"] not in (receipt["parent_public_key"], receipt["recovery_public_key"]),
                "receiver authorization must be independent")
    return receipt


def stage(args):
    parts = args.partitions.split()
    receipt = load_receipt(args.receipt, args.device, args.serial, parts, args.writing)
    # Only these private copies go on to parsing, conversion and writing. A change
    # to an input after verification cannot change the payload being installed.
    images = args.directory / "images"
    images.mkdir(mode=0o700)
    for part in parts:
        image = images / (part + ".img")
        shutil.copyfile(args.images / image.name, image)
        with image.open("rb") as f:
            require(digest(f) == receipt["boot_sha256"][part], "prepared boot digest differs: " + part)
    raw = args.directory / "root.img"
    zipped = hashlib.sha256()
    with args.rootfs.open("rb") as stream, subprocess.Popen(
        ["zstd", "-qd", "--sparse", "-o", raw], stdin=subprocess.PIPE
    ) as decoder:
        while block := stream.read(1024 * 1024):
            zipped.update(block)
            decoder.stdin.write(block)
        decoder.stdin.close()
        require(decoder.wait() == 0 and zipped.hexdigest() == receipt["root_sha256"], "prepared compressed root digest differs")
    with raw.open("rb") as f:
        require(digest(f) == receipt["raw_sha256"], "prepared ext4 digest differs")
    check = subprocess.check_output(["dumpe2fs", "-h", raw], stderr=subprocess.DEVNULL)
    require(re.search(rb"^Filesystem volume name:\s*omamobile-root$", check, re.M), "wrong prepared filesystem label")
    subprocess.run(["e2fsck", "-fn", raw], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    inspect_root(raw, receipt, receipt["purpose"] == "production")
    (args.directory / "recovery.pub").write_text(receipt["recovery_public_key"] + "\n", encoding="ascii")


def rescue_keys(archive):
    # cpio -it lists only the first member archive. Rescue images can contain a
    # second appended newc archive, so walk every header through the padding.
    data = archive.read_bytes()
    offset = 0
    result = []
    while offset < len(data):
        if data[offset] == 0:
            offset += 1
            continue
        require(data[offset:offset + 6] in (b"070701", b"070702"), "unexpected rescue cpio header")
        fields = [int(data[i:i + 8], 16) for i in range(offset + 6, offset + 110, 8)]
        name_end = offset + 110 + fields[11]
        require(name_end <= len(data) and data[name_end - 1] == 0, "invalid rescue cpio name")
        name = data[offset + 110:name_end - 1]
        start = (name_end + 3) & ~3
        end = start + fields[6]
        require(end <= len(data) and not name.startswith(b"/") and b".." not in name.split(b"/"), "invalid rescue cpio entry")
        name = b"/".join(part for part in name.split(b"/") if part not in (b"", b"."))
        if name.endswith(b"/authorized_keys"):
            require(name == b"root/.ssh/authorized_keys", "unverifiable rescue key path")
        if name in (b"root", b"root/.ssh"):
            require(stat.S_ISDIR(fields[1]), "unexpected rescue key directory type")
        if name == b"root/.ssh/authorized_keys":
            require(stat.S_ISREG(fields[1]) and fields[4] == 1 and fields[2:4] == [0, 0]
                    and stat.S_IMODE(fields[1]) == 0o600, "invalid rescue key metadata")
            result.append(data[start:end])
        offset = (end + 3) & ~3
    return result


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    check = sub.add_parser("stage")
    for name in ("receipt", "rootfs", "images", "directory"):
        check.add_argument("--" + name, type=Path, required=True)
    for name in ("device", "serial", "partitions"):
        check.add_argument("--" + name, required=True)
    check.add_argument("--writing", action="store_true")
    ramdisk = sub.add_parser("ramdisk")
    ramdisk.add_argument("archive", type=Path)
    ramdisk.add_argument("--key", type=Path)
    args = p.parse_args()
    if args.command == "stage":
        stage(args)
    else:
        expected = [args.key.read_bytes()] if args.key else []
        require(rescue_keys(args.archive) == expected, "unapproved or missing rescue SSH authorization")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError) as exc:
        sys.exit("prepared-image: " + str(exc))
