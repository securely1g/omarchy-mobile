# Installing a parent-managed prepared image

A prepared installation consumes a preconfigured AArch64 ext4 root, its matching boot images, a trusted private receipt and the independently identified bootloader serial. Use the option from a repository checkout. Keep the signed-release installer for ordinary firstboot installations. A receipt identifies the parent's reviewed artifacts and target; it carries no upstream signature.

The prepared path checks a private copy of each boot image, decompresses and verifies the root, validates the filesystem and inspects the managed accounts and policy before contacting fastboot. It preserves the exact ext4 payload, including firstboot, boot-update and root SSH configuration. It appends the receipt's recovery public key to a copy of the original rescue ramdisk, checks the resulting archive and reports the personalized boot image SHA-256. The original ramdisk must contain no authorized keys. Hardware writes retain the usual serial, product, bootloader, slot, capacity, allowlist and typed confirmation checks. Shared userdata is erased on an actual installation.

## Private receipt, version 1

Prepare the receipt from independently reviewed build output and target enrollment. Keep it with the private device backup, outside Git. The installer reads a regular receipt owned by the invoking account or root, without group/other write access. Taking expected values from an unverified download or device does not authenticate them.

| Field | Value |
| --- | --- |
| `version`, `purpose` | Integer `1` and either `rehearsal` or `production`. Rehearsal permits only verify-only and dry-run. |
| `device`, `policy_device` | Device descriptor codename and the expected managed policy identity. |
| `serial_sha256` | Lowercase SHA-256 of the separately verified fastboot serial in ASCII without a newline. Supply that same serial using `--serial`. |
| `root_sha256`, `raw_sha256` | Lowercase SHA-256 of the compressed root and complete decompressed ext4 disk, respectively. |
| `boot_sha256` | Object mapping every name in the descriptor's `BOOT_IMAGES` to the SHA-256 of its original image (for example, key `boot` for `boot.img`). |
| `managed_files` | Object mapping exactly the absolute paths below to reviewed content hashes. |
| `parent_public_key`, `recovery_public_key` | Authorized parent maintenance and initramfs recovery Ed25519 public keys as single OpenSSH lines without comments. |
| `receiver_public_key` | Production enrollment's restricted Ed25519 policy receiver public key, distinct from the maintenance and recovery authorizations. |

The managed file hashes cover both native lock PAM files (`/etc/pam.d/omarchy-lock-password`, `/etc/pam.d/omarchy-lock-fingerprint`), their original PAM substacks (`/etc/pam.d/omarch-phone-screen-password-base`, `/etc/pam.d/omarch-phone-screen-fingerprint-base`), `/etc/omamobile/image-policy.json`, `/etc/omamobile/image-profile.json`, `/usr/local/libexec/omarch-phone-screen-time`, `/etc/sudoers.d/90-parent-admin`, and `/etc/sudoers.d/zz-parent-managed-daily`. The full raw-image digest also binds launcher files, the rest of the filesystem and its metadata.

## Verify the deployment copy

Use the same receipt and artifact paths for both invocations. Replace the shell variables with the intended private paths.

```sh
tools/install-phone --verify-only --device "$codename" --serial "$target_serial" \
  --images "$boot_directory" --rootfs "$root_image" --prepared-image "$receipt" --work "$private_work"
tools/install-phone --dry-run --device "$codename" --serial "$target_serial" \
  --images "$boot_directory" --rootfs "$root_image" --prepared-image "$receipt" --work "$private_work"
```

Use `--reinstall` only for a confirmed Omarchy installation on slot B, following the device reinstall runbook. Verify-only reads files locally. A standard dry run reads the connected handset's variables. Tests substitute an offline mock using `FASTBOOT`.

A production root must have device-specific daily and parent credentials, matching parent authorization, a ready restricted receiver for the expected policy device, and a validated native lock and five-app policy. Any existing root SSH authorization must belong to the approved maintenance or recovery key. The root's account provisioning record must record completed production enrollment and retirement of synthetic accounts. Set those markers only after provisioning and exercising the actual credentials. Qualify the exact deployment copy, including parent login, daily PIN, policy delivery, application visibility and recovery. Preserve the target's own calibration backup, current data, boot images and firmware/recovery evidence before an attended installation.
