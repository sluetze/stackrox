#!/usr/bin/env bash
# Creates a tgz bundle of all binary artifacts needed for main-rhel

set -euo pipefail

die() {
    echo >&2 "$@"
    exit 1
}

image_exists() {
  if ! docker image inspect "$1" > /dev/null ; then
     die "Image file $1 not found."
  fi
}

extract_from_image() {
  local image=$1
  local src=$2
  local dst=$3

  [[ -n "$image" && -n "$src" && -n "$dst" ]] \
      || die "extract_from_image: <image> <src> <dst>"

  docker run -ii --rm --entrypoint /bin/sh "${image}" /dev/stdin \
  > "${dst}" <<EOF
set -e
cat < ${src}
EOF

  [[ -s $dst ]] || die "file extracted from image is empty: $dst"
}

INPUT_ROOT="$1"
DATA_IMAGE="$2"
OUTPUT_BUNDLE="$3"

[[ -n "$INPUT_ROOT" && -n "$DATA_IMAGE" && -n "$OUTPUT_BUNDLE" ]] \
    || die "Usage: $0 <input-root> <enc-data-image> <output-bundle>"
[[ -d "$INPUT_ROOT" ]] \
    || die "Input root directory doesn't exist or is not a directory."

# Verify image exists
image_exists "${DATA_IMAGE}"

# Create tmp directory with stackrox directory structure
bundle_root="$(mktemp -d)"
mkdir -p "${bundle_root}"/{assets/downloads/cli,stackrox/bin,ui}
chmod -R 755 "${bundle_root}"

# =============================================================================

# Add files to be included in the Dockerfile here. This includes artifacts that
# would be otherwise downloaded or included via a COPY command in the
# Dockerfile.

cp -p "${INPUT_ROOT}/central-entrypoint.sh" "${bundle_root}/stackrox/"
cp -p "${INPUT_ROOT}/bin/migrator"          "${bundle_root}/stackrox/bin/"
cp -p "${INPUT_ROOT}/bin/central"           "${bundle_root}/stackrox/"
cp -p "${INPUT_ROOT}/bin/compliance"        "${bundle_root}/stackrox/bin/"
cp -p "${INPUT_ROOT}/bin/roxctl"*           "${bundle_root}/assets/downloads/cli/"
cp -p "${INPUT_ROOT}/bin/kubernetes-sensor" "${bundle_root}/stackrox/bin/"
cp -p "${INPUT_ROOT}/bin/sensor-upgrader"   "${bundle_root}/stackrox/bin/"
cp -p "${INPUT_ROOT}/bin/admission-control" "${bundle_root}/stackrox/bin/"
cp -p "${INPUT_ROOT}/static-bin/"*          "${bundle_root}/stackrox/"
cp -pr "${INPUT_ROOT}/THIRD_PARTY_NOTICES"  "${bundle_root}/"
cp -pr "${INPUT_ROOT}/ui/build/"*           "${bundle_root}/ui/"

wget -q -O "${bundle_root}/telegraf" \
    "https://github.com/connorgorman/telegraf/releases/download/1.8.3.1%2B179-slim/telegraf"
chmod +x "${bundle_root}/telegraf"

# Extract and copy encrypted data file from container image
enc_file="stackrox-data.tgze"
extract_from_image "${DATA_IMAGE}" "${enc_file}" "${bundle_root}/stackrox/${enc_file}"

# =============================================================================

# Files should have owner/group equal to root:root
if tar --version | grep -q "gnu" ; then
  tar_chown_args=("--owner=root:0" "--group=root:0")
else
  tar_chown_args=("--uid=root:0" "--gid=root:0")
fi

# Create output bundle of all files in $bundle_root
tar cz "${tar_chown_args[@]}" --file "$OUTPUT_BUNDLE" --directory "${bundle_root}" .

# Create checksum
sha512sum "${OUTPUT_BUNDLE}" > "${OUTPUT_BUNDLE}.sha512"
sha512sum --check "${OUTPUT_BUNDLE}.sha512"

# Clean up after success
rm -r "${bundle_root}"
