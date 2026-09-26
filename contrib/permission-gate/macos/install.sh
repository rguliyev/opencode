#!/bin/sh
set -eu

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This installer only runs on macOS." >&2
  exit 1
fi

case "$(uname -m)" in
  arm64) binary=bin/darwin-arm64/opencode ;;
  x86_64) binary=bin/darwin-x64/opencode ;;
  *) echo "Unsupported Mac architecture: $(uname -m)" >&2; exit 1 ;;
esac

package_dir=$(CDPATH='' cd "$(dirname "$0")" && pwd -P)
cd "$package_dir"
if [ ! -f SHA256SUMS ] || [ ! -f "$binary" ]; then
  echo "The package is missing its checksum manifest or $binary." >&2
  exit 1
fi

expected=$(awk -v name="$binary" '$2 == name { print $1 }' SHA256SUMS)
actual=$(shasum -a 256 "$binary" | awk '{ print $1 }')
if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
  echo "Package checksum verification failed; nothing was installed." >&2
  exit 1
fi

install_dir="$HOME/src/bin"
destination="$install_dir/opencode"
mkdir -p "$install_dir"
temporary=$(mktemp "$install_dir/.opencode.XXXXXX")
trap 'rm -f "$temporary"' 0 1 2 3 15
cp "$binary" "$temporary"
chmod 0755 "$temporary"

if [ -e "$destination" ] || [ -L "$destination" ]; then
  backup=$(mktemp "$destination.backup.XXXXXX")
  cp -p "$destination" "$backup"
  echo "Previous opencode saved as $backup"
fi

mv -f "$temporary" "$destination"
trap - 0 1 2 3 15

echo "Installed $destination"
echo "Use: $destination attach <your-current-server-URL>"
resolved=$(command -v opencode 2>/dev/null || true)
if [ "$resolved" != "$destination" ]; then
  echo "Your PATH currently selects ${resolved:-no opencode} instead of $destination."
  echo "Use the full path above or put $install_dir first in PATH."
fi
