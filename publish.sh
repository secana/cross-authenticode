# Publish a new version of the cross-authenticode crate to crates.io
# Usage: ./publish.sh <version>
# Example: ./publish.sh 0.1.0

# Exit on error
set -e

# Check if the version was provided
if [ -z "$1" ]; then
    echo "Error: No version provided"
    echo "Usage: ./publish.sh <version>"
    exit 1
fi

# Check if the version is valid
if ! echo "$1" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+$"; then
    echo "Error: Invalid version"
    echo "Version must be in the format X.Y.Z"
    exit 1
fi

# Check if on main branch
if [ "$(git branch --show-current)" != "main" ]; then
    echo "Error: Not on main branch"
    exit 1
fi

# Check if the version is already in the Cargo.toml file
if grep -qE "^version = \"$1\"" Cargo.toml; then
    echo "Error: Version $1 is already in Cargo.toml"
    exit 1
fi

# Update the version in the Cargo.toml file
sed -i'' -e "s/^version = \".*\"/version = \"$1\"/" Cargo.toml

# Commit the changes
git add Cargo.toml
git commit -m "Release version to $1"

# Tag the commit
git tag "$1"

# Push the tag
git push origin "$1"

# Push the changes
git push
