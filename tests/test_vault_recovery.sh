#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_HOME="$(mktemp -d)"
trap 'rm -rf "$TEST_HOME"' EXIT

clear_screen() { :; }
sleep() { :; }

# shellcheck source=../lib/vault.sh
source "$ROOT_DIR/lib/vault.sh"

assert_quarantined() {
    local original="$1" matches=()
    [[ ! -e "$VAULT_FILE" ]]
    matches=("${VAULT_FILE}.corrupt."*)
    [[ "${#matches[@]}" == 1 ]]
    [[ "$(<"${matches[0]}")" == "$original" ]]
    [[ "$(stat -c '%a' "${matches[0]}")" == 600 ]]
}

# Use the real Ansible Vault implementation so these tests cover the format
# and password handling used by the application.
write_encrypted_vault() {
    local state="$1" password="$2" output="$3"
    printf '%s\n' "$state" >"$TEST_HOME/plain.json"
    printf '%s\n' "$password" >"$TEST_HOME/password"
    ansible-vault encrypt \
        --vault-password-file "$TEST_HOME/password" \
        --output "$output" "$TEST_HOME/plain.json" >/dev/null
}

# A valid Vault opens and remains in place.
VAULT_FILE="$TEST_HOME/valid-vault.json"
VAULT_PASSWORD_FILE=""
write_encrypted_vault '{"nodes":{}}' 'test-password' "$VAULT_FILE"
read_secret() {
    REPLY='test-password'
    return 0
}
ensure_vault_password_file
[[ -f "$VAULT_FILE" ]]
[[ -f "$VAULT_PASSWORD_FILE" ]]
rm -f "$VAULT_PASSWORD_FILE"
VAULT_PASSWORD_FILE=""

# A wrong password fails after the normal retry limit without quarantining data.
VAULT_FILE="$TEST_HOME/wrong-password-vault.json"
VAULT_PASSWORD_FILE=""
write_encrypted_vault '{"nodes":{}}' 'correct-password' "$VAULT_FILE"
read_secret() {
    REPLY='wrong-password'
    return 0
}
if ensure_vault_password_file; then
    printf '%s\n' 'Wrong Vault password unexpectedly opened.' >&2
    exit 1
fi
[[ -f "$VAULT_FILE" ]]
if compgen -G "${VAULT_FILE}.corrupt.*" >/dev/null; then
    printf '%s\n' 'Wrong password quarantined a valid Vault.' >&2
    exit 1
fi

# Invalid ciphertext is preserved under a timestamped quarantine name.
VAULT_FILE="$TEST_HOME/invalid-format-vault.json"
VAULT_PASSWORD_FILE=""
printf '%s\n' 'not an Ansible Vault' >"$VAULT_FILE"
if ensure_vault_password_file; then
    printf '%s\n' 'Invalid ciphertext unexpectedly opened.' >&2
    exit 1
fi
assert_quarantined 'not an Ansible Vault'

# Valid encryption with invalid JSON state is also quarantined without data loss.
VAULT_FILE="$TEST_HOME/invalid-state-vault.json"
VAULT_PASSWORD_FILE=""
write_encrypted_vault '{"unexpected":true}' 'test-password' "$VAULT_FILE"
invalid_state_ciphertext="$(<"$VAULT_FILE")"
read_secret() {
    REPLY='test-password'
    return 0
}
if ensure_vault_password_file; then
    printf '%s\n' 'Invalid decrypted state unexpectedly opened.' >&2
    exit 1
fi
assert_quarantined "$invalid_state_ciphertext"

# Labeled Ansible Vault headers are accepted.
VAULT_FILE="$TEST_HOME/labeled-vault.json"
printf '%s\n' '$ANSIBLE_VAULT;1.2;AES256;production' '00' >"$VAULT_FILE"
vault_ciphertext_valid

printf '%s\n' 'Vault recovery tests passed.'
