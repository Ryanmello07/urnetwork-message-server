#!/usr/bin/env bash
# Usage: bash scripts/siblings.sh [--check|--verify] <name>...
#        bash scripts/siblings.sh --self-test
#
# The sibling checkouts go.mod replaces to, at the commits scripts/siblings.txt pins. The pin file's
# format and these rules are github.com/urnetwork/message's own (its scripts/siblings.sh), so one
# reading serves both repositories.
#
#   (no flag)    clone each named sibling pinned in scripts/siblings.txt into ../<name>, at its
#                pinned commit, with core.autocrlf=false, so a sibling is ONE commit and never a
#                moving branch;
#   --check      validate the named pins and clone nothing;
#   --verify     require ../<name> to be a git checkout whose HEAD is the pinned commit and whose
#                tracked files are unmodified. Run it before `go test` on any machine, with or
#                without a CI service:
#
#                    bash scripts/siblings.sh --verify message connect glog gvisor
#
#   --self-test  this script's own controls: each refusal below, and the acceptance beside it, on
#                pin files and throwaway checkouts written for it. It fetches nothing.
#
# It refuses, before cloning or accepting anything:
#   - a name the file does not pin, or pins twice: an unpinned sibling is the failure this exists
#     for (this module's checks went red on 2026-10-05 on a connect commit nobody here made);
#   - a commit that is not a full 40-hex SHA (a branch name, a short SHA, a placeholder);
#   - a fetch source that is neither https://github.com/urnetwork/<repository>.git nor one of the
#     REVIEW SOURCES listed below, exactly.
# And, whenever it has a connect checkout in hand, a connect that still carries the messaging schema:
# protocol/message.proto, protocol/message.pb.go, or any protocol/*.pb.go that protoc-gen-go
# generated from message.proto. The .pb.go is what registers the schema at init, beside
# message/protocol's copy, and every test binary that links both panics; the .proto alone is a file
# the go command never compiles, so it is not the only thing asked about.
#
# THE PIN IS THE COMMIT, AND THE URL IS ONLY WHERE IT IS FETCHED FROM. A commit id names its content,
# so no fetch source can change what a pin builds; what the URL rule protects is that the pins can
# be fetched from the project's own repositories by anyone, for good.
#
# REVIEW SOURCES. This module's switch to github.com/urnetwork/message is the fourth of a set of
# pull requests that are built and tested together: the removals from urnetwork/sdk and
# urnetwork/connect, the import into urnetwork/message, and this one. It pins the heads of two of
# them, and those heads exist on the owner's forks before either is merged upstream, so until its
# pull request merges a head is fetched from the fork it was pushed to. Those forks are named here
# one by one, and nothing else outside urnetwork/ is accepted: not another repository of the same
# owner, not another owner's fork of the same repository. Every mode prints FORK and the URL beside
# such a pin, so a run against a commit the upstream repository does not hold yet says so each time.
#
# WHEN A PULL REQUEST MERGES (with a merge commit, so its head stays the commit it was), the pinned
# commit is in the upstream repository: change that sibling's URL in scripts/siblings.txt back to
# https://github.com/urnetwork/..., and delete its line here. The list is empty once both have
# merged, and --self-test then says that no review source is accepted.
#
# MESSAGE_SERVER_TEST_UNPINNED, a comma-separated list of names, lets --verify accept those siblings
# at whatever commit they are checked out at, placeholder pin or not. Each is printed as UNPINNED
# with both commits, so a run against unpinned siblings says it was one. SIBLINGS_FILE overrides the
# pin file; --self-test uses it.
set -euo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
pins="${SIBLINGS_FILE:-$here/scripts/siblings.txt}"

# The forks a pull request head under review may be fetched from, one URL per line.
review_sources="
"

# source_of <url>: prints "upstream" or "fork", or fails for a fetch source this script refuses.
# Every match here reads a here-string and never a pipe: under pipefail, a pipe into grep -q fails
# whenever grep stops reading early, which is exactly when it found what it was looking for.
source_of() {
  local url=$1
  if [ -z "$url" ]; then return 1; fi
  if grep -q '\.\.' <<<"$url"; then return 1; fi
  if grep -Eqx 'https://github\.com/urnetwork/[A-Za-z0-9_-][A-Za-z0-9_.-]*\.git' <<<"$url"; then
    echo upstream
    return 0
  fi
  if grep -qxF -- "$url" <<<"$review_sources"; then
    echo fork
    return 0
  fi
  return 1
}

# Why a connect checkout still carries the messaging schema, one reason a line, or nothing at all.
# grep reads each file itself, for the reason above.
schema_left_in() {
  local dir=$1 file
  if [ -e "$dir/protocol/message.proto" ]; then echo "protocol/message.proto is there"; fi
  if [ -e "$dir/protocol/message.pb.go" ]; then echo "protocol/message.pb.go is there"; fi
  for file in "$dir"/protocol/*.pb.go; do
    if [ -e "$file" ] && grep -q -x -e '// source: message.proto' -e $'// source: message.proto\r' "$file"; then
      echo "protocol/${file##*/} is generated from message.proto"
    fi
  done
  return 0
}

# The controls. Each runs a copy of this script, laid out as <scratch>/message-server/scripts/, on a
# pin file written for the control and on siblings made beside the copy with `git init`. It must
# end the way the control says AND print the line that says why: a refusal that fires for another
# reason is a broken control, and so is an acceptance that prints nothing.
selftest_scratch=""
self_test() {
  local failed=0 held=0 out got script ws sha url listed=0 index
  local fake=0123456789abcdef0123456789abcdef01234567
  local refused="neither https://github.com/urnetwork/ nor a listed review source"
  selftest_scratch=$(mktemp -d)
  trap 'if [ -n "$selftest_scratch" ]; then rm -rf "$selftest_scratch"; fi' EXIT
  ws="$selftest_scratch/ws"
  mkdir -p "$ws/message-server/scripts"
  cp "$0" "$ws/message-server/scripts/siblings.sh"
  script="$ws/message-server/scripts/siblings.sh"

  # pin <line>...: the pin file of the controls that follow.
  pin() { printf '%s\n' "$@" > "$selftest_scratch/pins"; }
  # expect <pass|fail> <title> <the line it must print> <names to run unpinned, or ''> <arguments...>
  expect() {
    local want=$1 title=$2 needle=$3 unpinned_names=$4
    shift 4
    if out=$(SIBLINGS_FILE="$selftest_scratch/pins" MESSAGE_SERVER_TEST_UNPINNED="$unpinned_names" bash "$script" "$@" 2>&1); then got=pass; else got=fail; fi
    if [ "$got" = "$want" ] && grep -qF -- "$needle" <<<"$out"; then
      held=$((held + 1))
      echo "  control: $title -> $got, as it must: $(grep -m 1 -F -- "$needle" <<<"$out")"
    else
      failed=$((failed + 1))
      echo "  CONTROL BROKEN: $title -> $got, want $want with: $needle"
      sed 's/^/    /' <<<"$out"
    fi
  }
  # commit <name> <subject>: everything in that sibling, committed, and its HEAD left in $sha.
  commit() {
    git -C "$ws/$1" add -A
    git -C "$ws/$1" -c user.name=control -c user.email=control@localhost -c commit.gpgsign=false commit -q -m "$2"
    sha=$(git -C "$ws/$1" rev-parse HEAD)
  }
  # checkout <name>: a sibling of one commit, beside the copy of this script.
  checkout() {
    git init -q "$ws/$1"
    git -C "$ws/$1" config core.autocrlf false
    printf 'module example.invalid/%s\n' "$1" > "$ws/$1/go.mod"
    commit "$1" "control: a sibling"
  }

  echo "the pin file's rules:"
  pin "one https://github.com/urnetwork/connect.git $fake"
  expect pass "a commit of an urnetwork repository" "(checked, not cloned)" '' --check one
  while IFS= read -r url; do
    if [ -z "$url" ]; then continue; fi
    listed=$((listed + 1))
    pin "one $url $fake"
    expect pass "a pull request head on the listed review source $url" "(checked, not cloned) FORK $url" '' --check one
    pin "one ${url%.git} $fake"
    expect fail "the same review source spelled without its .git" "$refused" '' --check one
  done <<<"$review_sources"
  if [ "$listed" -eq 0 ]; then
    echo "  no review source is listed, so none is accepted: every pin is fetched from urnetwork/"
  fi
  # The two forks this list named until their pull requests merged, on 2026-10-09. Each is refused
  # now, by the line that names it.
  for url in https://github.com/Ryanmello07/urmessage.git https://github.com/Ryanmello07/connect.git; do
    pin "one $url $fake"
    expect fail "a fork that was a review source until its pull request merged" "fetches from $url, which is $refused" '' --check one
  done
  pin "one https://github.com/Ryanmello07/unlisted.git $fake"
  expect fail "another repository of the same owner" "$refused" '' --check one
  pin "one https://github.com/someone-else/connect.git $fake"
  expect fail "another owner's fork of a repository that was listed" "$refused" '' --check one
  pin "one https://github.com/Ryanmello07/connect.git/../../someone-else/connect.git $fake"
  expect fail "a fork's URL with a path after it" "$refused" '' --check one
  pin "one https://github.com/Ryanmello07/connect $fake"
  expect fail "a fork's URL spelled another way" "$refused" '' --check one
  pin "one https://github.com.example.invalid/urnetwork/connect.git $fake"
  expect fail "an urnetwork URL on another host" "$refused" '' --check one
  pin "one http://github.com/urnetwork/connect.git $fake"
  expect fail "an urnetwork URL that is not https" "$refused" '' --check one
  pin "one https://github.com/urnetwork/../someone-else/connect.git $fake"
  expect fail "an urnetwork URL that climbs out" "$refused" '' --check one
  pin "one https://github.com/urnetwork/connect..git $fake"
  expect fail "an urnetwork URL with two dots and no path to climb" "$refused" '' --check one
  pin "one "
  expect fail "a pin with no URL at all" "$refused" '' --check one
  pin "one https://github.com/urnetwork/connect.git 0123456"
  expect fail "a short commit" "is not a full commit SHA" '' --check one
  pin "one https://github.com/urnetwork/connect.git main"
  expect fail "a branch name for a commit" "is not a full commit SHA" '' --check one
  pin "one https://github.com/urnetwork/connect.git FILL_IN_THE_HEAD"
  expect fail "a placeholder for a commit" "is not a full commit SHA" '' --check one
  pin "one https://github.com/urnetwork/connect.git $fake main"
  expect fail "a field after the commit" "has fields after the commit" '' --check one
  pin "one https://github.com/urnetwork/connect.git $fake" "one https://github.com/urnetwork/sdk.git $fake"
  expect fail "a name pinned twice" "pins 'one' 2 times" '' --check one
  pin "other https://github.com/urnetwork/connect.git $fake"
  expect fail "a name not pinned at all" "pins 'one' 0 times" '' --check one
  pin "one https://github.com/urnetwork/connect.git $fake"
  expect fail "a name that is a path" "is not a sibling's name" '' --check ../one
  expect fail "a name that is a pattern" "is not a sibling's name" '' --check 'o.e'
  printf 'one https://github.com/urnetwork/connect.git %s\r\n' "$fake" > "$selftest_scratch/pins"
  expect pass "a pin file with CRLF line endings" "one: https://github.com/urnetwork/connect.git $fake (checked, not cloned)" '' --check one

  echo "a checkout, held to its pin:"
  checkout one
  pin "one https://github.com/urnetwork/connect.git $sha"
  expect pass "a sibling at its pinned commit" "PINNED one $sha" '' --verify one
  # A fork that is not listed is refused in this mode as well, with the checkout at the very commit
  # its line pins: the fetch source is asked about before the checkout is looked at.
  pin "one https://github.com/Ryanmello07/connect.git $sha"
  expect fail "a sibling at its pin, the pin on a fork that was a review source" "fetches from https://github.com/Ryanmello07/connect.git, which is $refused" '' --verify one
  # With a review source listed, the same checkout is accepted and says where its pin was fetched from.
  url=$(grep -m 1 . <<<"$review_sources" || true)
  if [ -n "$url" ]; then
    pin "one $url $sha"
    expect pass "a sibling at a pin fetched from the listed review source $url" "PINNED one $sha FORK $url" '' --verify one
  fi
  pin "one https://github.com/urnetwork/connect.git $fake"
  expect fail "a sibling at another commit" "WRONG COMMIT one" '' --verify one
  expect pass "the same sibling, named unpinned" "UNPINNED one $sha (scripts/siblings.txt pins $fake)" 'one' --verify one
  expect fail "another sibling named unpinned, which excuses nothing here" "WRONG COMMIT one" 'two' --verify one
  pin "one https://github.com/urnetwork/connect.git FILL_IN_THE_HEAD"
  expect fail "a sibling whose pin is a placeholder" "UNPINNABLE one" '' --verify one
  expect pass "the same sibling, named unpinned" "UNPINNED one $sha (scripts/siblings.txt pins FILL_IN_THE_HEAD)" 'one' --verify one
  pin "one https://github.com/urnetwork/connect.git $sha"
  echo "// planted" >> "$ws/one/go.mod"
  expect fail "a sibling with a modified tracked file" "DIRTY one" '' --verify one
  expect fail "the same sibling, named unpinned: unpinned is not unchecked" "DIRTY one" 'one' --verify one
  git -C "$ws/one" checkout -q -- .
  expect pass "the same sibling, the file restored" "PINNED one $sha" '' --verify one
  expect fail "a clone onto a checkout that is already there" "already exists; refusing to build on a checkout this script did not make" '' one
  pin "two https://github.com/urnetwork/connect.git $sha"
  expect fail "a sibling that is not there" "MISSING two" '' --verify two
  # More modified files than a pipe holds: the list is read whole before its first lines are printed.
  checkout many
  mkdir "$ws/many/tracked"
  for index in $(seq 1 2000); do
    echo first > "$ws/many/tracked/a-file-with-a-name-long-enough-to-fill-a-pipe-quickly-$index.txt"
  done
  commit many "control: two thousand tracked files"
  for index in $(seq 1 2000); do
    echo second > "$ws/many/tracked/a-file-with-a-name-long-enough-to-fill-a-pipe-quickly-$index.txt"
  done
  pin "many https://github.com/urnetwork/connect.git $sha"
  expect fail "a sibling with two thousand modified tracked files" "DIRTY many: " '' --verify many
  expect fail "... and how many it did not print" "and 1995 more" '' --verify many

  echo "a connect that still carries the messaging schema:"
  checkout connect
  mkdir "$ws/connect/protocol"
  printf '%s\n' '// Code generated by protoc-gen-go. DO NOT EDIT.' '// source: frame.proto' '' '// message.proto is named here, in a comment, and nothing here is generated from it.' 'package protocol' > "$ws/connect/protocol/frame.pb.go"
  commit connect "control: connect after the removal"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect pass "a connect whose frame.pb.go names message.proto only in a comment" "PINNED connect $sha" '' --verify connect
  printf '%s\n' 'syntax = "proto3";' > "$ws/connect/protocol/message.proto"
  printf '%s\n' '// Code generated by protoc-gen-go. DO NOT EDIT.' '// source: message.proto' '' 'package protocol' > "$ws/connect/protocol/message.pb.go"
  commit connect "control: connect before the removal"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect fail "a connect from before the removal, at its pin" "SCHEMA connect" '' --verify connect
  expect fail "... for its message.proto" "protocol/message.proto is there" '' --verify connect
  expect fail "... for its message.pb.go" "protocol/message.pb.go is there" '' --verify connect
  expect fail "... and for what that file was generated from" "protocol/message.pb.go is generated from message.proto" '' --verify connect
  git -C "$ws/connect" rm -q protocol/message.proto
  commit connect "control: message.proto gone, message.pb.go kept"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect fail "message.proto deleted and message.pb.go kept" "protocol/message.pb.go is there" '' --verify connect
  git -C "$ws/connect" mv protocol/message.pb.go protocol/schema.pb.go
  commit connect "control: the generated schema under another name"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect fail "the generated schema renamed" "protocol/schema.pb.go is generated from message.proto" '' --verify connect
  expect fail "the same connect, named unpinned: the schema check is not a pin check" "SCHEMA connect" 'connect' --verify connect
  printf '%s\r\n' '// Code generated by protoc-gen-go. DO NOT EDIT.' '// source: message.proto' '' 'package protocol' > "$ws/connect/protocol/schema.pb.go"
  commit connect "control: the generated schema with CRLF line endings"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect fail "the generated schema with CRLF line endings" "protocol/schema.pb.go is generated from message.proto" '' --verify connect
  git -C "$ws/connect" rm -q protocol/schema.pb.go
  commit connect "control: the schema removed again"
  pin "connect https://github.com/urnetwork/connect.git $sha"
  expect pass "the same connect, the schema removed" "PINNED connect $sha" '' --verify connect

  echo "$held controls held, $failed broken"
  if [ "$failed" -ne 0 ] || [ "$held" -eq 0 ]; then return 1; fi
  return 0
}

mode=clone
case "${1:-}" in
  --check) mode=check; shift ;;
  --verify) mode=verify; shift ;;
  --self-test)
    echo "the sibling pins' own controls:"
    if self_test; then echo "SIBLINGS SELF-TEST PASS"; exit 0; fi
    echo "SIBLINGS SELF-TEST FAIL"
    exit 1
    ;;
esac
if [ "$#" -eq 0 ]; then echo "name at least one sibling"; exit 2; fi
unpinned=",${MESSAGE_SERVER_TEST_UNPINNED:-},"

status=0
for name in "$@"; do
  # A name is matched against the pin file as a pattern and becomes a directory beside this
  # repository, so it is held to what a sibling is called before it is used as either.
  if ! grep -Eqx '[A-Za-z0-9][A-Za-z0-9_-]*' <<<"$name"; then echo "'$name' is not a sibling's name"; exit 1; fi
  matches=$(tr -d '\r' < "$pins" | grep -cE "^${name}[[:space:]]" || true)
  if [ "$matches" -ne 1 ]; then echo "siblings.txt pins '$name' $matches times, want exactly once"; exit 1; fi
  line=$(tr -d '\r' < "$pins" | grep -E "^${name}[[:space:]]")
  read -r _ url sha extra <<<"$line"
  if [ -n "${extra:-}" ]; then echo "the pin for '$name' has fields after the commit: $extra"; exit 1; fi
  if ! from=$(source_of "$url"); then
    echo "the pin for '$name' fetches from $url, which is neither https://github.com/urnetwork/ nor a listed review source: refusing"; exit 1
  fi
  note=""
  if [ "$from" = fork ]; then note=" FORK $url"; fi
  pinned=1
  if ! grep -Eqx '[0-9a-f]{40}' <<<"$sha"; then pinned=0; fi
  accept_unpinned=0
  case "$unpinned" in *",$name,"*) accept_unpinned=1 ;; esac
  dir="$here/../$name"
  case "$mode" in
    check)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      echo "$name: $url $sha (checked, not cloned)$note"
      ;;
    clone)
      if [ "$pinned" = 0 ]; then echo "the pin for '$name' is not a full commit SHA: '$sha'"; exit 1; fi
      if [ -e "$dir" ]; then echo "$dir already exists; refusing to build on a checkout this script did not make"; exit 1; fi
      git init -q "$dir"
      git -C "$dir" config core.autocrlf false
      if ! git -C "$dir" fetch -q --depth 1 "$url" "$sha"; then
        echo "the pin for '$name' could not be fetched: $url does not serve $sha (not pushed there yet, or the URL is the wrong repository)"
        rm -rf "$dir"
        exit 1
      fi
      git -C "$dir" checkout -q --detach FETCH_HEAD
      test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
      if [ "$name" = connect ]; then
        left=$(schema_left_in "$dir")
        if [ -n "$left" ]; then
          echo "connect at $sha still carries the messaging schema; pin a connect after its messaging removal:"
          while IFS= read -r reason; do printf '  %s\n' "$reason"; done <<<"$left"
          exit 1
        fi
      fi
      echo "$name at $sha$note"
      ;;
    verify)
      if [ ! -d "$dir" ]; then echo "MISSING $name: $dir is not there"; status=1; continue; fi
      head=$(git -C "$dir" rev-parse --verify -q HEAD || true)
      if [ -z "$head" ]; then echo "MISSING $name: $dir is not a git checkout"; status=1; continue; fi
      # The list is read whole and cut afterwards. Cut inside the pipe, `git status | head`, the
      # reader leaves first when the list is long, git dies writing to it, and under pipefail this
      # script would stop here without a word about a sibling that is modified all over.
      dirty=$(git -C "$dir" status --porcelain --untracked-files=no)
      if [ -n "$dirty" ]; then
        changed_count=$(grep -c '' <<<"$dirty")
        echo "DIRTY $name: $dir has modified tracked files:"
        head -n 5 <<<"$dirty" | sed 's/^/  /'
        if [ "$changed_count" -gt 5 ]; then echo "  and $((changed_count - 5)) more"; fi
        status=1
        continue
      fi
      if [ "$name" = connect ]; then
        left=$(schema_left_in "$dir")
        if [ -n "$left" ]; then
          echo "SCHEMA $name: $dir at $head still carries the messaging schema, and every test binary linking both copies panics at init:"
          while IFS= read -r reason; do printf '  %s\n' "$reason"; done <<<"$left"
          status=1
          continue
        fi
      fi
      if [ "$pinned" = 1 ] && [ "$head" = "$sha" ]; then echo "PINNED $name $head$note"; continue; fi
      if [ "$accept_unpinned" = 1 ]; then echo "UNPINNED $name $head (scripts/siblings.txt pins $sha)"; continue; fi
      if [ "$pinned" = 0 ]; then
        echo "UNPINNABLE $name: scripts/siblings.txt pins '$sha', not a commit; fill the pin in, or name it in MESSAGE_SERVER_TEST_UNPINNED to run against $head"
      else
        echo "WRONG COMMIT $name: $dir is at $head, scripts/siblings.txt pins $sha"
      fi
      status=1
      ;;
  esac
done
exit $status
