# HominemAuth: the studio verbs (see .studio/STUDIO.md).
import '.studio/studio.just'

default:
    @just --list

# Resolve Swift packages; safe to repeat.
setup:
    swift package resolve

# Read-only checks: the Swift toolchain this package needs.
doctor:
    @command -v swift >/dev/null || { echo "swift is missing. Install Xcode."; exit 1; }
    @swift --version 2>&1 | head -n 1
    @echo "ok"

# Everything to pass before pushing.
check:
    swift test

run:
    @echo "not applicable here: HominemAuth is a library"

sim:
    @echo "not applicable here: HominemAuth is a library"

device:
    @echo "not applicable here: HominemAuth is a library"

e2e *flows:
    @echo "not applicable here: HominemAuth has no end-to-end flows"

testflight:
    @echo "not applicable here: HominemAuth is a library (release = a git tag and a CHANGELOG entry)"
