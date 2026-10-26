# HominemAuth: the studio verbs live in project-installed skills (see skills-lock.json).
SKILLS_DIR := justfile_directory() / ".agents/skills"

# Installed skill set version.
studio-version:
    @cat "{{ SKILLS_DIR }}/studio-dev/scripts/VERSION"

# Restore the installed skills from skills-lock.json.
studio-update:
    cd "{{ justfile_directory() }}" && npx -y skills experimental_install --yes

# Fail when an installed skill is missing or the lockfile is.
studio-check:
    @test -f "{{ SKILLS_DIR }}/ship-ios/SKILL.md" || (echo "missing ship-ios: run just studio-update"; exit 1)
    @test -f "{{ SKILLS_DIR }}/studio-dev/SKILL.md" || (echo "missing studio-dev: run just studio-update"; exit 1)
    @test -f "{{ justfile_directory() }}/skills-lock.json" || (echo "missing skills-lock.json"; exit 1)
    @echo "skills ok"

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
