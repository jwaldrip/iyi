import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(os.environ["GITHUB_WORKSPACE"])
WORK = Path(os.environ["RUNNER_TEMP"]) / "p4-corpus"
WORK.mkdir(parents=True, exist_ok=True)
WINDOWS = os.name == "nt"
REPOS = [
    ("iyilang/db", "7eb102404dd9b005856b328d8cfba71a9009b19c", "db.iyi", False),
    ("sdogruyol/iyi-web", "b6996efb3baa0b7160d27a0b5a1da4c873d7541e", "examples/templates.iyi", False),
    ("domify/slang", "26dcbedd0a80f7700f2e279680b468f7bbcd511b", "slang_test.iyi", False),
    ("Tuntii/kilim", "b98c1b69e2f23cac4f0b41d58c361619f0daf7ad", "kilim/sdl_canvas.iyi", True),
]


def command(args, cwd=ROOT, env=None):
    print("+", *args, flush=True)
    subprocess.run(args, cwd=cwd, env=env, check=True)


for repo, revision, _, _ in REPOS:
    target = WORK / repo
    target.mkdir(parents=True)
    command(["git", "init", "-q"], target)
    command(["git", "remote", "add", "origin", "https://github.com/" + repo + ".git"], target)
    command(["git", "fetch", "-q", "--depth", "1", "origin", revision], target)
    command(["git", "checkout", "-q", "--detach", "FETCH_HEAD"], target)

if WINDOWS:
    library = subprocess.check_output(["crystal", "env", "CRYSTAL_LIBRARY_PATH"], text=True).strip()
    os.environ["CRYSTAL_LIBRARY_PATH"] = library
    os.environ["LLVM_VERSION"] = (Path(library) / "llvm_VERSION").read_text().splitlines()[0].strip()
    command(["make", "-f", "Makefile.win", "crystal"])
else:
    command(["make", "-j2", "crystal", "collector=1"])

results = {}
for variant in ("changed", "master"):
    if variant == "master":
        command(["git", "checkout", "--detach", "c3dc702a13b7020e3d6d070ff4e4da95e60ae867"])
        (ROOT / "src/compiler/iyi/macros/methods.cr").touch()
    if WINDOWS:
        command(["make", "-f", "Makefile.win", "iyi"])
        compiler = ROOT / ".build/iyi.exe"
    else:
        command(["make", "-j2", "-o", ".build/crystal", "iyi", "collector=1"])
        compiler = ROOT / ".build/iyi"
    keep = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LIB", "LIBPATH", "INCLUDE", "CRYSTAL_LIBRARY_PATH", "LLVM_VERSION", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT")
    env = {name: os.environ[name] for name in keep if name in os.environ}
    env["IYI_PATH"] = "lib" + os.pathsep + str(ROOT / "src")
    env["IYI_CACHE_DIR"] = str(WORK / ("cache-" + variant))
    if WINDOWS:
        env["IYI_LIBRARY_PATH"] = os.environ["CRYSTAL_LIBRARY_PATH"]
    for repo, _, entry, no_codegen in REPOS:
        args = [str(compiler), "build", entry, "--force", "-o", str(WORK / ("output-" + variant))]
        if no_codegen:
            args.append("--no-codegen")
        try:
            p = subprocess.run(args, cwd=WORK / repo, env=env, text=True, capture_output=True, timeout=240)
            result = "pass" if p.returncode == 0 else "fail"
            if p.returncode:
                print(f"{variant} {repo} output:\n{(p.stderr or p.stdout)[-4000:]}", flush=True)
        except subprocess.TimeoutExpired:
            result = "timeout"
        results[(repo, variant)] = result
        print(f"RESULT {os.environ['RUNNER_OS']} {repo} {variant} {result}", flush=True)

print("| OS | Repository | Master | Change | Scope |")
print("| --- | --- | --- | --- | --- |")
regression = False
for repo, _, entry, no_codegen in REPOS:
    baseline, changed = results[(repo, "master")], results[(repo, "changed")]
    print(f"| {os.environ['RUNNER_OS']} | {repo} | {baseline} | {changed} | {entry}{' (no codegen)' if no_codegen else ''} |")
    regression |= baseline == "pass" and changed != "pass"
sys.exit(1 if regression else 0)
