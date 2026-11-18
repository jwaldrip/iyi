from pathlib import Path
import os
import re
import subprocess
import sys

repo = Path(sys.argv[1]).resolve()
compiler = Path(sys.argv[2]).resolve()
work = Path(sys.argv[3]).resolve()
work.mkdir(parents=True, exist_ok=True)
env = os.environ.copy()
env['IYI_PATH'] = str(repo / 'src')
env['IYI_LIBRARY_PATH'] = str(repo / 'lib')
env['IYI_CACHE_DIR'] = str(work / 'probe-cache')
cases = [
    ('selfhost_abstract_requirement_probe', 'bodies_abstract_requirement', [], ['refusals: 0', 'item.greet: String', 'abstract instances: 0']),
    ('selfhost_arg_arms_probe', 'sem_arms_union_overload', ['consume'], ['arms=2 cover=true', 'main#consume:Int32', 'main#consume:String']),
    ('selfhost_proc_scope_probe', 'sem_bodies_proc_scope', [], ['both proc helper instances typed']),
    ('selfhost_program_owner_probe', 'bodies_program_owner', [], ['*owner_probe<Int32>:Int32', '*owner_probe<String>:String', '*OwnerShadow#owner_probe<Int32>:Bool']),
    ('selfhost_recursion_target_probe', 'lowcall_recursion_top', [], None),
]
for name, fixture, extra, expected in cases:
    binary = work / (name + (".exe" if os.name == "nt" else ""))
    build = subprocess.run([str(compiler), 'build', '-o', str(binary), str(repo / 'bench' / (name + '.iyi'))], cwd=repo, env=env, capture_output=True, text=True)
    (work / (name + '.build.log')).write_text(build.stdout + build.stderr)
    if build.returncode:
        raise RuntimeError(f'{name}: build exited {build.returncode}; see {work / (name + ".build.log")}')
    run = subprocess.run([str(binary), str(repo / 'bench/fixtures' / (fixture + '.iyi')), str(repo / 'src'), *extra], cwd=repo, env=env, capture_output=True, text=True)
    (work / (name + '.run.log')).write_text(run.stdout + run.stderr)
    if run.returncode:
        raise RuntimeError(f'{name}: execution exited {run.returncode}; see {work / (name + ".run.log")}')
    if expected is None:
        assert re.search(r'^cycle_a target=.* typed-params Bool$', run.stdout, re.M), run.stdout
    else:
        assert sorted(run.stdout.splitlines()) == sorted(expected), run.stdout
    print(name + ': expected semantic result matched with its fixture arguments', flush=True)
print('All five argument-driven probes passed their existing semantic assertions', flush=True)
