import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { createConnection } from 'node:net';

const source = `import json,socket,sys
s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(4)
token=sys.argv[1]
print(json.dumps({'port':s.getsockname()[1]}),flush=True)
while True:
 c,_=s.accept()
 with c:
  data=b''
  while not data.endswith(b'\\n'):
   part=c.recv(1024)
   if not part: break
   data+=part
  command=data.decode().strip()
  if command==token+':challenge': c.sendall((token+':alive\\n').encode())
  elif command==token+':stop':
   c.sendall((token+':stopped\\n').encode()); break
s.close()`;

export async function startSentinel(python, observer) {
  const token = randomBytes(32).toString('hex');
  const child = spawn(python, ['-u', '-c', source, token], { stdio: ['ignore', 'pipe', 'inherit'] });
  const lines = createInterface({ input: child.stdout });
  const [line] = await once(lines, 'line');
  const { port } = JSON.parse(line);
  const birth = observer.point(child.pid);
  assert.equal(birth.status, 'LIVE');
  assert.ok(birth.birth);
  async function exchange(command, expected) {
    const socket = createConnection({ host: '127.0.0.1', port });
    const response = new Promise((resolve, reject) => {
      let data = '';
      socket.on('data', chunk => { data += chunk; if (data.includes('\n')) resolve(data.trim()); });
      socket.on('error', reject);
      socket.on('end', () => { if (!data.includes('\n')) reject(new Error('sentinel closed before response')); });
    });
    socket.write(`${token}:${command}\n`);
    assert.equal(await response, `${token}:${expected}`);
    socket.end();
  }
  return {
    async challenge() {
      await exchange('challenge', 'alive');
      const current = observer.point(child.pid);
      assert.equal(current.status, 'LIVE');
      assert.equal(current.birth, birth.birth);
    },
    async stop() {
      const exited = once(child, 'exit');
      await exchange('stop', 'stopped');
      await exited;
      lines.close();
    },
  };
}
