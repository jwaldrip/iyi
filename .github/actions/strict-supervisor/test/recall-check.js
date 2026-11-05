// A process is certainly alive throughout a census only if its guaranteed lifetime
// covers that entire call. Observations are ordered by completion of each poll.
export function missingRecall(spawns, polls, slackNs = 20_000_000) {
  const missing = [];
  for (const spawn of spawns) {
    const end = (spawn.guaranteed_end_ns ?? spawn.spawn_ns + spawn.lifetime_ns) - slackNs;
    for (const poll of polls) {
      if (spawn.spawn_ns <= poll.start_ns && poll.end_ns <= end && !poll.committed.includes(spawn.pid)) {
        missing.push({ pid: spawn.pid, start_ns: poll.start_ns, end_ns: poll.end_ns });
      }
    }
  }
  return missing;
}
