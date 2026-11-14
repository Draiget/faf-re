// Checks a pull request's description against .github/pull_request_template.md,
// CONTRIBUTING.md and docs/PR_REPLAY_CHECK.md:
//   - the "Evidence" section says what shows the problem and the fix;
//   - exactly one sim impact box is ticked;
//   - "None" is not ticked while the PR changes code that runs in the sim;
//   - a PR that changes anything but documentation and CI lists played replays
//     on both x64 and x86 (MIN_REPLAYS_PER_ARCH each).
// Run by .github/workflows/pr-sim-impact.yml through actions/github-script.

// Paths whose code runs in the sim (see the hint in the template).
const SIM_PATHS = [
  /^src\/moho\/(sim|unit|ai|entity|command|collision|path|projectile|vision|script|math)\//,
  /^src\/lua\//,
  /^src\/legacy\/math\//,
];

// Files that change neither the game nor its build: a PR that only touches
// these needs no replays.
const NO_REPLAY_PATHS = [/^docs\//, /\.md$/i, /^\.github\//, /^LICENSE/];

// Sim impact options, by the bold label in the template.
const OPTIONS = {
  none: /^None\b/i,
  replayNet: /^Replay or network only\b/i,
  simSame: /^Sim code touched\b/i,
  simChanged: /^Sim behaviour changes\b/i,
  unsure: /^Not sure\b/i,
};
// Options that need replays even when every changed file is documentation.
const NEEDS_REPLAYS = ['replayNet', 'simSame', 'simChanged'];

// Played replays each architecture needs in the Testing table.
const ARCHES = ['x64', 'x86'];
const MIN_REPLAYS_PER_ARCH = 3;

// The Evidence section needs more than a word or two.
const MIN_EVIDENCE_CHARS = 40;

function stripComments(text) {
  return text.replace(/<!--[\s\S]*?-->/g, '');
}

// Body of the "## <title>" section, up to the next "## " heading.
function section(body, title) {
  const lines = body.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^##\\s+${title}\\b`, 'i').test(l));
  if (start < 0) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => /^##\s/.test(l));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

function tickedOptions(impact) {
  const ticked = [];
  for (const m of impact.matchAll(/^\s*[-*]\s*\[[xX]\]\s*\*\*(.+?)\*\*/gm)) {
    const key = Object.keys(OPTIONS).find((k) => OPTIONS[k].test(m[1].trim()));
    ticked.push(key ?? m[1].trim());
  }
  return ticked;
}

// The replay ID in a table cell: bare digits, or written as code, bold or a
// link (`26902315`, **26902315**, [26902315](https://...)).
function replayId(cell) {
  const text = cell.replace(/[`*_]/g, '').replace(/^\[([^\]]*)\]\([^)]*\)$/, '$1').trim();
  return /^\d{6,}$/.test(text) ? text : null;
}

const tableCells = (line) =>
  line
    .trim()
    .replace(/^\||\|$/g, '')
    .split('|')
    .map((c) => c.trim());

// Rows of the testing table with a replay ID and a filled result cell, as
// { id, arch }. `arch` is "x64", "x86" or the cell as written.
function replayRows(testing) {
  const lines = testing.split(/\r?\n/).filter((l) => l.trim().startsWith('|'));
  const header = lines.length > 0 ? tableCells(lines[0]).map((c) => c.replace(/[`*_]/g, '').toLowerCase()) : [];
  const archColumn = header.indexOf('arch') >= 0 ? header.indexOf('arch') : 1;
  return lines
    .map(tableCells)
    .filter((cells) => replayId(cells[0]) !== null && cells[cells.length - 1] !== '')
    .map((cells) => {
      const arch = (cells[archColumn] ?? '').replace(/[`*_]/g, '').trim().toLowerCase();
      return { id: replayId(cells[0]), arch: arch === 'x32' || arch === 'win32' ? 'x86' : arch };
    });
}

// Whether the PR must list played replays: its box says so, or it changes
// something besides documentation and CI.
function needsReplays(choice, files) {
  return NEEDS_REPLAYS.includes(choice) || files.some((f) => !NO_REPLAY_PATHS.some((p) => p.test(f)));
}

// What the Testing table lacks, as messages; empty when it has enough.
function replayProblems(body, files, choice) {
  if (!needsReplays(choice, files)) return [];
  const rows = replayRows(section(body, 'Testing') ?? '');
  const problems = [];
  for (const arch of ARCHES) {
    const played = new Set(rows.filter((r) => r.arch === arch).map((r) => r.id)).size;
    if (played < MIN_REPLAYS_PER_ARCH) {
      problems.push(
        `The "Testing" table lists ${played} replay(s) played on ${arch}; every PR that changes more than ` +
          `documentation and CI needs at least ${MIN_REPLAYS_PER_ARCH} different replays on x64 and on x86 ` +
          '(replay ID, Arch and result in each row). See docs/PR_REPLAY_CHECK.md.',
      );
    }
  }
  return problems;
}

// What the Evidence section lacks, as messages; empty when it is filled in.
function evidenceProblems(body) {
  const evidence = section(body, 'Evidence');
  if (evidence === null) {
    return ['The PR description has no "## Evidence" section. Use the pull request template.'];
  }
  if (evidence.replace(/\s+/g, '').length < MIN_EVIDENCE_CHARS) {
    return [
      'The "Evidence" section is empty. Say what shows the problem and what shows the change fixes it ' +
        '(replay and beat, log lines, crash stack, binary addresses, screenshots, test names).',
    ];
  }
  return [];
}

// Returns a list of error messages; empty means the check passes.
function check(rawBody, files) {
  const body = stripComments(rawBody ?? '');
  const errors = evidenceProblems(body);

  const impact = section(body, 'Sim impact');
  if (impact === null) {
    return [...errors, 'The PR description has no "## Sim impact" section. Use the pull request template.'];
  }

  const ticked = tickedOptions(impact);
  if (ticked.length !== 1) {
    return [...errors, `Tick exactly one box under "Sim impact" (ticked: ${ticked.length}).`];
  }
  const [choice] = ticked;

  const simFiles = files.filter((f) => SIM_PATHS.some((p) => p.test(f)));
  if (choice === 'none' && simFiles.length > 0) {
    errors.push(
      `"None" is ticked, but the PR changes code that runs in the sim: ${simFiles.slice(0, 10).join(', ')}` +
        `${simFiles.length > 10 ? ` and ${simFiles.length - 10} more` : ''}. ` +
        'Tick the option that fits, or "Not sure".',
    );
  }

  errors.push(...replayProblems(body, files, choice));
  return errors;
}

module.exports = async ({ github, context, core }) => {
  const pr = context.payload.pull_request;
  const files = await github.paginate(github.rest.pulls.listFiles, {
    owner: context.repo.owner,
    repo: context.repo.repo,
    pull_number: pr.number,
    per_page: 100,
  });
  const errors = check(pr.body, files.map((f) => f.filename));
  if (errors.length > 0) {
    core.setFailed(errors.join('\n'));
  } else {
    core.info('Evidence, sim impact and testing sections are filled in.');
  }
};
module.exports.check = check;
// Shared with pr-labels.js, so labels and this check read the template the same way.
Object.assign(module.exports, {
  SIM_PATHS,
  NEEDS_REPLAYS,
  stripComments,
  section,
  tickedOptions,
  replayRows,
  replayProblems,
  evidenceProblems,
});
