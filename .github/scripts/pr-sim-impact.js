// Checks the "Sim impact" and "Testing" sections of a pull request against
// .github/pull_request_template.md and docs/PR_REPLAY_CHECK.md:
//   - exactly one sim impact box is ticked;
//   - "None" is not ticked while the PR changes code that runs in the sim;
//   - replay, network and sim changes list at least one played replay.
// Run by .github/workflows/pr-sim-impact.yml through actions/github-script.

// Paths whose code runs in the sim (see the hint in the template).
const SIM_PATHS = [
  /^src\/moho\/(sim|unit|ai|entity|command|collision|path|projectile|vision|script|math)\//,
  /^src\/lua\//,
  /^src\/legacy\/math\//,
];

// Sim impact options, by the bold label in the template.
const OPTIONS = {
  none: /^None\b/i,
  replayNet: /^Replay or network only\b/i,
  simSame: /^Sim code touched\b/i,
  simChanged: /^Sim behaviour changes\b/i,
  unsure: /^Not sure\b/i,
};
const NEEDS_REPLAYS = ['replayNet', 'simSame', 'simChanged'];

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

// Rows of the testing table with a replay ID and a filled result cell.
function replayRows(testing) {
  return testing
    .split(/\r?\n/)
    .filter((l) => l.trim().startsWith('|'))
    .map((l) => l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim()))
    .filter((cells) => /^\d{6,}$/.test(cells[0]) && cells[cells.length - 1] !== '');
}

// Returns a list of error messages; empty means the check passes.
function check(rawBody, files) {
  const body = stripComments(rawBody ?? '');
  const impact = section(body, 'Sim impact');
  if (impact === null) {
    return ['The PR description has no "## Sim impact" section. Use the pull request template.'];
  }

  const ticked = tickedOptions(impact);
  if (ticked.length !== 1) {
    return [`Tick exactly one box under "Sim impact" (ticked: ${ticked.length}).`];
  }
  const [choice] = ticked;
  const errors = [];

  const simFiles = files.filter((f) => SIM_PATHS.some((p) => p.test(f)));
  if (choice === 'none' && simFiles.length > 0) {
    errors.push(
      `"None" is ticked, but the PR changes code that runs in the sim: ${simFiles.slice(0, 10).join(', ')}` +
        `${simFiles.length > 10 ? ` and ${simFiles.length - 10} more` : ''}. ` +
        'Tick the option that fits, or "Not sure".',
    );
  }

  if (NEEDS_REPLAYS.includes(choice)) {
    const testing = section(body, 'Testing') ?? '';
    if (replayRows(testing).length === 0) {
      errors.push(
        'This change needs at least one played replay in the "Testing" table (replay ID and result). ' +
          'See docs/PR_REPLAY_CHECK.md.',
      );
    }
  }
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
    core.info('Sim impact and testing sections are filled in.');
  }
};
module.exports.check = check;
