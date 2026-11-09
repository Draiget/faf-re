// Keeps a pull request's automatic labels in step with its description, its
// changed files and whether it still merges into its base branch.
// Run by .github/workflows/pr-labels.yml through actions/github-script.
//
// Labels it decides (names must exist in .github/labels.json):
//   sim: ...            the ticked "Sim impact" box; "sim: not sure" when "None"
//                       is ticked but the PR changes code that runs in the sim.
//   area: ...           from the changed paths (see AREAS).
//   parity: at risk     "behaviour change" or "not sure" is the sim label, or the
//                       diff adds a sim console variable or sim command
//                       (TSimConVar, CSimConFunc, CSimConCommand, a "DoSimCommand"
//                       alias): those reach every player through the command stream.
//   recovery            the diff adds an "Address: 0x..." anchor.
//   documentation       every changed file is documentation.
//   needs template      no "## Sim impact" section, or not exactly one box ticked.
//   needs replay check  the ticked box needs played replays and the Testing table lists none.
//   merge conflict      GitHub reports the PR no longer merges into its base.
//
// Reviewers win. A label whose last add or remove was done by a person is left
// alone, and once a person sets a sim label the bot stops choosing one (and drops
// its own). "merge conflict" and "needs template" are facts, not opinions, so the
// bot keeps those two right whoever set them.

const fs = require('fs');
const path = require('path');
const {
  SIM_PATHS,
  NEEDS_REPLAYS,
  stripComments,
  section,
  tickedOptions,
  replayRows,
} = require('./pr-sim-impact.js');

const CATALOG = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'labels.json'), 'utf8'));
const KNOWN = new Set(CATALOG.labels.map((l) => l.name));

const SIM_LABELS = {
  none: 'sim: none',
  replayNet: 'sim: replay/net only',
  simSame: 'sim: same behaviour',
  simChanged: 'sim: behaviour change',
  unsure: 'sim: not sure',
};

const AREAS = {
  'area: audio': [/^src\/moho\/audio\//],
  'area: render': [/^src\/moho\/(render|effects|particles|mesh|terrain)\//, /^src\/gpg\/gal\//],
  'area: ui': [/^src\/moho\/ui\//],
  // The sim paths without the Lua VM, which has its own area.
  'area: sim': SIM_PATHS.filter((p) => !p.test('src/lua/x')),
  'area: net': [/^src\/moho\/net\//],
  'area: replay': [/^src\/.*replay[^/]*$/i],
  'area: movie': [/^src\/moho\/movie\//],
  'area: lua': [/^src\/lua\//, /^src\/moho\/lua\//],
  'area: build': [
    /(^|\/)CMakeLists\.txt$/,
    /^cmake\//,
    /^src\/sources\.cmake$/,
    /\.vcxproj(\.filters)?$/,
    /^build[^/]*\.ps1$/,
    /^\.github\/workflows\//,
  ],
};

const DOC_PATHS = [/^docs\//, /\.md$/i];
const ADDED_ADDRESS_ANCHOR = /^\+.*\bAddress:\s*0x[0-9A-Fa-f]{6,8}\b/m;

const PARITY_AT_RISK = 'parity: at risk';
// Sim labels that mean the sim may compute something retail does not.
const RISKY_SIM_LABELS = new Set([SIM_LABELS.simChanged, SIM_LABELS.unsure]);
// An added line that declares a sim console variable or command.
const ADDED_SIM_SETTING = /^\+.*(\bTSimConVar\s*<|\bCSimConFunc\b|\bCSimConCommand\s*\(|"DoSimCommand\s)/m;
const isSourceFile = (name) => /^src\/.*\.(c|cc|cpp|h|hpp|inl)$/.test(name);

const MERGE_CONFLICT = 'merge conflict';
// Labels the bot keeps correct even when a person set or removed them.
const AUTHORITATIVE = new Set([MERGE_CONFLICT, 'needs template']);
// Every label the bot may add or remove on a PR event.
const MANAGED = new Set([
  ...Object.values(SIM_LABELS),
  ...Object.keys(AREAS),
  PARITY_AT_RISK,
  'recovery',
  'documentation',
  'needs template',
  'needs replay check',
  MERGE_CONFLICT,
]);

for (const name of MANAGED) {
  if (!KNOWN.has(name)) {
    // GitHub's add-labels endpoint would silently create it with a random colour.
    throw new Error(`pr-labels.js uses "${name}", which is not in .github/labels.json`);
  }
}

const isSim = (name) => name.startsWith('sim: ');

// Labels the description and the diff call for. Pure, so it can be tested
// without GitHub. `files` are pulls.listFiles entries ({ filename, patch }).
function wantedLabels(rawBody, files) {
  const want = new Set();
  const body = stripComments(rawBody ?? '');
  const names = files.map((f) => f.filename);

  const impact = section(body, 'Sim impact');
  const ticked = impact === null ? [] : tickedOptions(impact);
  const choice = ticked.length === 1 ? ticked[0] : null;
  if (choice !== null && SIM_LABELS[choice]) {
    const touchesSim = names.some((f) => SIM_PATHS.some((p) => p.test(f)));
    want.add(choice === 'none' && touchesSim ? 'sim: not sure' : SIM_LABELS[choice]);
    if (NEEDS_REPLAYS.includes(choice) && replayRows(section(body, 'Testing') ?? '').length === 0) {
      want.add('needs replay check');
    }
  } else {
    want.add('needs template');
  }

  for (const [label, patterns] of Object.entries(AREAS)) {
    if (names.some((f) => patterns.some((p) => p.test(f)))) want.add(label);
  }
  const addsSimSetting = files.some((f) => isSourceFile(f.filename) && f.patch && ADDED_SIM_SETTING.test(f.patch));
  if (addsSimSetting || [...want].some((name) => RISKY_SIM_LABELS.has(name))) want.add(PARITY_AT_RISK);
  if (files.some((f) => f.patch && ADDED_ADDRESS_ANCHOR.test(f.patch))) want.add('recovery');
  if (names.length > 0 && names.every((f) => DOC_PATHS.some((p) => p.test(f)))) want.add('documentation');
  return want;
}

function isBot(actor) {
  return Boolean(actor) && (actor.type === 'Bot' || /\[bot\]$/.test(actor.login ?? ''));
}

// Labels to add and remove. `decide` is the set of names this run has an opinion
// on; `lastActor` maps a label name to whoever last added or removed it.
function diffLabels({ current, want, decide, lastActor }) {
  const byPerson = (name) => lastActor.has(name) && !isBot(lastActor.get(name));
  const personSetSim = [...current].some((name) => isSim(name) && byPerson(name));
  const add = [];
  const remove = [];
  for (const name of decide) {
    if (!AUTHORITATIVE.has(name) && byPerson(name)) continue;
    const wanted = want.has(name) && !(isSim(name) && personSetSim);
    if (wanted && !current.has(name)) add.push(name);
    if (!wanted && current.has(name)) remove.push(name);
  }
  return { add, remove };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// true: conflicts with the base; false: merges cleanly; null: GitHub has not
// worked it out yet (it computes mergeability in the background after a push).
async function hasConflict(github, repo, number) {
  for (let attempt = 0; attempt < 6; attempt++) {
    const { data } = await github.rest.pulls.get({ ...repo, pull_number: number });
    if (data.state !== 'open') return null;
    if (data.mergeable !== null) return data.mergeable === false;
    await sleep(5000);
  }
  return null;
}

async function lastLabelActors(github, repo, number) {
  const events = await github.paginate(github.rest.issues.listEvents, {
    ...repo,
    issue_number: number,
    per_page: 100,
  });
  const last = new Map();
  for (const e of events) {
    if ((e.event === 'labeled' || e.event === 'unlabeled') && e.label) last.set(e.label.name, e.actor);
  }
  return last;
}

async function syncLabels({ github, core, repo, number, want, decide }) {
  const currentLabels = await github.paginate(github.rest.issues.listLabelsOnIssue, {
    ...repo,
    issue_number: number,
    per_page: 100,
  });
  const current = new Set(currentLabels.map((l) => l.name));
  const lastActor = await lastLabelActors(github, repo, number);
  const { add, remove } = diffLabels({ current, want, decide, lastActor });

  if (add.length > 0) {
    await github.rest.issues.addLabels({ ...repo, issue_number: number, labels: add });
  }
  for (const name of remove) {
    try {
      await github.rest.issues.removeLabel({ ...repo, issue_number: number, name });
    } catch (err) {
      if (err.status !== 404) throw err;
    }
  }
  core.info(
    `#${number}: ` +
      (add.length + remove.length === 0
        ? 'labels already up to date'
        : [add.length ? `added ${add.join(', ')}` : '', remove.length ? `removed ${remove.join(', ')}` : '']
            .filter(Boolean)
            .join('; ')),
  );
}

// A PR was opened, edited, reopened or pushed to: recompute everything.
async function onPullRequest({ github, context, core, repo }) {
  const number = context.payload.pull_request.number;
  // Re-read the PR: the payload can be older than the latest edit.
  const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
  const files = await github.paginate(github.rest.pulls.listFiles, { ...repo, pull_number: number, per_page: 100 });

  const want = wantedLabels(pr.body, files);
  const decide = new Set(MANAGED);
  const conflict = await hasConflict(github, repo, number);
  if (conflict === null) {
    decide.delete(MERGE_CONFLICT);
    core.info(`#${number}: GitHub has not computed mergeability yet; leaving "${MERGE_CONFLICT}" as it is`);
  } else if (conflict) {
    want.add(MERGE_CONFLICT);
  }
  await syncLabels({ github, core, repo, number, want, decide });
}

// The base branch moved: only merge conflicts can have changed.
async function onPush({ github, context, core, repo }) {
  const base = context.ref.replace(/^refs\/heads\//, '');
  const prs = await github.paginate(github.rest.pulls.list, { ...repo, state: 'open', base, per_page: 100 });
  for (const pr of prs) {
    const conflict = await hasConflict(github, repo, pr.number);
    if (conflict === null) {
      core.info(`#${pr.number}: mergeability unknown, skipped`);
      continue;
    }
    await syncLabels({
      github,
      core,
      repo,
      number: pr.number,
      want: new Set(conflict ? [MERGE_CONFLICT] : []),
      decide: new Set([MERGE_CONFLICT]),
    });
  }
}

module.exports = async ({ github, context, core }) => {
  const repo = { owner: context.repo.owner, repo: context.repo.repo };
  if (context.eventName === 'push') {
    await onPush({ github, context, core, repo });
  } else {
    await onPullRequest({ github, context, core, repo });
  }
};
module.exports.wantedLabels = wantedLabels;
module.exports.diffLabels = diffLabels;
