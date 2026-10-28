// Checks commit titles and pull request titles against the Conventional Commits
// rules in CONTRIBUTING.md ("Commits and pull request titles").
//
// In CI it is run by .github/workflows/commit-lint.yml through actions/github-script:
//   pull request  the PR title (it becomes the commit title on a squash merge)
//                 and every non-merge commit in the PR;
//   push          every non-merge commit the push added to the branch.
//
// Locally, with Node 18 or later:
//   node .github/scripts/commit-lint.js "fix(ui): blips show when zoomed out"
//   node .github/scripts/commit-lint.js --file .git/COMMIT_EDITMSG   (a commit-msg hook)
//   node .github/scripts/commit-lint.js --range origin/master..HEAD

const TYPES = {
  feat: 'new behaviour or feature',
  fix: 'bug fix, including code brought back in line with the original binary',
  perf: 'performance change (behind a switch)',
  refactor: 'restructuring with no behaviour change',
  test: 'tests, scenarios, replay tooling',
  docs: 'documentation only',
  build: 'CMake, dependencies, build and release scripts',
  ci: 'GitHub workflows and their scripts',
  chore: 'anything else that does not change the engine',
  revert: 'reverts an earlier commit',
};

// These change engine code, so the title must name the area it touches.
const SCOPE_REQUIRED = new Set(['feat', 'fix', 'perf', 'refactor', 'test']);

const MAX_HEADER = 100;

// type(scope)!: subject
const HEADER = /^(?<type>[A-Za-z]+)(?:\((?<scope>[^()]*)\))?(?<bang>!)?(?<colon>:?)(?<space> ?)(?<subject>.*)$/;
// One or more lowercase scopes, comma separated: ui, d3d12/vulkan, range-rings, sim,lua.
const SCOPE = /^[a-z0-9][a-z0-9._/-]*(?:,[a-z0-9][a-z0-9._/-]*)*$/;

// Commits are authored by people; no AI or bot co-author lines, no "Generated with" footers.
const AI_COAUTHOR =
  /^co-authored-by:.*\b(claude|anthropic|copilot|chatgpt|openai|gpt|gemini|cursor|codeium|devin|aider|bot)\b/im;
const GENERATED_WITH = /^\W*generated (with|by)\b/im;

// Titles that git or GitHub write for you.
const isMergeTitle = (header) => /^Merge (branch|pull request|remote-tracking branch|tag|commit) /.test(header);
const isGitRevertTitle = (header) => /^Revert ".+"$/.test(header);

// Problems with one commit message (or a PR title). Empty when it is fine.
function lintMessage(message, { isTitle = false } = {}) {
  const lines = String(message ?? '').replace(/\r\n/g, '\n').split('\n');
  const header = lines[0].trim();
  const problems = [];

  if (header === '') return ['the title is empty'];
  if (isMergeTitle(header) || isGitRevertTitle(header)) return problems;
  if (/^(fixup|squash|amend)! /.test(header)) {
    return ['fixup!/squash! commits are for local rebases; squash them before pushing'];
  }

  if (header.length > MAX_HEADER) {
    problems.push(`the title is ${header.length} characters; keep it to ${MAX_HEADER}`);
  }

  const m = HEADER.exec(header);
  const { type, scope, colon, space, subject } = m?.groups ?? {};
  const known = Object.keys(TYPES);

  if (!m || !colon) {
    problems.push(`the title must start with "<type>(<scope>): ", e.g. "fix(ui): ..."; types: ${known.join(', ')}`);
    return problems;
  }
  if (!TYPES[type]) {
    const lower = type.toLowerCase();
    problems.push(
      TYPES[lower]
        ? `the type is lowercase: "${lower}", not "${type}"`
        : `"${type}" is not a commit type; use one of: ${known.join(', ')}`,
    );
  }
  if (scope === undefined) {
    if (SCOPE_REQUIRED.has(type)) {
      problems.push(`"${type}" needs a scope naming the area it changes, e.g. "${type}(ui): ..."`);
    }
  } else if (!SCOPE.test(scope)) {
    problems.push(`the scope "${scope}" must be lowercase words, digits, ".", "/" or "-" (several: "a,b")`);
  }
  if (space !== ' ' || /^\s/.test(subject)) {
    problems.push('put exactly one space after the colon');
  }
  const text = subject.trim();
  if (text === '') {
    problems.push('the description after the colon is empty');
  } else if (/\.$/.test(text) && !/\.\.\.$/.test(text)) {
    problems.push('the title does not end with a full stop');
  }

  if (!isTitle) {
    if (lines.length > 1 && lines[1].trim() !== '') {
      problems.push('leave a blank line between the title and the body');
    }
    const body = lines.slice(1).join('\n');
    if (AI_COAUTHOR.test(body)) problems.push('remove the AI or bot "Co-authored-by:" line');
    if (GENERATED_WITH.test(body)) problems.push('remove the "Generated with ..." line');
  }
  return problems;
}

function report(core, failures, checked) {
  if (failures.length === 0) {
    core.info(`${checked} title(s) follow the commit rules`);
    return;
  }
  const lines = failures.map(({ what, header, problems }) => `${what}: "${header}"\n  - ${problems.join('\n  - ')}`);
  core.setFailed(
    `${failures.length} of ${checked} title(s) break the commit rules (CONTRIBUTING.md, "Commits and pull request titles"):\n\n` +
      lines.join('\n\n'),
  );
}

const firstLine = (message) => String(message ?? '').split('\n')[0];

async function onPullRequest({ github, context, core, repo }) {
  const number = context.payload.pull_request.number;
  // Re-read the PR: the payload can be older than the latest title edit.
  const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
  const commits = await github.paginate(github.rest.pulls.listCommits, { ...repo, pull_number: number, per_page: 100 });

  const failures = [];
  const titleProblems = lintMessage(pr.title, { isTitle: true });
  if (titleProblems.length > 0) failures.push({ what: 'PR title', header: pr.title, problems: titleProblems });

  let checked = 1;
  for (const c of commits) {
    if (c.parents.length > 1) continue;
    checked++;
    const problems = lintMessage(c.commit.message);
    if (problems.length > 0) {
      failures.push({ what: `commit ${c.sha.slice(0, 9)}`, header: firstLine(c.commit.message), problems });
    }
  }
  report(core, failures, checked);
}

async function onPush({ github, context, core, repo }) {
  const { before, after } = context.payload;
  if (!after || /^0+$/.test(after)) return core.info('branch deleted; nothing to check');
  if (!before || /^0+$/.test(before)) return core.info('new branch; its commits are checked in its pull request');

  const { data } = await github.rest.repos.compareCommitsWithBasehead({ ...repo, basehead: `${before}...${after}` });
  const failures = [];
  let checked = 0;
  for (const c of data.commits) {
    if (c.parents.length > 1) continue;
    checked++;
    const problems = lintMessage(c.commit.message);
    if (problems.length > 0) {
      failures.push({ what: `commit ${c.sha.slice(0, 9)}`, header: firstLine(c.commit.message), problems });
    }
  }
  report(core, failures, checked);
}

module.exports = async ({ github, context, core }) => {
  const repo = { owner: context.repo.owner, repo: context.repo.repo };
  if (context.eventName === 'push') {
    await onPush({ github, context, core, repo });
  } else {
    await onPullRequest({ github, context, core, repo });
  }
};
module.exports.lintMessage = lintMessage;
module.exports.TYPES = TYPES;
module.exports.SCOPE_REQUIRED = SCOPE_REQUIRED;
module.exports.MAX_HEADER = MAX_HEADER;

// Command line use; see the top of the file.
if (require.main === module) {
  const fs = require('fs');
  const { execFileSync } = require('child_process');
  const args = process.argv.slice(2);
  let messages;
  if (args[0] === '--file') {
    // A commit-msg hook: drop git's comment lines first.
    const text = fs.readFileSync(args[1], 'utf8').split(/\r?\n/).filter((l) => !l.startsWith('#')).join('\n');
    messages = [{ what: 'message', text }];
  } else if (args[0] === '--range') {
    const out = execFileSync('git', ['log', '--no-merges', '--format=%h%x00%B%x01', args[1]], { encoding: 'utf8' });
    messages = out
      .split('\x01')
      .map((s) => s.replace(/^\s+/, ''))
      .filter(Boolean)
      .map((s) => {
        const [sha, text] = s.split('\x00');
        return { what: `commit ${sha}`, text };
      });
  } else if (args.length > 0) {
    messages = [{ what: 'title', text: args.join(' '), isTitle: true }];
  } else {
    console.error('usage: commit-lint.js "<title>" | --file <message file> | --range <a..b>');
    process.exit(2);
  }

  let bad = 0;
  for (const { what, text, isTitle } of messages) {
    const problems = lintMessage(text, { isTitle });
    if (problems.length === 0) continue;
    bad++;
    console.log(`${what}: "${firstLine(text)}"\n  - ${problems.join('\n  - ')}`);
  }
  if (bad > 0) {
    console.log(`\n${bad} of ${messages.length} break the commit rules; see CONTRIBUTING.md`);
    process.exit(1);
  }
  console.log(`${messages.length} ok`);
}
