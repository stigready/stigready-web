# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
require 'base64'
require 'fileutils'
require 'json'
require 'open3'
require 'openssl'
require 'shellwords'
require 'tmpdir'
require 'yaml'

# Decision 0114 (claude-agents): public copy must match production. Decision 0003: CINC asserts.
#
# Fixtures (files/copy-truth/sites, pages stored as *.fixture so the site's own checks never read them):
#   before-0ef9b2c  the site before stigready-web#70: Applied rows with no availability claim
#   after-e3c47e4   stigready-web#70: all 56 Applied rows "Coming soon" while all 56 were Public on Marketplace
#   main-e911b14    stigready-web#73: all 80 rows link their live listing
#   marketplace-live-2026-10-26.json  a real snapshot (marketplace-live-snapshot.py, read-only, 2026-10-26): 80 Public
# Every page is RENDERED (scripts/render/render.mjs, jsdom): what counts is what a visitor sees.
#
#   web-copy-truth-01  L1: #70 fails against production; #73 passes; the review's two hiding tricks (availabilityCell
#                      `if (false && ...)`, a CSS display:none on the links) fail
#   web-copy-truth-02  L1: prices; a stale, missing, malformed or EMPTY snapshot is exit 2; unidentified listings fail
#   web-copy-truth-03  L2 on git objects: #70 and both hiding tricks fail without an owner approval; a stylesheet or
#                      script edit that withdraws nothing passes (decision 0173: judged by what renders, not by which
#                      file changed); the review's bypasses (self-approval with no key on main, a deleted, emptied or
#                      symlinked owner-signers, an approval replayed on another PR or another base, a software or
#                      unlisted key, an edited, expired or too-long approval) all fail; only a signature by a FIDO2-type
#                      verify-required key listed on the base and enrolled on the owner's GitHub account passes
#   web-copy-truth-04  the pipeline runs the checks from the base branch, the renderer pinned, no test hooks; the gate
#                      is advisory exactly while config/owner-signers lists no key
#   web-copy-truth-05  hardened visibility evaluation and checker isolation: markup that hides the listings, a page
#                      the renderer cannot evaluate, and page scripts acting on the checker all fail; the script
#                      stage refuses to run unhardened
#   web-copy-truth-06  claims are read from all text (hiding a sentence never removes it), an unevaluable catalog
#                      page fails, listings count only from the catalog page, and the script stage's output cannot
#                      be replayed or forged
#   web-copy-truth-07  review of a6c10a03 (decision 0173): the renderer gets PATH only (no GH_TOKEN for page scripts);
#                      an unsigned, wrongly signed or edited snapshot is exit 2; owner keys need verify-required, no
#                      cert-authority and GitHub enrolment; a signers change never rides with another withdrawal; a
#                      drift run without its sources file is exit 2; .gitignore entries match symlinks
#
# The FIDO2-type key in these tests is made in software (SoftSK below), as the security review showed anyone can:
# the key TYPE proves no touch. What protects the gate is that a key counts only when the owner's GitHub account also
# lists it as a signing key (decision 0173). The checker reads that list from api.github.com; these tests answer for
# GitHub with a sitecustomize on PYTHONPATH (CT_FAKE_GH), so the checker carries no test hook. The pipeline runs the
# checker with python3 -I, which ignores PYTHONPATH.

ROOT_CT  = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
CHECK_CT = File.join(ROOT_CT, 'scripts', 'check-copy-vs-marketplace.py')
FIX_CT   = File.join(File.dirname(__FILE__), '..', 'files', 'copy-truth')
SNAP_CT  = File.join(FIX_CT, 'marketplace-live-2026-10-26.json')
NOW_CT   = '2026-10-26T12:00:00Z'.freeze
CT_TMP = Dir.mktmpdir('copy-truth-')
at_exit { FileUtils.rm_rf(CT_TMP) }

# The renderer's Node, with jsdom installed in scripts/render. COPY_TRUTH_NODE when the pipeline set it up; else a
# `node` that already has jsdom here; else scripts/render/setup.sh now (pinned Node and npm ci from the lock), so the
# controls do not depend on which pipeline version runs them. If none works, every render fails and so do these tests.
NODE_CT = lambda do
  return ENV['COPY_TRUTH_NODE'] if ENV['COPY_TRUTH_NODE'].to_s != ''

  render_dir = File.join(ROOT_CT, 'scripts', 'render')
  _, st = Open3.capture2e('node', '-e', 'require("jsdom")', chdir: render_dir) rescue [nil, nil]
  return 'node' if st&.success?

  out, st = Open3.capture2('bash', File.join(render_dir, 'setup.sh'), render_dir, File.join(CT_TMP, 'node'))
  st.success? ? out.strip : 'node'
end.call
NS_CT    = 'stigready-owner-approval'.freeze

# An sk-ssh-ed25519@openssh.com key and SSHSIG signature made in software, user-presence flag set.
module SoftSK
  KT = 'sk-ssh-ed25519@openssh.com'.b
  APP = 'ssh:'.b
  def self.s(b)
    [b.bytesize].pack('N') + b.b
  end

  def self.blob(key)
    s(KT) + s(key.raw_public_key) + s(APP)
  end

  def self.pub_line(key, opts: ',verify-required')
    %(owner@stigready namespaces="#{NS_CT}"#{opts} #{KT} #{Base64.strict_encode64(blob(key))} soft)
  end

  # The key as GitHub's ssh_signing_keys API lists it.
  def self.gh_key(key)
    "#{KT} #{Base64.strict_encode64(blob(key))}"
  end

  # flags 5: user presence and user verification (a PIN); 1: presence only.
  def self.sign(key, msg, flags: 5)
    signed = 'SSHSIG'.b + s(NS_CT) + s('') + s('sha512') + s(OpenSSL::Digest::SHA512.digest(msg))
    flags = [flags].pack('C')
    counter = [1].pack('N')
    sig = key.sign(nil, OpenSSL::Digest::SHA256.digest(APP) + flags + counter + OpenSSL::Digest::SHA256.digest(signed))
    raw = 'SSHSIG'.b + [1].pack('N') + s(blob(key)) + s(NS_CT) + s('') + s('sha512') + s(s(KT) + s(sig) + flags + counter)
    "-----BEGIN SSH SIGNATURE-----\n#{Base64.strict_encode64(raw).scan(/.{1,70}/).join("\n")}\n-----END SSH SIGNATURE-----\n"
  end
end

# Materialise a fixture site into dir (*.fixture -> real name), then let a block mutate it.
CT_SITE = lambda do |name, dir, &mutate|
  src = File.join(FIX_CT, 'sites', name)
  FileUtils.mkdir_p(dir)
  Dir.glob('**/*', base: src).each do |rel|
    from = File.join(src, rel)
    next if File.directory?(from)

    to = File.join(dir, rel.sub(/\.fixture\z/, ''))
    FileUtils.mkdir_p(File.dirname(to))
    FileUtils.cp(from, to)
  end
  mutate&.call(dir)
  dir
end

# The review's hiding tricks on #73's site.
HIDE_JS = lambda do |dir|
  f = File.join(dir, 'index.html')
  File.write(f, File.read(f).sub("if (p.availability === 'available' && url) {",
                                 "if (false && p.availability === 'available' && url) {"))
end
HIDE_CSS = lambda do |dir|
  File.open(File.join(dir, 'assets', 'css', 'site.css'), 'a') do |f|
    f.write(%(\na[href^="https://aws.amazon.com/marketplace/pp/"]{display:none}\n))
  end
end

# GitHub's answer for the owner's signing keys, given to the checker by a sitecustomize (see the header).
CT_FAKE_GH = File.join(CT_TMP, 'fake-gh')
FileUtils.mkdir_p(CT_FAKE_GH)
File.write(File.join(CT_FAKE_GH, 'sitecustomize.py'), <<~PY)
  import io, json, os, urllib.error, urllib.request
  _real = urllib.request.urlopen
  def _fake(req, *a, **k):
      url = getattr(req, "full_url", str(req))
      if url.startswith("https://api.github.com/user/"):
          if not os.path.isfile(os.environ.get("CT_GH_KEYS", "")):
              raise urllib.error.URLError("fixture: GitHub unreachable")
          uid = int(os.environ.get("CT_GH_USER_ID") or url.rsplit("/", 1)[1])
          return io.BytesIO(json.dumps({"id": uid, "login": "owner-fixture"}).encode())
      if url == "https://api.github.com/users/owner-fixture/ssh_signing_keys":
          path = os.environ.get("CT_GH_KEYS", "")
          if not os.path.isfile(path):
              raise urllib.error.URLError("fixture: GitHub unreachable")
          with open(path, "rb") as f:
              return io.BytesIO(f.read())
      return _real(req, *a, **k)
  urllib.request.urlopen = _fake
PY
CT_GH_KEYS = lambda do |name, keys|
  path = File.join(CT_TMP, "gh-#{name}.json")
  File.write(path, JSON.generate(keys.each_with_index.map { |k, i| { 'id' => i + 1, 'key' => SoftSK.gh_key(k), 'title' => 'k' } }))
  path
end

CT_EDIT_EARLY = lambda do |rel, from, to|
  lambda do |dir|
    f = File.join(dir, rel)
    s = File.read(f)
    raise "fixture: #{from} not in #{rel}" unless s.include?(from)

    File.write(f, s.sub(from, to))
  end
end

CT_RUN = lambda do |*args, gh: nil, env: {}|
  e = { 'PYTHONPATH' => CT_FAKE_GH, 'CT_GH_KEYS' => gh || CT_GH_DEFAULT }.merge(env)
  out, st = Open3.capture2e(e, 'python3', CHECK_CT, '--node', NODE_CT, *args)
  [out, st.exitstatus]
end

# The snapshot is trusted only with a signature by a key in config/snapshot-signers (decision 0173). The tests sign
# with a key of their own and pass its list with --snapshot-signers, as the pipeline passes the base's file.
CT_SNAP_KEY = File.join(CT_TMP, 'snapkey')
Open3.capture2e('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'snap', '-f', CT_SNAP_KEY)
CT_SNAP_SIGNERS = File.join(CT_TMP, 'snapshot-signers')
File.write(CT_SNAP_SIGNERS, %(snapshot@stigready namespaces="stigready-marketplace-snapshot" #{File.read("#{CT_SNAP_KEY}.pub").strip}\n))
CT_SIGN_SNAP = lambda do |path, key = CT_SNAP_KEY|
  FileUtils.rm_f("#{path}.sig")
  out, st = Open3.capture2e('ssh-keygen', '-Y', 'sign', '-f', key, '-n', 'stigready-marketplace-snapshot', path)
  raise "snapshot sign: #{out}" unless st.success?

  path
end
SNAP_SIGNED = CT_SIGN_SNAP.call(File.join(CT_TMP, 'marketplace-live.json').tap { |f| FileUtils.cp(SNAP_CT, f) })

CT_L1 = lambda do |site, snap = SNAP_SIGNED, now = NOW_CT, signers: CT_SNAP_SIGNERS, env: {}|
  CT_RUN.call('--mode', 'pr', '--site', site, '--snapshot', snap, '--snapshot-signers', signers, '--now', now, env: env)
end

CT_SNAP_WITH = lambda do |name, &edit|
  snap = JSON.parse(File.read(SNAP_CT))
  edit.call(snap)
  path = File.join(CT_TMP, name)
  File.write(path, JSON.generate(snap))
  CT_SIGN_SNAP.call(path)
end

# ------------------------------------------------------------------------------------------------- git fixtures (L2)

CT_GIT = lambda do |repo, *args|
  out, st = Open3.capture2e('git', '-C', repo, *args)
  raise "git #{args.join(' ')}: #{out}" unless st.success?

  out.strip
end

# A repository whose commits are whole site trees: commit(name or nil, signers: text|:none|:symlink, extra: {path=>text},
# &mutate) replaces the work tree and commits it on the current branch, returning the sha.
class CtRepo
  attr_reader :dir

  def initialize(name)
    @dir = File.join(CT_TMP, name)
    FileUtils.mkdir_p(@dir)
    CT_GIT.call(@dir, 'init', '-q', '-b', 'main')
    CT_GIT.call(@dir, 'config', 'user.name', 'fixture')
    CT_GIT.call(@dir, 'config', 'user.email', 'fixture@invalid')
  end

  def commit(site, signers: :none, extra: {}, keep: false, &mutate)
    unless keep
      Dir.children(@dir).reject { |c| c == '.git' }.each { |c| FileUtils.rm_rf(File.join(@dir, c)) }
      CT_SITE.call(site, @dir, &mutate) if site
    end
    mutate&.call(@dir) if keep
    sp = File.join(@dir, 'config', 'owner-signers')
    FileUtils.mkdir_p(File.dirname(sp))
    FileUtils.rm_f(sp)
    case signers
    when :none then nil
    when :symlink then File.symlink('/dev/null', sp)
    else File.write(sp, signers)
    end
    unless keep
      tr = File.join(@dir, 'config', 'trust-root-paths')
      FileUtils.cp(File.join(ROOT_CT, 'config', 'trust-root-paths'), tr) unless File.exist?(tr)
    end
    extra.each do |rel, text|
      FileUtils.mkdir_p(File.dirname(File.join(@dir, rel)))
      File.write(File.join(@dir, rel), text)
    end
    CT_GIT.call(@dir, 'add', '-A')
    CT_GIT.call(@dir, 'commit', '-q', '--allow-empty', '-m', 'fixture')
    CT_GIT.call(@dir, 'rev-parse', 'HEAD')
  end

  def branch(name, at)
    CT_GIT.call(@dir, 'checkout', '-q', '-B', name, at)
  end
end

CT_L2 = lambda do |repo, base, head, pr, gh: nil, env: {}|
  CT_RUN.call('--mode', 'removal', '--repo', repo.dir, '--base-ref', base, '--head-ref', head, '--pr', pr.to_s,
              '--now', NOW_CT, gh: gh, env: env)
end

# Ask the checker for the canonical message of (base, head, pr), sign it, and commit both files onto head's branch.
CT_APPROVE = lambda do |repo, base, head, pr, key, expires: '2026-11-02', edit: nil, flags: 5|
  msg, st = Open3.capture2('python3', CHECK_CT, '--node', NODE_CT, '--mode', 'approval-message', '--repo', repo.dir,
                           '--base-ref', base, '--head-ref', head, '--pr', pr.to_s, '--expires', expires,
                           '--now', NOW_CT)
  raise "approval-message failed: #{msg}" unless st.success?

  digest = msg[/^digest: (\h{64})$/, 1]
  sig = SoftSK.sign(key, msg, flags: flags)
  msg = edit.call(msg) if edit
  repo.commit(nil, keep: true, signers: File.read(File.join(repo.dir, 'config', 'owner-signers')),
                   extra: { "approvals/owner/#{digest}.txt" => msg, "approvals/owner/#{digest}.sig" => sig })
end

OWNER_KEY = OpenSSL::PKey.generate_key('ED25519')
OTHER_KEY = OpenSSL::PKey.generate_key('ED25519')
OWNER_SIGNERS = "# fixture\n#{SoftSK.pub_line(OWNER_KEY)}\n".freeze
# What the owner's GitHub account lists by default in these tests: both keys (OTHER_KEY for the rotation case).
CT_GH_DEFAULT = CT_GH_KEYS.call('default', [OWNER_KEY, OTHER_KEY])

# ------------------------------------------------------------------------------------------------------------- L1

CT_SITES = {
  'before' => CT_SITE.call('before-0ef9b2c', File.join(CT_TMP, 's-before')),
  'after' => CT_SITE.call('after-e3c47e4', File.join(CT_TMP, 's-after')),
  'main' => CT_SITE.call('main-e911b14', File.join(CT_TMP, 's-main')),
  'hide-js' => CT_SITE.call('main-e911b14', File.join(CT_TMP, 's-hide-js'), &HIDE_JS),
  'hide-css' => CT_SITE.call('main-e911b14', File.join(CT_TMP, 's-hide-css'), &HIDE_CSS)
}.freeze

control 'web-copy-truth-01' do
  impact 1.0
  title 'L1: what the site renders is checked against live Marketplace'
  desc 'Fail-first for decision 0114 L1 and for the security review of stigready-web#74 (finding 3).'

  CT_L1.call(CT_SITES['after']).then do |out, rc|
    describe 'L1 on stigready-web#70 (e3c47e4)' do
      it('exits 1') { expect(rc).to eq(1), out }
      it('finds all 56 live-Public Applied products rendered as coming soon') do
        expect(out.scan(%r{^- WITHHELD stigapplied/}).size).to eq(56)
      end
      it('finds the "Applied ... coming soon" sentences: exactly 10, 66 findings in all') do
        expect(out).to match(/WITHHELD-TEXT index\.html: StigReady Applied has 56 live Public listings/)
        expect(out.scan(/^- WITHHELD-TEXT /).size).to eq(10)
        expect(out).to include('**66 finding(s)**')
      end
      it('never calls Base withheld') { expect(out).not_to match(%r{^- (WITHHELD|NOT-LINKED) stigready/}) }
    end
  end

  CT_L1.call(CT_SITES['main']).then do |out, rc|
    describe 'L1 on stigready-web#73 (all 80 linked)' do
      it('exits 0') { expect(rc).to eq(0), out }
    end
  end

  CT_L1.call(CT_SITES['hide-js']).then do |out, rc|
    describe 'L1 on #73 with availabilityCell changed to `if (false && ...)`' do
      it('fails: all 80 rendered as coming soon') do
        expect(rc).to eq(1), out
        expect(out.scan(/^- WITHHELD /).size).to eq(80)
      end
    end
  end

  CT_L1.call(CT_SITES['hide-css']).then do |out, rc|
    describe 'L1 on #73 with a CSS rule hiding the Marketplace links' do
      it('fails: no visible link for any of the 80') do
        expect(rc).to eq(1), out
        expect(out.scan(/^- NOT-LINKED /).size).to eq(80)
      end
    end
  end

  CT_L1.call(CT_SITES['before']).then do |out, rc|
    describe 'L1 on the site before #70 (no links rendered)' do
      it('fails: live listings the site does not link') do
        expect(rc).to eq(1), out
        expect(out.scan(/^- NOT-LINKED /).size).to eq(80)
      end
    end
  end
end

control 'web-copy-truth-02' do
  impact 1.0
  title 'L1: prices, unknown or empty production state, unidentified listings'
  desc 'A price that differs from the live offer fails. A snapshot that cannot be trusted is exit 2, never a pass.'

  prices = lambda do |applied_hourly|
    lambda do |s|
      s['prices'] = { 'stigready' => { 'hourly_usd' => '0.02', 'annual_usd' => '149' },
                      'stigapplied' => { 'hourly_usd' => applied_hourly, 'annual_usd' => '649' } }
    end
  end
  wrong = CT_SNAP_WITH.call('wrong-price.json', &prices.call('0.10'))
  right = CT_SNAP_WITH.call('right-price.json', &prices.call('0.08'))
  empty = CT_SNAP_WITH.call('empty.json') { |s| s['products'] = [] }
  unid = CT_SNAP_WITH.call('unidentified.json') { |s| s['unidentified'] = 2 }
  no_base = CT_SNAP_WITH.call('no-base-alma10.json') do |s|
    s['products'].reject! { |p| p['line'] == 'stigready' && p['os_key'] == 'alma-10' && p['arch'] == 'x86_64' }
  end
  bad = File.join(CT_TMP, 'bad.json')
  File.write(bad, '{"schema": "something-else"}')
  CT_SIGN_SNAP.call(bad)

  CT_L1.call(CT_SITES['main'], wrong).then do |out, rc|
    describe 'a site price that differs from the live price' do
      it('fails PRICE') do
        expect(rc).to eq(1), out
        expect(out).to match(/^- PRICE .*StigReady Applied hourly \$0\.08 on the site, \$0\.1 live/)
      end
    end
  end
  CT_L1.call(CT_SITES['main'], right).then do |out, rc|
    describe 'site prices equal to the live prices' do
      it('pass, with no price warning') do
        expect(rc).to eq(0), out
        expect(out).not_to match(/PRICE/)
      end
    end
  end
  CT_L1.call(CT_SITES['main']).then do |out, rc|
    describe 'a snapshot with no live price yet' do
      it('warns PRICE-UNVERIFIED, does not fail') do
        expect(rc).to eq(0), out
        expect(out).to match(/PRICE-UNVERIFIED StigReady Applied hourly \$0\.08/)
      end
    end
  end
  CT_L1.call(CT_SITES['main'], no_base).then do |out, rc|
    describe 'a row linked as purchasable whose listing is not live Public' do
      it('fails NOT-LIVE') do
        expect(rc).to eq(1), out
        expect(out).to match(%r{^- NOT-LIVE stigready/base/alma-10/x86_64})
      end
    end
  end
  CT_L1.call(CT_SITES['main'], unid).then do |out, rc|
    describe 'a snapshot with listings it could not identify' do
      it('fails UNIDENTIFIED') do
        expect(rc).to eq(1), out
        expect(out).to match(/^- UNIDENTIFIED 2 /)
      end
    end
  end
  [['stale (30 h)', SNAP_SIGNED, '2026-10-27T16:10:00Z'], ['missing', File.join(CT_TMP, 'nope.json'), NOW_CT],
   ['another schema', bad, NOW_CT], ['empty (0 Public listings)', empty, NOW_CT]].each do |what, snap, now|
    CT_L1.call(CT_SITES['after'], snap, now).then do |out, rc|
      describe "a #{what} snapshot" do
        it('is exit 2, production state unknown') do
          expect(rc).to eq(2), out
          expect(out).to match(/production state unknown/)
        end
      end
    end
  end
end

# --------------------------------------------------------------------------------------------------------------- L2

control 'web-copy-truth-03' do
  impact 1.0
  title 'L2: withdrawing a product, or changing how it renders, needs the owner\'s signed approval for this PR and base'
  desc 'Each bypass from the security review of stigready-web#74 is a case here and must fail.'

  # 1. The incident: #70 against its parent, main listing the owner key.
  r = CtRepo.new('r-incident')
  base = r.commit('before-0ef9b2c', signers: OWNER_SIGNERS)
  head = r.commit('after-e3c47e4', signers: OWNER_SIGNERS)
  CT_L2.call(r, base, head, 70).then do |out, rc|
    describe 'removal gate on #70 with no approval' do
      it('fails, listing the 56 Applied products downgraded, judged by what renders') do
        expect(rc).to eq(1), out
        expect(out.scan(%r{^- downgraded stigapplied/\S+ neutral -> withheld$}).size).to eq(56)
        expect(out).not_to match(/changed rendering code/)
        expect(out).to match(/no owner approval for PR 70/)
      end
    end
  end
  approved = CT_APPROVE.call(r, base, head, 70, OWNER_KEY)
  CT_L2.call(r, base, approved, 70).then do |out, rc|
    describe 'removal gate on #70 with the owner key\'s signature over PR 70 and its base' do
      it('passes') do
        expect(rc).to eq(0), out
        expect(out).to match(/owner approval \h{12} for PR 70 on base \h{12} verifies/)
      end
    end
  end
  CT_L2.call(r, base, approved, 71).then do |out, rc|
    describe 'the same approval files on another PR number (replay)' do
      it('fail') { expect(rc).to eq(1), out }
    end
  end
  r.branch('main', base)
  base2 = r.commit(nil, keep: true, signers: OWNER_SIGNERS, extra: { 'README.md' => "moved\n" })
  r.branch('replay', base2)
  replay = r.commit('after-e3c47e4', signers: OWNER_SIGNERS)
  # Copy the approval files of `approved` onto the replay head exactly.
  wt = File.join(CT_TMP, 'wt-approved')
  CT_GIT.call(r.dir, 'worktree', 'add', '-q', '--detach', wt, approved)
  files = Dir.glob('approvals/owner/*', base: wt).to_h { |f| [f, File.read(File.join(wt, f))] }
  CT_GIT.call(r.dir, 'worktree', 'remove', '--force', wt)
  replay = r.commit(nil, keep: true, signers: OWNER_SIGNERS, extra: files)
  CT_L2.call(r, base2, replay, 70).then do |out, rc|
    describe 'the same approval files on the same PR number after main moved (another base)' do
      it('fail') { expect(rc).to eq(1), out }
    end
  end

  # 2. The review's hiding tricks against #73's site.
  { 'availabilityCell `if (false && ...)`' => [HIDE_JS, /^- downgraded \S+ purchasable -> withheld$/, 80, 'js'],
    'a CSS display:none on the links' => [HIDE_CSS, /^- downgraded \S+ purchasable -> neutral$/, 80, 'css'] }
    .each do |what, (mut, pat, n, tag)|
    h = CtRepo.new("r-hide-#{tag}")
    b = h.commit('main-e911b14', signers: OWNER_SIGNERS)
    hd = h.commit('main-e911b14', signers: OWNER_SIGNERS, &mut)
    CT_L2.call(h, b, hd, 74).then do |out, rc|
      describe "removal gate on #73's site with #{what}" do
        it("fails: #{n} products downgraded in what renders") do
          expect(rc).to eq(1), out
          expect(out.scan(pat).size).to eq(n)
        end
      end
    end
  end

  # Routine site PRs (QA review of a6c10a03, finding 1): a stylesheet or inline-script edit that withdraws nothing
  # passes with no approval (decision 0173: judged by what renders, not by which file changed).
  { 'a stylesheet change' => lambda { |dir|
      File.open(File.join(dir, 'assets', 'css', 'site.css'), 'a') { |f| f.write("\n.unused-x{color:red}\n") }
    },
    'an inline-script change on the catalog page' => CT_EDIT_EARLY.call('index.html', "if (p.availability === 'available' && url) {",
                                                                        "if (p.availability === 'available' && url) { /* routine */") }
    .each_with_index do |(what, mut), i|
    c = CtRepo.new("r-routine-#{i}")
    cb = c.commit('main-e911b14', signers: OWNER_SIGNERS)
    ch = c.commit('main-e911b14', signers: OWNER_SIGNERS, &mut)
    CT_L2.call(c, cb, ch, 80 + i).then do |out, rc|
      describe "#{what} that withdraws nothing" do
        it('passes with no approval') do
          expect(rc).to eq(0), out
          expect(out).to match(/Nothing is withdrawn from what the site renders/)
        end
      end
    end
  end

  # 3. Self-approval: main lists no key; the PR adds its own key and signs (review finding 1). With a withdrawal in
  # the same PR it is refused before any signature is read; on its own it fails because main lists no key.
  s = CtRepo.new('r-bootstrap')
  sb = s.commit('main-e911b14', signers: "# no key yet\n")
  sh = s.commit('main-e911b14', signers: OWNER_SIGNERS, &HIDE_JS)
  sa = CT_APPROVE.call(s, sb, sh, 90, OWNER_KEY)
  CT_L2.call(s, sb, sa, 90).then do |out, rc|
    describe 'a PR that adds its own key while main lists none, withdraws listings, and signs with it' do
      it('fails: a signers change must be its own PR') do
        expect(rc).to eq(1), out
        expect(out).to match(/signers change must be its own PR/)
      end
    end
  end
  s.branch('alone', sb)
  so = s.commit('main-e911b14', signers: OWNER_SIGNERS)
  CT_L2.call(s, sb, CT_APPROVE.call(s, sb, so, 89, OWNER_KEY), 89).then do |out, rc|
    describe 'a PR that only adds its own key while main lists none, and signs with it' do
      it('fails: with no key on main nothing can be approved') do
        expect(rc).to eq(1), out
        expect(out).to match(/lists no owner key, so nothing can be approved/)
      end
    end
  end

  # 4. owner-signers deleted, emptied or replaced by a symlink: each a change (review finding 2).
  { 'deleted' => [:none, 'missing'], 'emptied' => ['', 'edited'], 'a symlink to /dev/null' => [:symlink, 'symlink'] }
    .each do |what, (signers, label)|
    d = CtRepo.new("r-signers-#{label}")
    db = d.commit('main-e911b14', signers: OWNER_SIGNERS)
    dh = d.commit('main-e911b14', signers: signers)
    CT_L2.call(d, db, dh, 91).then do |out, rc|
      describe "config/owner-signers #{what}" do
        it('is a change that needs a signature') do
          expect(rc).to eq(1), out
          expect(out).to include("- changed config/owner-signers (#{label})")
        end
      end
    end
  end
  # ... and with the owner's signature it passes (the owner may rotate the key).
  dd = CtRepo.new('r-signers-rotate')
  ddb = dd.commit('main-e911b14', signers: OWNER_SIGNERS)
  ddh = dd.commit('main-e911b14', signers: "#{OWNER_SIGNERS}#{SoftSK.pub_line(OTHER_KEY)}\n")
  CT_L2.call(dd, ddb, CT_APPROVE.call(dd, ddb, ddh, 92, OWNER_KEY), 92).then do |out, rc|
    describe 'a key rotation signed by the key on main' do
      it('passes') { expect(rc).to eq(0), out }
    end
  end

  # 5. Wrong keys and bad messages.
  k = CtRepo.new('r-keys')
  kb = k.commit('main-e911b14', signers: OWNER_SIGNERS)
  kh = k.commit('main-e911b14', signers: OWNER_SIGNERS, &HIDE_JS)
  cases = {
    'a key the base does not list' => [CT_APPROVE.call(k, kb, kh, 93, OTHER_KEY), /does not verify/],
    'an approval message edited after signing' =>
      [CT_APPROVE.call(k, kb, kh, 93, OWNER_KEY, edit: ->(m) { m.sub(/^- downgraded .*\n/, '') }),
       /not the canonical message|does not verify/],
    'an approval that expires more than 14 days out' =>
      [CT_APPROVE.call(k, kb, kh, 93, OWNER_KEY, expires: '2026-12-31'), /must be between today and 14 days out/],
    'an expired approval' => [CT_APPROVE.call(k, kb, kh, 93, OWNER_KEY, expires: '2026-10-25'), /must be between/]
  }
  cases.each do |what, (head_sha, pat)|
    CT_L2.call(k, kb, head_sha, 93).then do |out, rc|
      describe what do
        it('fails') do
          expect(rc).to eq(1), out
          expect(out).to match(pat)
        end
      end
    end
  end

  # 6. A software (non-FIDO2) key on main never counts, even with a valid signature.
  w = CtRepo.new('r-software-key')
  wkey = File.join(CT_TMP, 'swkey')
  Open3.capture2e('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'sw', '-f', wkey)
  sw_signers = %(owner@stigready namespaces="#{NS_CT}" #{File.read("#{wkey}.pub").strip}\n)
  wb = w.commit('main-e911b14', signers: sw_signers)
  wh = w.commit('main-e911b14', signers: sw_signers, &HIDE_JS)
  msg, = Open3.capture2('python3', CHECK_CT, '--node', NODE_CT, '--mode', 'approval-message', '--repo', w.dir,
                        '--base-ref', wb, '--head-ref', wh, '--pr', '94', '--expires', '2026-11-02', '--now', NOW_CT)
  digest = msg[/^digest: (\h{64})$/, 1]
  mf = File.join(CT_TMP, 'sw-msg.txt')
  File.write(mf, msg)
  Open3.capture2e('ssh-keygen', '-Y', 'sign', '-f', wkey, '-n', NS_CT, mf)
  ws = w.commit(nil, keep: true, signers: sw_signers,
                     extra: { "approvals/owner/#{digest}.txt" => msg, "approvals/owner/#{digest}.sig" => File.read("#{mf}.sig") })
  CT_L2.call(w, wb, ws, 94).then do |out, rc|
    describe 'a valid signature by a software ssh-ed25519 key listed on main' do
      it('does not count') do
        expect(rc).to eq(1), out
        expect(out).to match(/lists no owner key/)
      end
    end
  end

  # 8. The trust root (security review at c773a3a, finding 1): a PR that changes what judges the next PR renders the
  #    same site, but is removal-class all the same.
  { 'the checker' => [{ 'scripts/check-copy-vs-marketplace.py' => "# v1\n" }, { 'scripts/check-copy-vs-marketplace.py' => "# v2\n" },
                      'scripts/check-copy-vs-marketplace.py'],
    'the renderer' => [{ 'scripts/render/render.mjs' => "// v1\n" }, { 'scripts/render/render.mjs' => "// v2\n" },
                       'scripts/render/render.mjs'],
    'the copy-removal-gate job' => [{ '.cairn.yml' => "jobs:\n  - name: copy-removal-gate\n    run: a\n" },
                                    { '.cairn.yml' => "jobs:\n  - name: copy-removal-gate\n    run: b\n" },
                                    '.cairn.yml#copy-removal-gate'],
    'these controls' => [{ 'cinc/profiles/stigready-web/controls/copy_truth.rb' => "# v1\n" },
                         { 'cinc/profiles/stigready-web/controls/copy_truth.rb' => "# v2\n" },
                         'cinc/profiles/stigready-web/controls/copy_truth.rb'],
    'the trust-root list (an entry dropped)' => [{}, { 'config/trust-root-paths' => "scripts/render/**\n" },
                                                 'config/trust-root-paths'] }
    .each_with_index do |(what, (b_extra, h_extra, entry)), i|
    t = CtRepo.new("r-trust-#{i}")
    tb = t.commit('main-e911b14', signers: OWNER_SIGNERS, extra: b_extra)
    th = t.commit('main-e911b14', signers: OWNER_SIGNERS, extra: h_extra)
    CT_L2.call(t, tb, th, 40 + i).then do |out, rc|
      describe "a PR that changes #{what} and renders the same site" do
        it('is removal-class: it needs the owner\'s signature') do
          expect(rc).to eq(1), out
          expect(out).to include("- changed trust root: #{entry}")
        end
      end
    end
  end
  t = CtRepo.new('r-trust-signed')
  tb = t.commit('main-e911b14', signers: OWNER_SIGNERS, extra: { 'scripts/check-copy-vs-marketplace.py' => "# v1\n" })
  th = t.commit('main-e911b14', signers: OWNER_SIGNERS, extra: { 'scripts/check-copy-vs-marketplace.py' => "# v2\n" })
  CT_L2.call(t, tb, CT_APPROVE.call(t, tb, th, 49, OWNER_KEY), 49).then do |out, rc|
    describe 'a checker change signed by the owner key' do
      it('passes') { expect(rc).to eq(0), out }
    end
  end

  # 7. Nothing changed: passes with no approval.
  n = CtRepo.new('r-unchanged')
  nb = n.commit('main-e911b14', signers: OWNER_SIGNERS)
  nh = n.commit('main-e911b14', signers: OWNER_SIGNERS, extra: { 'blog/x.txt' => "x\n" })
  CT_L2.call(n, nb, nh, 95).then do |out, rc|
    describe 'a PR that withdraws nothing and leaves the rendering code alone' do
      it('passes') { expect(rc).to eq(0), out }
    end
  end
end

control 'web-copy-truth-04' do
  impact 1.0
  title 'The pipeline runs copy-truth and copy-removal-gate from the base branch, rendered with the pinned Node and jsdom'
  desc 'A PR must not be able to change the checker, the renderer, the snapshot or the signers that judge it.'

  pipe = YAML.safe_load(File.read(File.join(ROOT_CT, '.cairn.yml')))
  jobs = (pipe['jobs'] || []).to_h { |j| [j['name'], j] }
  text = File.read(File.join(ROOT_CT, '.cairn.yml'))
  checker = File.read(CHECK_CT)
  steps = ->(name) { (jobs.dig(name, 'run', 'exec', 'steps') || []).map { |s| s['run'].to_s }.join("\n") }

  describe 'stigready-web .cairn.yml' do
    %w[copy-truth copy-removal-gate].each do |name|
      it "has #{name} on pull requests, under its own status" do
        expect(jobs.dig(name, 'when')).to eq('pull_request')
        expect(jobs.dig(name, 'status')).to eq(name)
      end
      it "#{name} runs the checker, renderer and setup from origin/$CAIRN_BASE_REF" do
        s = steps.call(name)
        expect(s).to include('git archive "origin/${CAIRN_BASE_REF:?}"')
        expect(s).to include('bash "$t/base/scripts/render/setup.sh" "$t/base/scripts/render"')
        expect(s).to match(%r{python3 -I "\$t/base/scripts/check-copy-vs-marketplace\.py"})
        expect(s).to include('--renderer "$t/base/scripts/render/render.mjs"')
      end
    end
    it 'copy-removal-gate is advisory exactly while config/owner-signers lists no key (decision 0173)' do
      keys = File.read(File.join(ROOT_CT, 'config', 'owner-signers')).lines.map(&:strip)
                 .reject { |l| l.empty? || l.start_with?('#') }
      expect(jobs.dig('copy-removal-gate', 'advisory') == true).to eq(keys.empty?)
    end
    it 'copy-removal-gate judges HEAD against the base by git objects, and binds the PR number' do
      s = steps.call('copy-removal-gate')
      expect(s).to include('--base-ref "origin/${CAIRN_BASE_REF:?}" --head-ref HEAD --pr "${CAIRN_PR:?}"')
    end
    it 'copy-truth reads the snapshot and its signature from the live/marketplace branch, keys from the base' do
      s = steps.call('copy-truth')
      expect(s).to include('live/marketplace')
      expect(s).to include('FETCH_HEAD:marketplace-live.json.sig')
      expect(s).to include('--snapshot-signers "$t/base/config/snapshot-signers"')
    end
    it 'copy-drift-watch checks the snapshot signature too' do
      s = steps.call('copy-drift-watch')
      expect(s).to include('FETCH_HEAD:marketplace-live.json.sig')
      expect(s).to include('--snapshot-signers config/snapshot-signers')
    end
    it 'validate installs the renderer before CINC runs (the controls render pages)' do
      expect(steps.call('validate')).to include('scripts/render/setup.sh')
    end
    it 'copy-drift-watch is manual, scheduled as copy-drift, and may only write issues' do
      expect(jobs.dig('copy-drift-watch', 'when')).to eq('manual')
      sched = (pipe.dig('triggers', 'schedule') || []).find { |s| s['name'] == 'copy-drift' }
      expect(sched && sched['jobs']).to eq(['copy-drift-watch'])
      expect(jobs.dig('copy-drift-watch', 'github_token', 'permissions')).to eq('issues' => 'write')
    end
    it 'has no test hook in the pipeline or the checker' do
      expect(text).not_to match(/test-allow|allow-software/)
      expect(checker).not_to match(/test-allow|allow_software/)
    end
  end

  describe 'the renderer is pinned' do
    lock = JSON.parse(File.read(File.join(ROOT_CT, 'scripts', 'render', 'package-lock.json')))
    setup = File.read(File.join(ROOT_CT, 'scripts', 'render', 'setup.sh'))
    it('jsdom exactly 30.1.1, every package with a sha512 integrity') do
      expect(lock.dig('packages', 'node_modules/jsdom', 'version')).to eq('30.1.1')
      pk = lock['packages'].reject { |k, _| k.empty? }
      expect(pk.reject { |_, v| v['integrity'].to_s.start_with?('sha512-') }.keys).to eq []
    end
    it('Node exactly v24.21.0, checked against its sha256, packages by npm ci with no install scripts') do
      expect(setup).to include('NODE_VERSION=v24.21.0')
      expect(setup).to include('NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6')
      expect(setup).to include('sha256sum -c -')
      expect(setup.scan(/"\$npm" ci [^\n]*/).all? { |l| l.include?('--ignore-scripts') }).to eq(true)
      expect(setup).not_to match(/"\$npm" install/)
    end
  end

  describe file(File.join(ROOT_CT, 'config', 'owner-signers')) do
    it { should exist }
  end
end

# ----------------------------------------------------------------------------------------------- render hardening

# Security re-review of stigready-web#74: hardened visibility evaluation and checker isolation. Each case hides the
# 56 Applied listings from a visitor, or makes a page the renderer cannot evaluate, or is a page script acting on the
# checker; each must fail L1.
CT_EDIT = lambda do |rel, from, to|
  lambda do |dir|
    f = File.join(dir, rel)
    s = File.read(f)
    raise "fixture: #{from} not in #{rel}" unless s.include?(from)

    File.write(f, s.sub(from, to))
  end
end
CT_TBODY = '<tbody id="applied-tbody" class="'.freeze
CT_TB_ATTR = ->(attr) { CT_EDIT.call('index.html', CT_TBODY, %(<tbody id="applied-tbody" #{attr} class=")) }
CT_BOTH = ->(*muts) { ->(dir) { muts.each { |m| m.call(dir) } } }
CT_PAGE = ->(name, body) { ->(dir) { File.write(File.join(dir, name), body) } }
CT_TW = lambda do |css, cls|
  CT_BOTH.call(->(dir) { File.open(File.join(dir, 'assets', 'css', 'site.css'), 'a') { |f| f.write("\n#{css}\n") } },
               CT_EDIT.call('index.html', CT_TBODY, %(#{CT_TBODY}#{cls} )))
end
# Page scripts acting on the checker.
CT_ESCAPE_PAGE = <<~HTML.freeze
  <!doctype html><html><head><title>Changelog</title></head><body><p>Release notes.</p>
  <script>
  try { var P = console.log.constructor('return process')();
    var w = P.stdout.write.bind(P.stdout);
    P.stdout.write = function (s, cb) { return w(String(s).replace(/"visible":false/g, '"visible":true'), cb); };
  } catch (e) {}
  </script></body></html>
HTML
CT_POLLUTE_PAGE = <<~HTML.freeze
  <!doctype html><html><head><title>Notes</title></head><body><p>Release notes.</p>
  <script>
  try { var P = Object.getPrototypeOf(Object.getPrototypeOf(setTimeout));
    Object.defineProperty(P, 'toJSON', { configurable: true, value: function () {
      if (this && this.tbody !== undefined && this.visible === false) { var o = {}; for (var k in this) o[k] = this[k]; o.visible = true; return o; }
      return this; } });
  } catch (e) {}
  </script></body></html>
HTML
CT_LIE_SCRIPT = <<~HTML.freeze
  <script>
  setTimeout(function () {
    document.querySelectorAll('#applied-tbody a').forEach(function (a) { a.style.display = 'none'; });
    var g = window.getComputedStyle;
    window.getComputedStyle = function (e) {
      var s = g(e);
      return new Proxy(s, { get: function (t, k) { if (k === 'display') return 'block'; var v = t[k]; return typeof v === 'function' ? v.bind(t) : v; } });
    };
  }, 300);
  </script>
  </body>
HTML
CT_HIDE_DISPLAY = CT_TB_ATTR.call('style="display:none"')

CT_HARDEN = {
  # markup: style attributes, classes, structure
  'a zero-height, overflow-hidden tbody' => CT_TB_ATTR.call('style="display:block;height:0;overflow:hidden"'),
  'a tbody moved off the page' => CT_TB_ATTR.call('style="position:absolute;left:-99999px"'),
  'a tbody scaled to 0' => CT_TB_ATTR.call('style="transform:scale(0)"'),
  "the site's own .hidden class on the tbody" => CT_EDIT.call('index.html', CT_TBODY, "#{CT_TBODY}hidden "),
  'text filled transparent' => CT_TB_ATTR.call('style="-webkit-text-fill-color:transparent"'),
  'a tbody clipped away' => CT_TB_ATTR.call('style="clip-path:inset(50%)"'),
  'a filter to opacity 0' => CT_TB_ATTR.call('style="filter:opacity(0)"'),
  'content-visibility:hidden' => CT_TB_ATTR.call('style="content-visibility:hidden"'),
  'two opacities that multiply below 0.1' => CT_BOTH.call(CT_TB_ATTR.call('style="opacity:0.3"'),
                                                           CT_EDIT.call('index.html', '<table class="w-full text-sm min-w-[640px]">',
                                                                        '<table style="opacity:0.3" class="w-full text-sm min-w-[640px]">')),
  'the table inside a closed <details>' => CT_EDIT.call('index.html', '<table class="w-full text-sm min-w-[640px]">',
                                                         '<details><summary>Products</summary><table class="w-full text-sm min-w-[640px]">'),
  'an opaque element positioned over the page' => CT_EDIT.call('index.html', '</body>',
                                                                '<div style="position:fixed;inset:0;background:#111827"></div></body>'),
  'an off-site stylesheet the renderer cannot evaluate' => CT_EDIT.call('index.html', '</head>',
                                                                         '<link rel="stylesheet" href="https://cdn.example.net/x.css"></head>'),
  # rebuilt Tailwind utilities: L1 must see them
  'Tailwind .sr-only' => CT_TW.call('.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;' \
                                     'clip:rect(0,0,0,0);white-space:nowrap;border-width:0}', 'sr-only'),
  'Tailwind .invisible' => CT_TW.call('.invisible{visibility:hidden}', 'invisible'),
  'Tailwind .opacity-0' => CT_TW.call('.opacity-0{opacity:0}', 'opacity-0'),
  # page scripts against the checker
  'a page script that escapes to Node and rewrites the output' => CT_BOTH.call(CT_HIDE_DISPLAY,
                                                                                CT_PAGE.call('zz.html', CT_ESCAPE_PAGE)),
  "a page script that pollutes the renderer's Object.prototype" => CT_BOTH.call(CT_HIDE_DISPLAY,
                                                                                 CT_PAGE.call('zz.html', CT_POLLUTE_PAGE)),
  "a page script that replaces the window's getComputedStyle" => CT_EDIT.call('index.html', '</body>', CT_LIE_SCRIPT),
}.freeze
# The cases the removal gate (L2) also sees as 56 Applied downgrades. The others hide the listings in ways only L1's
# visible-link rule names (an unevaluable page, for one), so they are L1 cases only.
CT_HARDEN_L2 = ['a zero-height, overflow-hidden tbody', 'a tbody moved off the page', "the site's own .hidden class on the tbody",
                'text filled transparent', 'the table inside a closed <details>', 'an opaque element positioned over the page',
                'a page script that escapes to Node and rewrites the output',
                "a page script that pollutes the renderer's Object.prototype"].freeze

control 'web-copy-truth-05' do
  impact 1.0
  title 'Markup cannot hide listings from the renderer, and page scripts cannot change its result'
  desc 'Security re-review of stigready-web#74 (0114 L1; L2 for CT_HARDEN_L2): hardened visibility evaluation and ' \
       'checker isolation. Every case hides the Applied listings from a visitor, or tries to; every case must fail.'

  CT_HARDEN.each_with_index do |(what, mut), i|
    site = CT_SITE.call('main-e911b14', File.join(CT_TMP, "s-harden-#{i}"), &mut)
    CT_L1.call(site).then do |out, rc|
      describe "L1 on #73 with #{what}" do
        it('fails: the Applied listings are not visibly linked') do
          expect(rc).to eq(1), out
          expect(out.scan(%r{^- (NOT-LINKED|MISSING) stigapplied/}).size).to eq(56), out
        end
      end
    end
    next unless CT_HARDEN_L2.include?(what)

    h = CtRepo.new("r-harden-#{i}")
    b = h.commit('main-e911b14', signers: OWNER_SIGNERS)
    hd = h.commit('main-e911b14', signers: OWNER_SIGNERS, &mut)
    CT_L2.call(h, b, hd, 90 + i).then do |out, rc|
      describe "removal gate on #73 with #{what}" do
        it('fails without an owner approval: the Applied listings are downgraded') do
          expect(rc).to eq(1), out
          expect(out.scan(%r{^- downgraded stigapplied/\S+ purchasable -> }).size).to eq(56), out
        end
      end
    end
  end

  describe 'render.mjs run, started without the hardening flags' do
    it 'refuses to run page scripts' do
      out, st = Open3.capture2e(NODE_CT, File.join(ROOT_CT, 'scripts', 'render', 'render.mjs'), 'run',
                                CT_SITES['main'], 'index.html', stdin_data: "#{'a' * 64}\n")
      expect(st.exitstatus).to eq(2), out
      expect(out).to match(/not hardened/)
    end
  end
end

# ------------------------------------------------------------------------------------- claims, catalog, stage 1

CT_CLAIM = 'StigReady Applied is coming soon.'.freeze
CT_SAY = ->(style) { CT_EDIT.call('index.html', '</body>', %(<p style="#{style}">#{CT_CLAIM}</p></body>)) }
CT_CLAIMS = {
  'display:none' => CT_SAY.call('display:none'),
  'clip-path' => CT_SAY.call('clip-path:inset(0)'),
  'a 3D rotation' => CT_SAY.call('transform:rotateX(1deg)'),
  'a negative z-index' => CT_SAY.call('z-index:-1'),
  'a relative offset' => CT_SAY.call('position:relative;top:1000px'),
  'a mask' => CT_SAY.call('mask-image:linear-gradient(#000,#000)'),
  'a page the renderer cannot evaluate' => CT_PAGE.call('zz.html', <<~HTML),
    <!doctype html><html><head><title>Notes</title><script src="https://cdn.example.com/x.js"></script></head>
    <body><p>#{CT_CLAIM}</p></body></html>
  HTML
}.freeze
# The catalog hidden on its page, and a working copy of it on another page.
CT_DECOY = CT_BOTH.call(lambda do |dir|
  FileUtils.mkdir_p(File.join(dir, 'notes'))
  File.write(File.join(dir, 'notes', 'archive.html'),
             File.read(File.join(dir, 'index.html')).sub("fetch('catalog.json')", "fetch('/catalog.json')"))
end, CT_HIDE_DISPLAY)

control 'web-copy-truth-06' do
  impact 1.0
  title 'Claims cannot be hidden, listings count only from the catalog page, and the script stage cannot be impersonated'
  desc 'Security re-review of stigready-web#74, round 3: claims and catalog location; stage-1 output integrity.'

  CT_CLAIMS.each_with_index do |(how, mut), i|
    site = CT_SITE.call('main-e911b14', File.join(CT_TMP, "s-claim-#{i}"), &mut)
    CT_L1.call(site).then do |out, rc|
      describe "L1 with a false \"Applied is coming soon\" hidden by #{how}" do
        it('fails on the claim') do
          expect(rc).to eq(1), out
          expect(out).to match(/^- WITHHELD-TEXT \S+: StigReady Applied has 56 live Public listings/), out
        end
      end
    end
  end

  unev = CT_SITE.call('main-e911b14', File.join(CT_TMP, 's-unev-catalog'),
                      &CT_EDIT.call('index.html', '</head>', '<link rel="stylesheet" href="https://cdn.example.net/x.css"></head>'))
  CT_L1.call(unev).then do |out, rc|
    describe 'L1 on a catalog page the renderer cannot evaluate' do
      it('fails as UNEVALUABLE, not a warning') do
        expect(rc).to eq(1), out
        expect(out).to match(/^- UNEVALUABLE index\.html: the page loads an off-site stylesheet/)
      end
    end
  end

  CT_L1.call(CT_SITE.call('main-e911b14', File.join(CT_TMP, 's-decoy'), &CT_DECOY)).then do |out, rc|
    describe 'L1 with the catalog hidden and a working copy of it on another page' do
      it('fails: links elsewhere do not count') do
        expect(rc).to eq(1), out
        expect(out.scan(%r{^- (NOT-LINKED|MISSING) stigapplied/}).size).to eq(56), out
      end
    end
  end
  d = CtRepo.new('r-decoy')
  db = d.commit('main-e911b14', signers: OWNER_SIGNERS)
  dh = d.commit('main-e911b14', signers: OWNER_SIGNERS, &CT_DECOY)
  CT_L2.call(d, db, dh, 97).then do |out, rc|
    describe 'removal gate with the catalog hidden and a working copy of it on another page' do
      it('fails without an owner approval') do
        expect(rc).to eq(1), out
        expect(out.scan(%r{^- downgraded stigapplied/\S+ purchasable -> }).size).to eq(56), out
      end
    end
  end

  # Stage 1's output, replayed from another run or forged, is refused. The fake `node` answers the `run` stage with
  # a saved output and passes everything else to the real one.
  real = Open3.capture2(NODE_CT, '-p', 'process.execPath').first.strip
  cap = File.join(CT_TMP, 'stage1.out')
  fake = lambda do |name, body|
    f = File.join(CT_TMP, name)
    File.write(f, "#!/bin/bash\nfor a in \"$@\"; do [ \"$a\" = run ] && { #{body}; }; done\nexec #{real.shellescape} \"$@\"\n")
    File.chmod(0o755, f)
    f
  end
  l1 = lambda do |node|
    Open3.capture2e('python3', CHECK_CT, '--node', node, '--mode', 'pr', '--site', CT_SITES['main'],
                    '--snapshot', SNAP_SIGNED, '--snapshot-signers', CT_SNAP_SIGNERS, '--now', NOW_CT)
  end
  cap_out, cap_st = l1.call(fake.call('node-capture', %(#{real.shellescape} "$@" | tee #{cap.shellescape}; exit "${PIPESTATUS[0]}")))
  describe 'L1 through a node that only records the script stage' do
    it('passes, as without it') { expect(cap_st.exitstatus).to eq(0), cap_out }
  end
  replay = fake.call('node-replay', "cat #{cap.shellescape}; exit 0")
  rep_out, rep_st = l1.call(replay)
  describe 'a script-stage output replayed from another run' do
    it('is refused: cannot check') do
      expect(rep_st.exitstatus).to eq(2), rep_out
      expect(rep_out).to match(/not authentic/)
    end
  end
  saved = File.file?(cap) ? File.read(cap) : "x\n{}"
  body = saved.split("\n", 2)[1].to_s.gsub('"visible":false', '"visible":true')
  forged = File.join(CT_TMP, 'stage1.forged')
  File.write(forged, "#{OpenSSL::HMAC.hexdigest('SHA256', 'k' * 32, body)}\n#{body}")
  forge_out, forge_st = l1.call(fake.call('node-forge', "cat #{forged.shellescape}; exit 0"))
  describe 'a script-stage output forged with another key' do
    it('is refused: cannot check') do
      expect(forge_st.exitstatus).to eq(2), forge_out
      expect(forge_out).to match(/not authentic/)
    end
  end
end

# ------------------------------------------------------------------------------------ review of a6c10a03 (0173)

control 'web-copy-truth-07' do
  impact 1.0
  title 'The renderer holds no credentials, the snapshot is signed, and owner keys are enrolled, PIN-bound and plain'
  desc 'Security and QA reviews of stigready-web#74 at a6c10a03 (decision 0173, amending 0114). Each case must fail ' \
       '(exit 1) or be refused (exit 2).'

  # 1. GH_TOKEN never reaches the Node processes that run page scripts. A node that records its environment, then
  #    runs the real one.
  real = Open3.capture2(NODE_CT, '-p', 'process.execPath').first.strip
  envlog = File.join(CT_TMP, 'node-env')
  rec = File.join(CT_TMP, 'node-record-env')
  File.write(rec, "#!/bin/bash\n/usr/bin/env -0 > #{envlog.shellescape}.$$\nexec #{real.shellescape} \"$@\"\n")
  File.chmod(0o755, rec)
  sentinel = 'ct-sentinel-not-a-token'
  out, st = Open3.capture2e({ 'GH_TOKEN' => sentinel, 'GITHUB_TOKEN' => sentinel, 'AWS_SECRET_ACCESS_KEY' => sentinel,
                              'VAULT_TOKEN' => sentinel },
                            'python3', CHECK_CT, '--node', rec, '--mode', 'pr', '--site', CT_SITES['main'],
                            '--snapshot', SNAP_SIGNED, '--snapshot-signers', CT_SNAP_SIGNERS, '--now', NOW_CT)
  envs = Dir.glob("#{envlog}.*").map { |f| File.binread(f).split("\0").to_h { |kv| kv.split('=', 2) } }
  describe 'the renderer, started with GH_TOKEN, AWS and Vault variables in the checker\'s environment' do
    it('still renders (L1 passes on #73)') { expect(st.exitstatus).to eq(0), out }
    it('ran both stages') { expect(envs.size).to eq(2) }
    it('gets PATH only: no token, no AWS or Vault variable') do
      envs.each do |e|
        expect(e.keys - %w[PATH PWD SHLVL _ OLDPWD]).to eq([])
        expect(e.values.join("\n")).not_to include(sentinel)
      end
    end
  end

  # 2. The snapshot: the live/marketplace branch is pushable by any writer, so only its signature counts.
  unsigned = File.join(CT_TMP, 'snap-unsigned.json')
  FileUtils.cp(SNAP_CT, unsigned)
  other_key = File.join(CT_TMP, 'snapkey-other')
  Open3.capture2e('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'other', '-f', other_key)
  forged = CT_SIGN_SNAP.call(File.join(CT_TMP, 'snap-forged.json').tap { |f| FileUtils.cp(SNAP_CT, f) }, other_key)
  edited = CT_SIGN_SNAP.call(File.join(CT_TMP, 'snap-edited.json').tap { |f| FileUtils.cp(SNAP_CT, f) })
  File.write(edited, File.read(edited).sub('"Public"', '"Restricted"'))
  key_line = File.read(CT_SNAP_SIGNERS)
  validity = lambda do |name, opt|
    f = File.join(CT_TMP, "snapshot-signers-#{name}")
    File.write(f, key_line.sub('namespaces="stigready-marketplace-snapshot"', %(namespaces="stigready-marketplace-snapshot",#{opt})))
    f
  end
  expired = validity.call('expired', 'valid-before="20200101"')
  future = validity.call('future', 'valid-after="20990101"')
  unknown = validity.call('unknown', 'no-touch-required')
  verify_req = validity.call('verify-required', 'verify-required')
  no_keys = File.join(CT_TMP, 'snapshot-signers-empty')
  File.write(no_keys, "# no key yet\n")
  ca_keys = File.join(CT_TMP, 'snapshot-signers-ca')
  File.write(ca_keys, File.read(CT_SNAP_SIGNERS).sub('namespaces=', 'cert-authority,namespaces='))
  { 'an unsigned snapshot' => [unsigned, CT_SNAP_SIGNERS, /no signature/],
    'a snapshot signed by a key the base does not list' => [forged, CT_SNAP_SIGNERS, /signature does not verify/],
    'a snapshot edited after it was signed' => [edited, CT_SNAP_SIGNERS, /signature does not verify/],
    'a base that lists no snapshot key' => [SNAP_SIGNED, no_keys, /lists no snapshot key/],
    'a snapshot key listed as cert-authority' => [SNAP_SIGNED, ca_keys, /lists no snapshot key \(refused: line 1: cert-authority is refused\)/],
    'a snapshot key whose valid-before has passed' => [SNAP_SIGNED, expired, /signature does not verify/],
    'a snapshot key whose valid-after is in the future' => [SNAP_SIGNED, future, /signature does not verify/],
    'a snapshot key line with an option the checker does not support' =>
      [SNAP_SIGNED, unknown, /refused: line 1: unsupported option\(s\) no-touch-required/],
    'a snapshot key line carrying verify-required (an owner-key option)' =>
      [SNAP_SIGNED, verify_req, /refused: line 1: unsupported option\(s\) verify-required/] }
    .each do |what, (snap, signers, pat)|
    CT_L1.call(CT_SITES['after'], snap, signers: signers).then do |o, rc|
      describe "L1 with #{what}" do
        it('is exit 2, production state unknown') do
          expect(rc).to eq(2), o
          expect(o).to match(pat)
          expect(o).to match(/production state unknown/)
        end
      end
    end
  end

  # 3. Owner keys: verify-required, no cert-authority, enrolled on the owner's GitHub account, PIN on the signature.
  owner_cases = {
    'an owner key without verify-required' =>
      [SoftSK.pub_line(OWNER_KEY, opts: ''), nil, 5, 1, /lists no owner key/],
    'an owner key listed as cert-authority' =>
      [SoftSK.pub_line(OWNER_KEY, opts: ',verify-required,cert-authority'), nil, 5, 1, /lists no owner key/],
    'an owner key the owner\'s GitHub account does not list' =>
      [SoftSK.pub_line(OWNER_KEY), CT_GH_KEYS.call('other-only', [OTHER_KEY]), 5, 1,
       /enrolled as an SSH signing key of the owner's GitHub account/],
    'an owner key, with GitHub unreachable' =>
      [SoftSK.pub_line(OWNER_KEY), File.join(CT_TMP, 'gh-none.json'), 5, 2, /fetch https:\/\/api\.github\.com\/user\/\d+: URLError/],
    'a signature made without user verification (no PIN)' =>
      [SoftSK.pub_line(OWNER_KEY), nil, 1, 1, /does not verify/],
    'an owner key whose valid-before has passed' =>
      [SoftSK.pub_line(OWNER_KEY, opts: ',verify-required,valid-before="20200101"'), nil, 5, 1, /does not verify/],
    'an owner key line with an option the checker does not support' =>
      [SoftSK.pub_line(OWNER_KEY, opts: ',verify-required,no-touch-required'), nil, 5, 1,
       /refused: line 1: unsupported option\(s\) no-touch-required/]
  }
  owner_cases.each_with_index do |(what, (line, gh, flags, want_rc, pat)), i|
    r = CtRepo.new("r-owner-#{i}")
    signers = "#{line}\n"
    b = r.commit('main-e911b14', signers: signers)
    h = r.commit('main-e911b14', signers: signers, &HIDE_JS)
    CT_L2.call(r, b, CT_APPROVE.call(r, b, h, 60 + i, OWNER_KEY, flags: flags), 60 + i, gh: gh).then do |o, rc|
      describe "removal gate with #{what}" do
        it("fails (exit #{want_rc})") do
          expect(rc).to eq(want_rc), o
          expect(o).to match(pat)
        end
      end
    end
  end
  # The owner's account is pinned by its numeric id: an answer for another id is refused before any key is read.
  idr = CtRepo.new('r-owner-id')
  idb = idr.commit('main-e911b14', signers: OWNER_SIGNERS)
  idh = idr.commit('main-e911b14', signers: OWNER_SIGNERS, &HIDE_JS)
  CT_L2.call(idr, idb, CT_APPROVE.call(idr, idb, idh, 68, OWNER_KEY), 68, env: { 'CT_GH_USER_ID' => '1' }).then do |o, rc|
    describe 'removal gate when GitHub answers for another user id (a renamed or re-registered login)' do
      it('is exit 2: the owner\'s account is unknown') do
        expect(rc).to eq(2), o
        expect(o).to match(/answered id 1, not \d+: the owner's account is unknown/)
      end
    end
  end
  # ... and the same withdrawal, signed with a PIN by the enrolled, verify-required key, passes.
  ok = CtRepo.new('r-owner-ok')
  okb = ok.commit('main-e911b14', signers: OWNER_SIGNERS)
  okh = ok.commit('main-e911b14', signers: OWNER_SIGNERS, &HIDE_JS)
  CT_L2.call(ok, okb, CT_APPROVE.call(ok, okb, okh, 69, OWNER_KEY), 69).then do |o, rc|
    describe 'removal gate with a PIN signature by an enrolled verify-required owner key' do
      it('passes') { expect(rc).to eq(0), o }
    end
  end

  # 4. A signers change never rides with another withdrawal, even when the key that counts signs it.
  { 'config/owner-signers' => { signers: "#{OWNER_SIGNERS}#{SoftSK.pub_line(OTHER_KEY)}\n" },
    'config/snapshot-signers' => { signers: OWNER_SIGNERS, extra: { 'config/snapshot-signers' => File.read(CT_SNAP_SIGNERS) } } }
    .each_with_index do |(path, kw), i|
    r = CtRepo.new("r-alone-#{i}")
    b = r.commit('main-e911b14', signers: OWNER_SIGNERS)
    h = r.commit('main-e911b14', **kw, &HIDE_JS)
    CT_L2.call(r, b, CT_APPROVE.call(r, b, h, 70 + i, OWNER_KEY), 70 + i).then do |o, rc|
      describe "a PR that changes #{path} and withdraws listings, signed by the owner key" do
        it('fails: a signers change must be its own PR') do
          expect(rc).to eq(1), o
          expect(o).to include("- changed #{path} (")
          expect(o).to match(/signers change must be its own PR/)
        end
      end
    end
  end

  # ssh-keygen missing: exit 2, never a pass or a finding.
  nossh = File.join(CT_TMP, 'path-no-ssh')
  FileUtils.mkdir_p(nossh)
  py = Open3.capture2('python3', '-c', 'import sys; print(sys.executable)').first.strip
  File.symlink(py, File.join(nossh, 'python3')) unless File.exist?(File.join(nossh, 'python3'))
  ns_out, ns_st = Open3.capture2e({ 'PATH' => nossh }, File.join(nossh, 'python3'), CHECK_CT, '--node', NODE_CT, '--mode', 'pr',
                                  '--site', CT_SITES['main'], '--snapshot', SNAP_SIGNED, '--snapshot-signers', CT_SNAP_SIGNERS,
                                  '--now', NOW_CT)
  describe 'L1 when ssh-keygen cannot be run' do
    it('is exit 2: the signature is unchecked') do
      expect(ns_st.exitstatus).to eq(2), ns_out
      expect(ns_out).to match(/ssh-keygen could not verify a signature \(FileNotFoundError\)/)
    end
  end

  # 5. Drift mode without its sources file cannot check the READMEs: exit 2, not a silent skip.
  CT_RUN.call('--mode', 'drift', '--snapshot', SNAP_SIGNED, '--snapshot-signers', CT_SNAP_SIGNERS, '--now', NOW_CT,
              '--sources', File.join(CT_TMP, 'no-such-sources.yml'), '--site-url', 'https://invalid.example').then do |o, rc|
    describe 'drift mode with config/copy-truth-sources.yml missing' do
      it('is exit 2') do
        expect(rc).to eq(2), o
        expect(o).to match(/copy-truth-sources\.yml missing|no-such-sources\.yml missing/)
      end
    end
  end

  # 6. .gitignore matches the renderer's directories as symlinks too (the #84 class).
  g = File.join(CT_TMP, 'gi')
  FileUtils.mkdir_p(g)
  CT_GIT.call(g, 'init', '-q')
  FileUtils.cp(File.join(ROOT_CT, '.gitignore'), File.join(g, '.gitignore'))
  %w[node_modules .render scripts/render/node_modules].each do |rel|
    FileUtils.mkdir_p(File.dirname(File.join(g, rel)))
    File.symlink('/tmp', File.join(g, rel))
  end
  describe 'a node_modules or .render symlink' do
    %w[node_modules .render scripts/render/node_modules].each do |rel|
      it("#{rel} is ignored") do
        _, st2 = Open3.capture2e('git', '-C', g, 'check-ignore', '-q', rel)
        expect(st2.exitstatus).to eq(0)
      end
    end
  end
end

# ------------------------------------------------------------------------------------------------- trust root (0114)

control 'web-copy-truth-08' do
  impact 1.0
  title 'A change to what judges pull requests is named, by the base\'s checker in copy-truth and as a tripwire here'
  desc 'Security review of stigready-web#74 at c773a3a (finding 1) and a4d77aa: a PR could weaken the checker, the ' \
       'renderer, the copy-* jobs, the validate steps that run these controls, the schedule, or these controls. ' \
       'What it ENFORCES: copy-truth runs --mode trust-root with the BASE\'s checker, list and manifest, so its ' \
       'status names every such change and a PR cannot alter that comparison; copy-truth is advisory, so this ' \
       'detects and does not block (stigready-web#96 makes such a change need the owner\'s signature). What it ' \
       'only DETECTS: this control runs the PR\'s own checker and manifest in validate, so a PR can rewrite both; ' \
       'it is a tripwire that makes the manifest diff visible to review/security, not a control a PR cannot pass.'

  tr = lambda do |dir|
    o, st = Open3.capture2e('python3', CHECK_CT, '--mode', 'trust-root', '--repo', dir)
    [o, st.exitstatus]
  end
  tr.call(ROOT_CT).then do |o, rc|
    describe 'this tree against config/trust-root.sha256' do
      it('matches: every trust-root change in this PR is in the manifest') { expect(rc).to eq(0), o }
    end
  end

  # A copy of the trust root, then one change at a time.
  copy = lambda do |name|
    d = File.join(CT_TMP, "tr-#{name}")
    %w[config scripts cinc .cairn.yml].each do |rel|
      src = File.join(ROOT_CT, rel)
      next unless File.exist?(src)

      if File.directory?(src)
        FileUtils.mkdir_p(d)
        FileUtils.cp_r(src, d)
      else
        FileUtils.mkdir_p(d)
        FileUtils.cp(src, File.join(d, rel))
      end
    end
    FileUtils.rm_rf(Dir.glob(File.join(d, '**', 'node_modules')))
    d
  end
  edit = lambda do |dir, rel, from, to|
    f = File.join(dir, rel)
    t = File.read(f)
    raise "fixture: #{from} not in #{rel}" unless t.include?(from)

    File.write(f, t.sub(from, to))
  end
  {
    'the checker' => ['scripts/check-copy-vs-marketplace.py', 'SCHEMA = "stigready-marketplace-live/1"', 'SCHEMA = "x"',
                      'scripts/check-copy-vs-marketplace.py'],
    'the renderer' => ['scripts/render/render.mjs', "// SPDX-FileCopyrightText: 2026 StigReady\n", "// SPDX-FileCopyrightText: 2026 StigReady\n// x\n",
                       'scripts/render/render.mjs'],
    'the copy-truth job' => ['.cairn.yml', '--snapshot-signers "$t/base/config/snapshot-signers"', '--snapshot-signers x',
                             '.cairn.yml#copy-truth'],
    'these controls' => ['cinc/profiles/stigready-web/controls/copy_truth.rb', "impact 1.0\n", "impact 0.0\n",
                         'cinc/profiles/stigready-web/controls/copy_truth.rb'],
    'the snapshot keys' => ['config/snapshot-signers', '# Marketplace snapshot keys', '# keys',
                            'config/snapshot-signers'],
    'the list of trust-root paths' => ['config/trust-root-paths', "scripts/render/**\n", '',
                                       'config/trust-root-paths']
  }.each_with_index do |(what, (rel, from, to, entry)), i|
    d = copy.call("edit-#{i}")
    edit.call(d, rel, from, to)
    tr.call(d).then do |o, rc|
      describe "a change to #{what} with the manifest left alone" do
        it('fails, naming the entry') do
          expect(rc).to eq(1), o
          expect(o).to include("- changed trust root: #{entry} ")
        end
      end
    end
  end
  # Distinct names: `it` blocks run after the whole control is loaded, so a reused variable would be read too late.
  rewritten = copy.call('rewritten')
  edit.call(rewritten, 'scripts/check-copy-vs-marketplace.py', 'SCHEMA = "stigready-marketplace-live/1"', 'SCHEMA = "x"')
  Open3.capture2e('python3', CHECK_CT, '--mode', 'trust-root', '--repo', rewritten, '--write')
  rw_out, rw_rc = tr.call(rewritten)
  rw_manifest = File.read(File.join(rewritten, 'config', 'trust-root.sha256'))
  describe 'the same checker change with the manifest rewritten' do
    it('passes, and the manifest line for the checker changed (the diff review/security reads)') do
      expect(rw_rc).to eq(0), rw_out
      expect(rw_manifest).not_to eq(File.read(File.join(ROOT_CT, 'config', 'trust-root.sha256')))
    end
  end
  bare = copy.call('no-manifest')
  FileUtils.rm_f(File.join(bare, 'config', 'trust-root.sha256'))
  tr.call(bare).then do |o, rc|
    describe 'a tree without config/trust-root.sha256' do
      it('is exit 2') { expect(rc).to eq(2), o }
    end
  end
  # The base's checker, list and manifest (copy-truth): rewriting the PR's manifest does not hide the change.
  base_cmp = lambda do |dir|
    o, st = Open3.capture2e('python3', CHECK_CT, '--mode', 'trust-root', '--repo', dir, '--base', ROOT_CT)
    [o, st.exitstatus]
  end
  bc_out, bc_rc = base_cmp.call(rewritten)
  describe 'the checker change with the PR\'s manifest rewritten, judged against the base (copy-truth)' do
    it('fails, naming the checker') do
      expect(bc_rc).to eq(1), bc_out
      expect(bc_out).to include('- changed trust root: scripts/check-copy-vs-marketplace.py ')
    end
  end
  dropped = copy.call('dropped-entry')
  edit.call(dropped, 'config/trust-root-paths', "scripts/render/**\n", '')
  Open3.capture2e('python3', CHECK_CT, '--mode', 'trust-root', '--repo', dropped, '--write')
  edit.call(dropped, 'scripts/render/render.mjs', "// SPDX-FileCopyrightText: 2026 StigReady\n",
            "// SPDX-FileCopyrightText: 2026 StigReady\n// x\n")
  dr_out, dr_rc = base_cmp.call(dropped)
  describe 'a PR that drops scripts/render/** from its list, rewrites its manifest, then edits the renderer' do
    it('fails against the base: the base\'s list still names the renderer') do
      expect(dr_rc).to eq(1), dr_out
      expect(dr_out).to include('- changed trust root: scripts/render/render.mjs ')
      expect(dr_out).to include('- changed trust root: config/trust-root-paths ')
    end
  end
  # Steps of validate and the schedule are entries too.
  { 'the validate step that installs the renderer' => ['.cairn.yml', 'mkdir -p .render', 'mkdir -p .render2',
                                                       '.cairn.yml#validate/render-setup'],
    'the validate step that runs these controls' => ['.cairn.yml', 'cinc-auditor exec cinc/profiles/stigready-web',
                                                     'true || cinc-auditor exec cinc/profiles/stigready-web',
                                                     '.cairn.yml#validate/cinc-stigready-web'],
    'the copy-drift schedule' => ['.cairn.yml', 'cron: "30 6 * * *"', 'cron: "30 6 1 1 *"', '.cairn.yml#triggers/schedule'] }
    .each_with_index do |(what, (rel, from, to, entry)), i|
    sd = copy.call("step-#{i}")
    edit.call(sd, rel, from, to)
    tr.call(sd).then do |o, rc|
      describe "a change to #{what}" do
        it('fails, naming the entry') do
          expect(rc).to eq(1), o
          expect(o).to include("- changed trust root: #{entry} ")
        end
      end
    end
  end
  # A symlink under scripts/render is refused, never hashed as "missing".
  linked = copy.call('symlink')
  File.symlink('/etc/hosts', File.join(linked, 'scripts', 'render', 'extra.mjs'))
  ln_out, ln_rc = tr.call(linked)
  lw_out, lw_rc = Open3.capture2e('python3', CHECK_CT, '--mode', 'trust-root', '--repo', linked, '--write')
  describe 'a symlink under scripts/render' do
    it('fails, refused by name') do
      expect(ln_rc).to eq(1), ln_out
      expect(ln_out).to include('- refused trust root: scripts/render/extra.mjs is a symlink')
    end
    it('cannot be written into the manifest (exit 2)') do
      expect(lw_rc.exitstatus).to eq(2), lw_out
    end
  end

  describe 'the pipeline' do
    it('runs the trust-root comparison in copy-truth with the base\'s checker, list and manifest') do
      pipe = YAML.safe_load(File.read(File.join(ROOT_CT, '.cairn.yml')))
      job = (pipe['jobs'] || []).find { |j| j['name'] == 'copy-truth' }
      s = (job.dig('run', 'exec', 'steps') || []).map { |x| x['run'].to_s }.join("\n")
      expect(s).to include('python3 -I "$t/base/scripts/check-copy-vs-marketplace.py" --mode trust-root --repo . --base "$t/base"')
      expect(s).to include('|| rc=$?')
      expect(s).to include('exit "$rc"')
    end
    it('prints the Node version in every copy-* job') do
      pipe = YAML.safe_load(File.read(File.join(ROOT_CT, '.cairn.yml')))
      jobs = (pipe['jobs'] || []).select { |j| j['name'].to_s.start_with?('copy-') }
      expect(jobs).not_to be_empty
      jobs.each do |j|
        s = (j.dig('run', 'exec', 'steps') || []).map { |x| x['run'].to_s }.join("\n")
        expect(s).to include('echo "renderer: $("$node" --version) at $node"'), j['name']
      end
    end
  end
end
