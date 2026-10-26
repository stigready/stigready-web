require 'base64'
require 'fileutils'
require 'json'
require 'open3'
require 'openssl'
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
#   web-copy-truth-03  L2 on git objects: #70 and both hiding tricks fail without an owner approval; a rendering-code
#                      change is removal-class; the review's bypasses (self-approval with no key on main, a deleted,
#                      emptied or symlinked owner-signers, an approval replayed on another PR or another base, a
#                      software or unlisted key, an edited, expired or too-long approval) all fail; only a signature
#                      by a FIDO2-type key listed on the base, over this PR and base, passes
#   web-copy-truth-04  the pipeline runs the checks from the base branch, the renderer pinned, no test hooks
#
# The FIDO2-type key in these tests is made in software (SoftSK below), as the security review showed anyone can:
# the key TYPE proves no touch. What protects the gate is that only the owner's key is listed on the base, and that
# only the owner merges a change to that list.

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

  def self.pub_line(key)
    %(owner@stigready namespaces="#{NS_CT}" #{KT} #{Base64.strict_encode64(blob(key))} soft)
  end

  def self.sign(key, msg)
    signed = 'SSHSIG'.b + s(NS_CT) + s('') + s('sha512') + s(OpenSSL::Digest::SHA512.digest(msg))
    flags = [5].pack('C')
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

CT_RUN = lambda do |*args|
  out, st = Open3.capture2e('python3', CHECK_CT, '--node', NODE_CT, *args)
  [out, st.exitstatus]
end

CT_L1 = lambda do |site, snap = SNAP_CT, now = NOW_CT|
  CT_RUN.call('--mode', 'pr', '--site', site, '--snapshot', snap, '--now', now)
end

CT_SNAP_WITH = lambda do |name, &edit|
  snap = JSON.parse(File.read(SNAP_CT))
  edit.call(snap)
  path = File.join(CT_TMP, name)
  File.write(path, JSON.generate(snap))
  path
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

CT_L2 = lambda do |repo, base, head, pr|
  CT_RUN.call('--mode', 'removal', '--repo', repo.dir, '--base-ref', base, '--head-ref', head, '--pr', pr.to_s,
              '--now', NOW_CT)
end

# Ask the checker for the canonical message of (base, head, pr), sign it, and commit both files onto head's branch.
CT_APPROVE = lambda do |repo, base, head, pr, key, expires: '2026-11-02', edit: nil|
  msg, st = Open3.capture2('python3', CHECK_CT, '--node', NODE_CT, '--mode', 'approval-message', '--repo', repo.dir,
                           '--base-ref', base, '--head-ref', head, '--pr', pr.to_s, '--expires', expires,
                           '--now', NOW_CT)
  raise "approval-message failed: #{msg}" unless st.success?

  digest = msg[/^digest: (\h{64})$/, 1]
  sig = SoftSK.sign(key, msg)
  msg = edit.call(msg) if edit
  repo.commit(nil, keep: true, signers: File.read(File.join(repo.dir, 'config', 'owner-signers')),
                   extra: { "approvals/owner/#{digest}.txt" => msg, "approvals/owner/#{digest}.sig" => sig })
end

OWNER_KEY = OpenSSL::PKey.generate_key('ED25519')
OTHER_KEY = OpenSSL::PKey.generate_key('ED25519')
OWNER_SIGNERS = "# fixture\n#{SoftSK.pub_line(OWNER_KEY)}\n".freeze

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
      it('finds the "Applied ... coming soon" sentences') do
        expect(out).to match(/WITHHELD-TEXT index\.html: StigReady Applied has 56 live Public listings/)
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
  [['stale (30 h)', SNAP_CT, '2026-10-27T16:10:00Z'], ['missing', File.join(CT_TMP, 'nope.json'), NOW_CT],
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
      it('fails, listing 56 Applied products downgraded and the changed rendering code') do
        expect(rc).to eq(1), out
        expect(out.scan(%r{^- downgraded stigapplied/\S+ neutral -> withheld$}).size).to eq(56)
        expect(out).to match(/^- changed rendering code: index\.html inline scripts$/)
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
  { 'availabilityCell `if (false && ...)`' => [HIDE_JS, /^- downgraded \S+ purchasable -> withheld$/, 80,
                                               'index.html inline scripts'],
    'a CSS display:none on the links' => [HIDE_CSS, /^- downgraded \S+ purchasable -> neutral$/, 80,
                                          'assets/css/site.css'] }.each do |what, (mut, pat, n, surface)|
    h = CtRepo.new("r-#{surface.tr('/ .', '---')}")
    b = h.commit('main-e911b14', signers: OWNER_SIGNERS)
    hd = h.commit('main-e911b14', signers: OWNER_SIGNERS, &mut)
    CT_L2.call(h, b, hd, 74).then do |out, rc|
      describe "removal gate on #73's site with #{what}" do
        it("fails: #{n} products downgraded and the rendering code changed") do
          expect(rc).to eq(1), out
          expect(out.scan(pat).size).to eq(n)
          expect(out).to include("- changed rendering code: #{surface}")
        end
      end
    end
  end

  # A rendering-code change that hides nothing still needs a signature.
  c = CtRepo.new('r-css-harmless')
  cb = c.commit('main-e911b14', signers: OWNER_SIGNERS)
  ch = c.commit('main-e911b14', signers: OWNER_SIGNERS) do |dir|
    File.open(File.join(dir, 'assets', 'css', 'site.css'), 'a') { |f| f.write("\n.unused-x{color:red}\n") }
  end
  CT_L2.call(c, cb, ch, 80).then do |out, rc|
    describe 'a stylesheet change that hides nothing' do
      it('is still removal-class') do
        expect(rc).to eq(1), out
        expect(out).to include('- changed rendering code: assets/css/site.css')
      end
    end
  end

  # 3. Self-approval: main lists no key; the PR adds its own key and signs (review finding 1).
  s = CtRepo.new('r-bootstrap')
  sb = s.commit('main-e911b14', signers: "# no key yet\n")
  sh = s.commit('main-e911b14', signers: OWNER_SIGNERS, &HIDE_JS)
  sa = CT_APPROVE.call(s, sb, sh, 90, OWNER_KEY)
  CT_L2.call(s, sb, sa, 90).then do |out, rc|
    describe 'a PR that adds its own key while main lists none, and signs with it' do
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
    it 'copy-removal-gate is not advisory, judges HEAD against the base by git objects, and binds the PR number' do
      expect(jobs.dig('copy-removal-gate', 'advisory')).not_to eq(true)
      s = steps.call('copy-removal-gate')
      expect(s).to include('--base-ref "origin/${CAIRN_BASE_REF:?}" --head-ref HEAD --pr "${CAIRN_PR:?}"')
    end
    it 'copy-truth reads the snapshot from the live/marketplace branch' do
      expect(steps.call('copy-truth')).to include('live/marketplace')
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
