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
#   web-copy-truth-03  L2 on git objects: #70 and both hiding tricks fail without an owner approval; a rendering-code
#                      change is removal-class; the review's bypasses (self-approval with no key on main, a deleted,
#                      emptied or symlinked owner-signers, an approval replayed on another PR or another base, a
#                      software or unlisted key, an edited, expired or too-long approval) all fail; only a signature
#                      by a FIDO2-type key listed on the base, over this PR and base, passes
#   web-copy-truth-04  the pipeline runs the checks from the base branch, the renderer pinned, no test hooks
#   web-copy-truth-05  hardened visibility evaluation and checker isolation: markup that hides the listings, a page
#                      the renderer cannot evaluate, and page scripts acting on the checker all fail; the script
#                      stage refuses to run unhardened
#   web-copy-truth-06  claims are read from all text (hiding a sentence never removes it), an unevaluable catalog
#                      page fails, listings count only from the catalog page, and the script stage's output cannot
#                      be replayed or forged
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

# ----------------------------------------------------------------------------------------------- render hardening

# Security re-review of stigready-web#74: hardened visibility evaluation and checker isolation. Each case hides the
# 56 Applied listings from a visitor, or makes a page the renderer cannot evaluate, or is a page script acting on the
# checker; each must fail L1 (and the removal gate, where noted).
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
  'a zero-height, overflow-hidden tbody' => [CT_TB_ATTR.call('style="display:block;height:0;overflow:hidden"'), true],
  'a tbody moved off the page' => [CT_TB_ATTR.call('style="position:absolute;left:-99999px"'), true],
  'a tbody scaled to 0' => [CT_TB_ATTR.call('style="transform:scale(0)"'), false],
  "the site's own .hidden class on the tbody" => [CT_EDIT.call('index.html', CT_TBODY, "#{CT_TBODY}hidden "), true],
  'text filled transparent' => [CT_TB_ATTR.call('style="-webkit-text-fill-color:transparent"'), true],
  'a tbody clipped away' => [CT_TB_ATTR.call('style="clip-path:inset(50%)"'), false],
  'a filter to opacity 0' => [CT_TB_ATTR.call('style="filter:opacity(0)"'), false],
  'content-visibility:hidden' => [CT_TB_ATTR.call('style="content-visibility:hidden"'), false],
  'two opacities that multiply below 0.1' => [CT_BOTH.call(CT_TB_ATTR.call('style="opacity:0.3"'),
                                                           CT_EDIT.call('index.html', '<table class="w-full text-sm min-w-[640px]">',
                                                                        '<table style="opacity:0.3" class="w-full text-sm min-w-[640px]">')), false],
  'the table inside a closed <details>' => [CT_EDIT.call('index.html', '<table class="w-full text-sm min-w-[640px]">',
                                                         '<details><summary>Products</summary><table class="w-full text-sm min-w-[640px]">'), true],
  'an opaque element positioned over the page' => [CT_EDIT.call('index.html', '</body>',
                                                                '<div style="position:fixed;inset:0;background:#111827"></div></body>'), true],
  'an off-site stylesheet the renderer cannot evaluate' => [CT_EDIT.call('index.html', '</head>',
                                                                         '<link rel="stylesheet" href="https://cdn.example.net/x.css"></head>'), false],
  # rebuilt Tailwind utilities (site.css changes too, so the removal gate already asks for approval; L1 must see them)
  'Tailwind .sr-only' => [CT_TW.call('.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;' \
                                     'clip:rect(0,0,0,0);white-space:nowrap;border-width:0}', 'sr-only'), false],
  'Tailwind .invisible' => [CT_TW.call('.invisible{visibility:hidden}', 'invisible'), false],
  'Tailwind .opacity-0' => [CT_TW.call('.opacity-0{opacity:0}', 'opacity-0'), false],
  # page scripts against the checker
  'a page script that escapes to Node and rewrites the output' => [CT_BOTH.call(CT_HIDE_DISPLAY,
                                                                                CT_PAGE.call('zz.html', CT_ESCAPE_PAGE)), true],
  "a page script that pollutes the renderer's Object.prototype" => [CT_BOTH.call(CT_HIDE_DISPLAY,
                                                                                 CT_PAGE.call('zz.html', CT_POLLUTE_PAGE)), true],
  "a page script that replaces the window's getComputedStyle" => [CT_EDIT.call('index.html', '</body>', CT_LIE_SCRIPT), false],
}.freeze

control 'web-copy-truth-05' do
  impact 1.0
  title 'Markup cannot hide listings from the renderer, and page scripts cannot change its result'
  desc 'Security re-review of stigready-web#74 (decision 0114 L1, L2): hardened visibility evaluation and checker ' \
       'isolation. Every case hides the Applied listings from a visitor, or tries to; every case must fail.'

  CT_HARDEN.each_with_index do |(what, (mut, l2)), i|
    site = CT_SITE.call('main-e911b14', File.join(CT_TMP, "s-harden-#{i}"), &mut)
    CT_L1.call(site).then do |out, rc|
      describe "L1 on #73 with #{what}" do
        it('fails: the Applied listings are not visibly linked') do
          expect(rc).to eq(1), out
          expect(out.scan(%r{^- (NOT-LINKED|MISSING) stigapplied/}).size).to eq(56), out
        end
      end
    end
    next unless l2

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
                    '--snapshot', SNAP_CT, '--now', NOW_CT)
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
