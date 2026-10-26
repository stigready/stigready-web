require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'
require 'yaml'

# Decision 0114 (claude-agents): public copy must match production. Decision 0003: CINC asserts.
#
# The fixtures are shaped like the incident of 2026-10-25. stigready-web#70 (e3c47e4) showed all 56 StigReady Applied
# products as "Coming soon" while all 56 listings were Public on AWS Marketplace:
#   files/copy-truth/incident-2026-10-25/before  the site at 0ef9b2c (the parent of #70): index, /applied/, catalog
#   files/copy-truth/incident-2026-10-25/after   the site at e3c47e4 (#70 merged)
#   files/copy-truth/marketplace-live-2026-10-26.json  a real snapshot (marketplace-live-snapshot.py, read-only
#                                                      marketplace-ro, 2026-10-26): 80 Public, 56 of them Applied
# Pages are stored as *.html.fixture, so the site's own checks (validate-site.py, web-copy-*) never read them as pages.
#
#   web-copy-truth-01  L1: #70 fails against production (56 products withheld, the line called coming soon); the
#                      parent passes
#   web-copy-truth-02  L1: a price that differs from live fails; a missing or stale snapshot cannot pass (exit 2); a
#                      row shown as purchasable with no live listing fails
#   web-copy-truth-03  L2: #70 fails the removal gate without an owner approval; only a signature that verifies over
#                      the canonical message, with a key from the base's owner-signers, unexpired, passes; a
#                      software key does not count
#   web-copy-truth-04  the pipeline runs both checks from the base branch, never from the PR, never with the test flag

ROOT_CT    = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
CHECK_CT   = File.join(ROOT_CT, 'scripts', 'check-copy-vs-marketplace.py')
FIX_CT     = File.join(File.dirname(__FILE__), '..', 'files', 'copy-truth')
SNAP_CT    = File.join(FIX_CT, 'marketplace-live-2026-10-26.json')
NOW_CT     = '2026-10-26T12:00:00Z'.freeze
TODAY_CT   = '2026-10-26'.freeze

# Copy a fixture tree to dir, *.html.fixture -> *.html.
CT_SITE = lambda do |name, dir|
  src = File.join(FIX_CT, 'incident-2026-10-25', name)
  Dir.glob('**/*', base: src).each do |rel|
    from = File.join(src, rel)
    next if File.directory?(from)

    to = File.join(dir, rel.sub(/\.html\.fixture\z/, '.html'))
    FileUtils.mkdir_p(File.dirname(to))
    FileUtils.cp(from, to)
  end
  dir
end

CT_RUN = lambda do |*args|
  out, st = Open3.capture2e('python3', CHECK_CT, *args)
  [out, st.exitstatus]
end

CT_TMP = Dir.mktmpdir('copy-truth-')
at_exit { FileUtils.rm_rf(CT_TMP) }
CT_BEFORE = CT_SITE.call('before', File.join(CT_TMP, 'before'))
CT_AFTER  = CT_SITE.call('after', File.join(CT_TMP, 'after'))

CT_SNAP_WITH = lambda do |name, &edit|
  snap = JSON.parse(File.read(SNAP_CT))
  edit.call(snap)
  path = File.join(CT_TMP, name)
  File.write(path, JSON.generate(snap))
  path
end

control 'web-copy-truth-01' do
  impact 1.0
  title 'L1: the site of stigready-web#70 fails against live Marketplace; its parent passes'
  desc 'Fail-first for decision 0114 L1: every live-Public Applied product shown as coming soon is a finding.'

  CT_RUN.call('--mode', 'pr', '--site', CT_AFTER, '--snapshot', SNAP_CT, '--now', NOW_CT).then do |out, rc|
    describe 'check-copy-vs-marketplace.py --mode pr on #70 (e3c47e4)' do
      it('exits 1') { expect(rc).to eq(1), out }
      it('finds all 56 live-Public Applied products shown as coming soon') do
        expect(out.scan(/^- WITHHELD stigapplied\//).size).to eq(56)
      end
      it 'finds the line-level "Applied ... coming soon" sentences' do
        expect(out).to match(/WITHHELD-TEXT index\.html: StigReady Applied has 56 live Public listings/)
        expect(out).to match(%r{WITHHELD-TEXT applied/index\.html: StigReady Applied})
      end
      it('never calls Base withheld (Base is on Marketplace in the same sentences)') do
        expect(out).not_to match(/WITHHELD(?:-TEXT)? .*StigReady Base has/)
        expect(out).not_to match(%r{^- WITHHELD stigready/})
      end
    end
  end

  out_b, rc_b = CT_RUN.call('--mode', 'pr', '--site', CT_BEFORE, '--snapshot', SNAP_CT, '--now', NOW_CT)
  describe 'check-copy-vs-marketplace.py --mode pr on the parent of #70 (0ef9b2c)' do
    it('exits 0: it made no availability claim production contradicts') { expect(rc_b).to eq(0), out_b }
  end
end

control 'web-copy-truth-02' do
  impact 1.0
  title 'L1: prices, unknown production state and purchasable-but-not-live rows'
  desc 'A price that differs from the live offer fails. A missing, stale or malformed snapshot is exit 2, never a pass.'

  wrong = CT_SNAP_WITH.call('wrong-price.json') do |s|
    s['prices'] = { 'stigready' => { 'hourly_usd' => '0.02', 'annual_usd' => '149' },
                    'stigapplied' => { 'hourly_usd' => '0.10', 'annual_usd' => '649' } }
  end
  right = CT_SNAP_WITH.call('right-price.json') do |s|
    s['prices'] = { 'stigready' => { 'hourly_usd' => '0.02', 'annual_usd' => '149' },
                    'stigapplied' => { 'hourly_usd' => '0.08', 'annual_usd' => '649' } }
  end
  no_base = CT_SNAP_WITH.call('no-base-alma10.json') do |s|
    s['products'].reject! { |p| p['line'] == 'stigready' && p['os_key'] == 'alma-10' && p['arch'] == 'x86_64' }
  end
  bad = File.join(CT_TMP, 'bad.json')
  File.write(bad, '{"schema": "something-else"}')

  CT_RUN.call('--mode', 'pr', '--site', CT_BEFORE, '--snapshot', wrong, '--now', NOW_CT).then do |out, rc|
    describe 'a site price that differs from the live price' do
      it('exits 1 with a PRICE finding for Applied hourly') do
        expect(rc).to eq(1), out
        expect(out).to match(/^- PRICE .*StigReady Applied hourly \$0\.08 on the site, \$0\.1 live/)
      end
    end
  end

  CT_RUN.call('--mode', 'pr', '--site', CT_BEFORE, '--snapshot', right, '--now', NOW_CT).then do |out, rc|
    describe 'site prices equal to the live prices' do
      it('exit 0 and no price warning') do
        expect(rc).to eq(0), out
        expect(out).not_to match(/PRICE/)
      end
    end
  end

  CT_RUN.call('--mode', 'pr', '--site', CT_BEFORE, '--snapshot', SNAP_CT, '--now', NOW_CT).then do |out, rc|
    describe 'a snapshot with no live price (no Offer read yet)' do
      it('warns PRICE-UNVERIFIED, does not fail') do
        expect(rc).to eq(0), out
        expect(out).to match(/PRICE-UNVERIFIED StigReady Applied hourly \$0\.08/)
      end
    end
  end

  CT_RUN.call('--mode', 'pr', '--site', CT_AFTER, '--snapshot', no_base, '--now', NOW_CT).then do |out, rc|
    describe 'a row linked as purchasable whose listing is not live Public' do
      it('fails NOT-LIVE') do
        expect(rc).to eq(1), out
        expect(out).to match(%r{^- NOT-LIVE stigready/base/alma-10/x86_64})
      end
    end
  end

  [['stale (30 h)', ['--snapshot', SNAP_CT, '--now', '2026-10-27T16:10:00Z']],
   ['missing', ['--snapshot', File.join(CT_TMP, 'nope.json'), '--now', NOW_CT]],
   ['another schema', ['--snapshot', bad, '--now', NOW_CT]],
   ['not given', ['--now', NOW_CT]]].each do |what, extra|
    out, rc = CT_RUN.call('--mode', 'pr', '--site', CT_BEFORE, *extra)
    describe "a #{what} snapshot" do
      it('is exit 2, production state unknown, never a pass') do
        expect(rc).to eq(2), out
        expect(out).to match(/production state unknown|cannot check/)
      end
    end
  end
end

control 'web-copy-truth-03' do
  impact 1.0
  title 'L2: #70 cannot merge without the owner\'s signed approval; nothing else stands in for it'
  desc 'The signature is made at test time with a throwaway key; no private key is committed.'

  signers_none = File.join(ROOT_CT, 'config', 'owner-signers')
  CT_RUN.call('--mode', 'removal', '--base-site', CT_BEFORE, '--site', CT_AFTER, '--signers', signers_none).then do |out, rc|
    describe 'removal gate on #70 with no approval' do
      it('exits 1 and lists the 56 Applied products withdrawn') do
        expect(rc).to eq(1), out
        expect(out.scan(%r{^- downgraded stigapplied/\S+ neutral -> withheld$}).size).to eq(56)
        expect(out).to match(/no owner approval/)
      end
    end
  end

  CT_RUN.call('--mode', 'removal', '--base-site', CT_AFTER, '--site', CT_BEFORE, '--signers', signers_none).then do |out, rc|
    describe 'the reverse change (nothing withdrawn; Base links go back to no claim)' do
      it('lists only the 24 Base rows that lose their link') do
        expect(out.scan(%r{^- downgraded stigready/base/\S+ purchasable -> neutral$}).size).to eq(24)
        expect(out).not_to match(/stigapplied/)
      end
    end
  end

  CT_RUN.call('--mode', 'removal', '--base-site', CT_BEFORE, '--site', CT_BEFORE, '--signers', signers_none).then do |out, rc|
    describe 'an unchanged site' do
      it('passes with nothing withdrawn') { expect(rc).to eq(0), out }
    end
  end

  # A signed approval. The head is a copy of #70 with the approval files added.
  head = File.join(CT_TMP, 'after-approved')
  FileUtils.cp_r(CT_AFTER, head)
  key = File.join(CT_TMP, 'k')
  Open3.capture2e('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'test', '-f', key)
  pub = File.read("#{key}.pub").strip
  signers = File.join(CT_TMP, 'signers-soft')
  File.write(signers, %(owner@stigready namespaces="stigready-owner-approval" #{pub}\n))

  sign = lambda do |expires|
    msg, = Open3.capture2('python3', CHECK_CT, '--mode', 'approval-message', '--base-site', CT_BEFORE, '--site', head,
                          '--expires', expires)
    digest = msg[/^digest: (\h{64})$/, 1]
    dir = File.join(head, 'approvals', 'owner')
    FileUtils.rm_rf(dir)
    FileUtils.mkdir_p(dir)
    txt = File.join(dir, "#{digest}.txt")
    File.write(txt, msg)
    Open3.capture2e('ssh-keygen', '-Y', 'sign', '-f', key, '-n', 'stigready-owner-approval', txt)
    FileUtils.mv("#{txt}.sig", File.join(dir, "#{digest}.sig"))
    txt
  end

  txt = sign.call('2026-11-02')
  base_args = ['--mode', 'removal', '--base-site', CT_BEFORE, '--site', head, '--now', NOW_CT]

  CT_RUN.call(*base_args, '--signers', signers).then do |out, rc|
    describe 'a valid signature by a software (non-FIDO2) key' do
      it('does not count: the agent could make one') do
        expect(rc).to eq(1), out
        expect(out).to match(/lists no FIDO2/)
      end
    end
  end

  CT_RUN.call(*base_args, '--signers', signers, '--test-allow-software-key').then do |out, rc|
    describe 'a valid signature over the canonical message, key in the base signers (test flag stands in for FIDO2)' do
      it('passes') do
        expect(rc).to eq(0), out
        expect(out).to match(/owner approval \h{12} verifies, expires 2026-11-02/)
      end
    end
  end

  other = File.join(CT_TMP, 'k2')
  Open3.capture2e('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'other', '-f', other)
  signers_other = File.join(CT_TMP, 'signers-other')
  File.write(signers_other, %(owner@stigready namespaces="stigready-owner-approval" #{File.read("#{other}.pub").strip}\n))
  CT_RUN.call(*base_args, '--signers', signers_other, '--test-allow-software-key').then do |out, rc|
    describe 'a signature by a key the base does not list' do
      it('fails') do
        expect(rc).to eq(1), out
        expect(out).to match(/does not verify/)
      end
    end
  end

  File.write(txt, File.read(txt).sub("expires: 2026-11-02\n", "expires: 2026-11-02\n- removed nothing\n"))
  CT_RUN.call(*base_args, '--signers', signers, '--test-allow-software-key').then do |out, rc|
    describe 'an approval whose message was edited after signing' do
      it('fails') { expect(rc).to eq(1), out }
    end
  end

  sign.call('2026-12-31')
  CT_RUN.call(*base_args, '--signers', signers, '--test-allow-software-key').then do |out, rc|
    describe 'an approval that expires more than 14 days out' do
      it('fails') do
        expect(rc).to eq(1), out
        expect(out).to match(/must be between today and 14 days out/)
      end
    end
  end

  sign.call('2026-10-25')
  CT_RUN.call(*base_args, '--signers', signers, '--test-allow-software-key').then do |out, rc|
    describe 'an expired approval' do
      it('fails') { expect(rc).to eq(1), out }
    end
  end

  head_signers = File.join(CT_TMP, 'head-signers')
  File.write(head_signers, "#{File.read(signers_none)}# changed\n")
  CT_RUN.call('--mode', 'removal', '--base-site', CT_BEFORE, '--site', CT_BEFORE, '--signers', signers_none,
                        '--head-signers', head_signers).then do |out, rc|
    describe 'a PR that changes config/owner-signers' do
      it('is a removal-class change that needs a signature') do
        expect(rc).to eq(1), out
        expect(out).to match(%r{changed config/owner-signers})
      end
    end
  end
end

control 'web-copy-truth-04' do
  impact 1.0
  title 'The pipeline runs copy-truth and copy-removal-gate from the base branch, on every PR, without the test flag'
  desc 'A PR must not be able to change the checker, the snapshot or the signers that judge it.'

  pipe = YAML.safe_load(File.read(File.join(ROOT_CT, '.cairn.yml')))
  jobs = (pipe['jobs'] || []).to_h { |j| [j['name'], j] }
  text = File.read(File.join(ROOT_CT, '.cairn.yml'))
  steps = lambda do |name|
    ((jobs.dig(name, 'run', 'exec', 'steps')) || []).map { |s| s['run'].to_s }.join("\n")
  end

  describe 'stigready-web .cairn.yml' do
    it 'never passes --test-allow-software-key' do
      expect(text).not_to include('--test-allow-software-key')
    end

    %w[copy-truth copy-removal-gate].each do |name|
      it "has #{name} on pull requests, under its own status" do
        expect(jobs.dig(name, 'when')).to eq('pull_request')
        expect(jobs.dig(name, 'status')).to eq(name)
      end

      it "#{name} runs the checker taken from origin/$CAIRN_BASE_REF, not the PR's" do
        s = steps.call(name)
        expect(s).to include('git archive "origin/${CAIRN_BASE_REF:?}"')
        expect(s).to match(%r{python3 -I "\$t/base/scripts/check-copy-vs-marketplace\.py"})
      end
    end

    it 'copy-removal-gate is not advisory and reads the signers from the base' do
      expect(jobs.dig('copy-removal-gate', 'advisory')).not_to eq(true)
      expect(steps.call('copy-removal-gate')).to include('--signers "$t/base/config/owner-signers"')
    end

    it 'copy-truth reads the snapshot from the live/marketplace branch' do
      expect(steps.call('copy-truth')).to include('live/marketplace')
    end

    it 'copy-drift-watch is manual and scheduled as copy-drift' do
      expect(jobs.dig('copy-drift-watch', 'when')).to eq('manual')
      sched = (pipe.dig('triggers', 'schedule') || []).find { |s| s['name'] == 'copy-drift' }
      expect(sched && sched['jobs']).to eq(['copy-drift-watch'])
      expect(jobs.dig('copy-drift-watch', 'github_token', 'permissions')).to eq('issues' => 'write')
    end
  end

  describe file(File.join(ROOT_CT, 'config', 'owner-signers')) do
    it { should exist }
  end
end
