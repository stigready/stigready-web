# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# The public evidence summary pages under applied/evidence/ (decision 0003: CINC asserts).
# - web-evidence-pages-match-input: every page is exactly what scripts/build-evidence-pages.py writes from
#   config/applied-evidence.json and catalog.json (no hand edit, no stale page), each SBOM download is the signed SBOM,
#   and every available Applied row of catalog.json has a page for the version it sells.
# - web-evidence-pages-guard-fails: the generator refuses inputs that would publish an untrue or internal page.
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'

EV_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
EV_GEN = File.join(EV_ROOT, 'scripts', 'build-evidence-pages.py')
EV_INPUT = File.join(EV_ROOT, 'config', 'applied-evidence.json')
EV_DOC = JSON.parse(File.read(EV_INPUT))
EV_CATALOG = JSON.parse(File.read(File.join(EV_ROOT, 'catalog.json')))
EV_TMP = Dir.mktmpdir('evidence-pages-')
at_exit { FileUtils.rm_rf(EV_TMP) }

EV_RUN = lambda do |*args|
  out, st = Open3.capture2e('python3', EV_GEN, *args)
  [out, st.exitstatus]
end

# Run --check against the real pages with a mutated copy of the input; return [output, exit status].
EV_MUTATED = lambda do |name, &mutate|
  doc = JSON.parse(JSON.generate(EV_DOC))
  mutate.call(doc)
  path = File.join(EV_TMP, "#{name}.json")
  File.write(path, JSON.generate(doc))
  EV_RUN.call('--check', '--input', path)
end

control 'web-evidence-pages-match-input' do
  impact 1.0
  title 'applied/evidence/ is exactly what build-evidence-pages.py writes from config/applied-evidence.json'
  out, status = EV_RUN.call('--check')
  describe 'build-evidence-pages.py --check' do
    it("exits 0 (output: #{out.strip[0, 2000]})") { expect(status).to eq(0) }
  end
  applied = EV_CATALOG.fetch('products', []).select { |p| p['line'] == 'stigapplied' && p['availability'] == 'available' }
  describe 'available Applied rows of catalog.json with no evidence page for the version they sell' do
    subject do
      applied.reject do |p|
        File.file?(File.join(EV_ROOT, 'applied', 'evidence', "#{p['os_key']}-#{p['arch']}-#{p['profile']}", "v#{p['version']}", 'index.html'))
      end.map { |p| "#{p['os_key']}-#{p['arch']}-#{p['profile']} v#{p['version']}" }
    end
    it { should be_empty }
  end
end

control 'web-evidence-pages-guard-fails' do
  impact 1.0
  title 'The evidence page generator refuses an input that would publish an untrue or internal page'
  first_cis = ->(d) { d['cells'].find { |c| c['profile'] != 'stig' } }
  first = ->(d) { d['cells'].first }
  cases = {
    'a score that differs from catalog.json' => ->(d) { first.call(d)['scorecard']['score'] += 0.1 },
    'an extract problem' => ->(d) { first.call(d)['problems'] = ['bundle version 1.0.0 is not 1.0.2'] },
    'an unverified signature' => ->(d) { first.call(d)['signature']['cosign_verified'] = nil },
    'a bundle not matched to the live listing' => ->(d) { first.call(d)['ami_matches_live_listing'] = false },
    'FIPS on a CIS image' => ->(d) { first_cis.call(d)['fips'] = true },
    'an exemption class with no public label' => ->(d) { first.call(d)['exemptions'].first['class'] = 'new-class' },
    'a failing rule with no exemption' => ->(d) { first.call(d)['exemptions'].pop },
    'an AMI id in published text' => ->(d) { first.call(d)['exemptions'].first['why'] += ' See ami-0123456789abcdef0.' },
    'an internal record in published text' => ->(d) { first.call(d)['exemptions'].first['why'] += ' Decision 0070.' },
    'a GovCloud claim in published text' => ->(d) { first.call(d)['exemptions'].first['customer_action'] += ' GovCloud too.' },
    'a version that catalog.json does not sell' => ->(d) { first.call(d)['version'] = '9.9.9' },
    'an extract made without the live-listing check' => ->(d) { d['live_listings_checked'] = false },
    'a missing version' => ->(d) { d['cells'].shift },
  }
  cases.each do |name, mutate|
    out, status = EV_MUTATED.call(name.gsub(/\W+/, '-'), &mutate)
    describe "build-evidence-pages.py --check on #{name}" do
      it("exits 1 (output: #{out.strip[0, 300]})") { expect(status).to eq(1) }
    end
  end
end
