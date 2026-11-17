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

# Run --check against the real pages with a mutated copy of the input (and, optionally, of catalog.json); return
# [output, exit status].
EV_MUTATED = lambda do |name, mutate, mutate_catalog = nil|
  doc = JSON.parse(JSON.generate(EV_DOC))
  mutate&.call(doc)
  path = File.join(EV_TMP, "#{name}.json")
  File.write(path, JSON.generate(doc))
  args = ['--check', '--input', path]
  if mutate_catalog
    cat = JSON.parse(JSON.generate(EV_CATALOG))
    mutate_catalog.call(cat)
    cpath = File.join(EV_TMP, "#{name}-catalog.json")
    File.write(cpath, JSON.generate(cat))
    args += ['--catalog', cpath]
  end
  EV_RUN.call(*args)
end

EV_PAGES = Dir.glob(File.join(EV_ROOT, 'applied', 'evidence', '*', 'v*', 'index.html')).sort.to_h do |f|
  [f.delete_prefix("#{EV_ROOT}/"), File.read(f)]
end
EV_APPLIED_INDEX = File.read(File.join(EV_ROOT, 'applied', 'index.html'))
EV_INDEX = File.read(File.join(EV_ROOT, 'applied', 'evidence', 'index.html'))
EV_PAGES_OF = ->(re) { EV_PAGES.select { |rel, _| rel.match?(re) } }

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
  rhel9 = ->(d) { d['cells'].find { |c| c['os_key'] == 'rhel-9' } }
  cases.merge!(
    # security review S1-S5 of stigready-web#99
    'zero OS-package findings on a release where zero was never reviewed' =>
      ->(d) { rhel9.call(d)['cve']['classes']['os-pkgs']['findings'] = 0 },
    'a CVE scan with no OS-package result' => ->(d) { first.call(d)['cve']['classes'].delete('os-pkgs') },
    'a Trivy result class with no public wording' =>
      ->(d) { first.call(d)['cve']['classes']['secret'] = first.call(d)['cve']['classes']['os-pkgs'] },
    'markup in a rule count' => ->(d) { first.call(d)['scorecard']['pass'] = '<b>1</b>' },
    'a string in a CVE count' => ->(d) { first.call(d)['cve']['classes']['os-pkgs']['distinct']['high'] = '1' },
    'a fraction for the SBOM component count' => ->(d) { first.call(d)['sbom']['components'] = 3.5 },
    'a string for the manifest file count' => ->(d) { first.call(d)['signature']['manifest_files'] = '22' },
    'a cell that is not os_key-arch-profile' => ->(d) { first.call(d)['cell'] = '../../index' },
    'a version that is not N.N.N' => ->(d) { first.call(d)['version'] = '1.0.2"><script>' },
  )
  cases.each do |name, mutate|
    out, status = EV_MUTATED.call(name.gsub(/\W+/, '-'), mutate)
    describe "build-evidence-pages.py --check on #{name}" do
      it("exits 1 (output: #{out.strip[0, 300]})") { expect(status).to eq(1) }
    end
  end
  out, status = EV_MUTATED.call('listing-url', nil, lambda do |cat|
    cat['products'].find { |p| p['line'] == 'stigapplied' }['marketplace_url'] = 'https://example.com/pp/x'
  end)
  describe 'build-evidence-pages.py --check on a catalog.json listing URL outside AWS Marketplace' do
    it("exits 1 (output: #{out.strip[0, 300]})") { expect(status).to eq(1) }
  end
end

control 'web-evidence-pages-say-what-was-assessed' do
  impact 1.0
  title 'Evidence pages name each STIG honestly and never print an OS CVE count Trivy could not assess (stigready-web#99)'
  describe 'version pages found' do
    it { expect(EV_PAGES.size).to be >= 56 }
  end
  EV_PAGES_OF.call(%r{/(rhel|rocky|alma)-10-}).each do |rel, body|
    describe "#{rel} (EL 10: Trivy does not assess the OS packages)" do
      it { expect(body).to match(/Not (fully )?assessed\./) }
      it('labels any OS count it shows as a lower bound') do
        expect(body[%r{<h3>OS packages</h3>(.*?)(?:<h3>|<p class="muted">The per-CVE list)}m, 1].to_s).not_to include('<td>CVEs found</td>')
      end
    end
  end
  EV_PAGES_OF.call(%r{/(rocky|alma)-[89]-}).each do |rel, body|
    describe "#{rel} (Rocky/Alma advisories list fixed CVEs only)" do
      it { expect(body).to include('lists only CVEs that have a published fix') }
    end
  end
  EV_PAGES.each do |rel, body|
    describe "#{rel} CVE wording" do
      it('counts OS and language packages separately') { expect(body).to include('counted separately') }
      it('never says the counts are OS packages only') { expect(body).not_to include('in the installed OS packages') }
      it('shows commands as code, not literal backticks') { expect(body).not_to include('`') }
    end
  end
  {
    %r{/(rocky|alma)-8-[^/]+-stig/} => 'with DISA RHEL 8 STIG',
    %r{/(rocky|alma)-9-[^/]+-stig/} => 'with DISA RHEL 9 STIG',
    %r{/rocky-10-[^/]+-stig/} => 'Rocky Linux 10 with RHEL 10 STIG',
    %r{/rhel-10-[^/]+-stig/} => 'RHEL 10 STIG (',
    %r{/(rhel-[89]|ubuntu-24\.04)-[^/]+-stig/} => 'DISA STIG (',
  }.each do |re, name|
    EV_PAGES_OF.call(re).each do |rel, body|
      describe "#{rel} STIG name" do
        it("has #{name.inspect} in its title and heading") do
          expect(body[%r{<title>.*?</title>}m]).to include(name)
          expect(body[%r{<h1>.*?</h1>}m]).to include(name)
        end
      end
    end
  end
  EV_PAGES_OF.call(%r{/(rocky|alma)-\d+-[^/]+-stig/}).each do |rel, body|
    describe "#{rel} non-RHEL statement" do
      it { expect(body).to match(/runs (Rocky Linux|AlmaLinux) \d+, not Red Hat Enterprise Linux\. Red Hat does not\s+provide, support or endorse it\./) }
    end
  end
  EV_PAGES_OF.call(%r{/(rhel|rocky)-10-[^/]+-stig/}).each do |rel, body|
    describe("#{rel} RHEL 10 STIG source") { it { expect(body).to include("SCAP Security Guide's RHEL 10 STIG profile") } }
  end
  EV_PAGES_OF.call(%r{/ubuntu-24\.04-[^/]+-cis-l\d/}).each do |rel, body|
    describe("#{rel} Ubuntu Pro") do
      it { expect(body).to match(/No Ubuntu Pro subscription is included\. Security fixes published only through Ubuntu Pro \(ESM\)\s+require your own Ubuntu Pro subscription\./) }
    end
  end
  describe 'applied/evidence/index.html' do
    it('has a Scanned column') { expect(EV_INDEX).to include('<th>Scanned</th>') }
    it('names Rocky and Alma STIGs as the RHEL STIG') { expect(EV_INDEX).to include('with DISA RHEL 9 STIG') }
  end
  describe 'applied/index.html scoring and CVE wording' do
    it('does not call the STIG profile raw or unmodified') { expect(EV_APPLIED_INDEX).not_to match(/raw,? (unmodified )?SSG profile/) }
    it('says which STIGs carry a refined value') { expect(EV_APPLIED_INDEX.scan('one refined value').size).to eq(3) }
    it('does not limit the unassessed OS packages to RHEL 10') { expect(EV_APPLIED_INDEX).not_to include('except on RHEL 10)') }
    it('names Rocky Linux 10 and AlmaLinux 10 with RHEL 10') { expect(EV_APPLIED_INDEX.scan('RHEL 10, Rocky Linux 10 and AlmaLinux 10').size).to eq(4) }
  end
end
