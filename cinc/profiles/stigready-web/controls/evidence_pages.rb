# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# The public evidence summary pages under applied/evidence/.
# - web-evidence-pages-match-input: every page is exactly what scripts/build-evidence-pages.py writes from
#   config/applied-evidence.json and catalog.json (no hand edit, no stale page), each SBOM download is the signed SBOM,
#   and every available Applied row of catalog.json has a page for the version it sells.
# - web-evidence-pages-guard-fails: the generator refuses inputs that would publish an untrue or internal page.
require 'fileutils'
require 'json'
require 'open3'
require 'tmpdir'
require 'zlib'

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
  # An output directory holding only the SBOM downloads (the generator reads them for Go-binary packages), no pages, so
  # a case can only pass on the problem it names.
  out_dir = File.join(EV_TMP, "#{name}-out", 'applied', 'evidence')
  Dir.glob(File.join(EV_ROOT, 'applied', 'evidence', '*', 'v*', 'sbom.cdx.json.gz')).each do |f|
    to = File.join(out_dir, f.delete_prefix(File.join(EV_ROOT, 'applied', 'evidence', '')))
    FileUtils.mkdir_p(File.dirname(to))
    FileUtils.cp(f, to)
  end
  args = ['--check', '--input', path, '--out', out_dir]
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
# The evidence-bundle CVE claim, as scoring_wording.rb CVE_SW states it (controls load in name order, so not shared).
EV_CVE_SW = 'CVE scan (except RHEL 10; on Rocky Linux 10 and AlmaLinux 10, OS packages not assessed; on most listed versions, ' \
            "language packages such as the AWS Systems Manager agent's Go binaries not assessed)"
# stigready#6049 / #6047 review H1: records whose CVE matching did not run (genuine RHEL 10 under the scan's gate deferral,
# until Grype took over its OS packages on 2026-10-31; build-evidence-pages.py CVE_MATCHING_DEFERRED). Their pages must show
# no CVE count at all, Go binaries included.
EV_DEFERRED_UNTIL = { 'rhel-10' => '2026-10-31' }.freeze
EV_RECORD_OF = EV_DOC['cells'].to_h { |c| ["applied/evidence/#{c['cell']}/v#{c['version']}/index.html", c] }
EV_DEFERRED = ->(c) { (u = EV_DEFERRED_UNTIL[c['os_key']]) && c.dig('cve', 'created_at').to_s[0, 10] < u }
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
  title 'The evidence page generator refuses an input that would publish an untrue or internal page, for the right reason'
  desc 'Each case runs --check against an empty output directory and asserts the problem the guard must name, so a ' \
       'case cannot pass on "pages differ" when its guard is gone.'
  first_cis = ->(d) { d['cells'].find { |c| c['profile'] != 'stig' } }
  first = ->(d) { d['cells'].first }
  rhel9 = ->(d) { d['cells'].find { |c| c['os_key'] == 'rhel-9' } }
  # name => [mutation of config/applied-evidence.json, mutation of catalog.json or nil, the problem it must report]
  cases = {
    'a score that differs from catalog.json' =>
      [->(d) { first.call(d)['scorecard']['score'] += 0.1 }, nil, /catalog\.json score \S+ is not the signed score/],
    'an extract problem' =>
      [->(d) { first.call(d)['problems'] = ['bundle version 1.0.0 is not 1.0.2'] }, nil, /extract problem: bundle version/],
    'an unverified signature' =>
      [->(d) { first.call(d)['signature']['cosign_verified'] = nil }, nil, /signature not verified at extraction/],
    'a bundle not matched to the live listing' =>
      [->(d) { first.call(d)['ami_matches_live_listing'] = false }, nil, /not matched to the live listing's AMI/],
    'FIPS on a CIS image' => [->(d) { first_cis.call(d)['fips'] = true }, nil, /FIPS True on profile cis-l\d/],
    'an exemption class with no public label' =>
      [->(d) { first.call(d)['exemptions'].first['class'] = 'new-class' }, nil, /exemption class 'new-class' has no public label/],
    'a failing rule with no exemption' =>
      [->(d) { first.call(d)['exemptions'].pop }, nil, /\d+ failing rules but \d+ exemptions/],
    'an AMI id in published text' =>
      [->(d) { first.call(d)['exemptions'].first['why'] += ' See ami-0123456789abcdef0.' }, nil,
       /published text names 'ami-0123456789abcdef0'/],
    'an internal record in published text' =>
      [->(d) { first.call(d)['exemptions'].first['why'] += ' Decision 0070.' }, nil, /published text names 'Decision 0070'/],
    'a GovCloud claim in published text' =>
      [->(d) { first.call(d)['exemptions'].first['customer_action'] += ' GovCloud too.' }, nil, /published text names 'GovCloud'/],
    'a version that catalog.json does not sell' =>
      [->(d) { first.call(d)['version'] = '9.9.9' }, nil, /catalog\.json sells v1\./],
    'an extract made without the live-listing check' =>
      [->(d) { d['live_listings_checked'] = false }, nil, /without the live-listing or signature check/],
    'a missing version' => [->(d) { d['cells'].shift }, nil, /available in catalog\.json but has no evidence record/],
    # numbers, cells, versions, listing URLs and Trivy results
    'zero OS-package findings on a release where zero was never reviewed' =>
      [->(d) { rhel9.call(d)['cve']['classes']['os-pkgs']['findings'] = 0 }, nil, /zero OS-package findings on rhel-9/],
    'a CVE scan with no OS-package result' =>
      [->(d) { first.call(d)['cve']['classes'].delete('os-pkgs') }, nil, /has no OS-package result/],
    'a Trivy result class with no public wording' =>
      [->(d) { first.call(d)['cve']['classes']['secret'] = first.call(d)['cve']['classes']['os-pkgs'] }, nil,
       /result class with no public wording/],
    'markup in a rule count' => [->(d) { first.call(d)['scorecard']['pass'] = '<b>1</b>' }, nil, /scorecard\.pass is not a number/],
    'a string in a CVE count' =>
      [->(d) { first.call(d)['cve']['classes']['os-pkgs']['distinct']['high'] = '1' }, nil,
       /cve\.os-pkgs\.distinct\.high is not a number/],
    'a fraction for the SBOM component count' =>
      [->(d) { first.call(d)['sbom']['components'] = 3.5 }, nil, /sbom\.components is not a number/],
    'a string for the manifest file count' =>
      [->(d) { first.call(d)['signature']['manifest_files'] = '22' }, nil, /signature\.manifest_files is not a number/],
    'a cell that is not os_key-arch-profile' =>
      [->(d) { first.call(d)['cell'] = '../../index' }, nil, /cell is not <os_key>-<arch>-<profile>/],
    'a version that is not N.N.N' => [->(d) { first.call(d)['version'] = '1.0.2"><script>' }, nil, /version is not N\.N\.N/],
    'a catalog.json listing URL outside AWS Marketplace' =>
      [nil, ->(cat) { cat['products'].find { |p| p['line'] == 'stigapplied' }['marketplace_url'] = 'https://example.com/pp/x' },
       %r{marketplace_url is not under https://aws\.amazon\.com/marketplace/}],
    'a Go-binary package in the SBOM but a lang-pkgs result that detected nothing' =>
      [->(d) {
        c = d['cells'].find { |x| x['cell'] == 'rhel-9-x86_64-stig' }
        c['cve']['classes']['lang-pkgs'] = JSON.parse(JSON.generate(c['cve']['classes']['os-pkgs'])).merge('packages' => 0)
      }, nil, /the SBOM lists amazon-ssm-agent but the lang-pkgs result detected no packages/],
    'a RHEL 10 scan dated after its CVE matching stopped being deferred' =>
      [->(d) { d['cells'].find { |x| x['os_key'] == 'rhel-10' }['cve']['created_at'] = '2026-11-18T01:00:00Z' }, nil,
       /a rhel-10 scan dated 2026-11-18, on or after 2026-10-31.*review what it assessed/],
    # severity filter
    'a CVE scan with no recorded severity filter' =>
      [->(d) { first.call(d)['cve'].delete('severity_filter') }, nil, /severity filter is not recorded/],
    'a count for a severity the scan did not cover' =>
      [->(d) { rhel9.call(d)['cve']['classes']['os-pkgs']['distinct']['low'] = 2 }, nil,
       /os-pkgs has low findings outside the scan's severity filter/],
  }
  cases.each do |name, (mutate, mutate_catalog, want)|
    out, status = EV_MUTATED.call(name.gsub(/\W+/, '-'), mutate, mutate_catalog)
    describe "build-evidence-pages.py --check on #{name}" do
      it('exits 1') { expect(status).to eq(1) }
      it("reports #{want.inspect} and writes nothing (output: #{out.strip[0, 300]})") do
        expect(out).to match(want)
        expect(out).to include('nothing written')
      end
    end
  end

  # A stray or stale SBOM in the output is reported by --check and removed by write mode. Each step gets a fresh
  # copy of the site, because a control file can be evaluated more than once.
  fresh = lambda do |name|
    root = File.join(EV_TMP, name)
    FileUtils.rm_rf(root)
    FileUtils.mkdir_p(File.join(root, 'applied'))
    FileUtils.cp_r(File.join(EV_ROOT, 'applied', 'evidence'), File.join(root, 'applied'))
    FileUtils.cp(File.join(EV_ROOT, 'sitemap.xml'), File.join(root, 'sitemap.xml'))
    [File.join(root, 'applied', 'evidence'), File.join(root, 'sitemap.xml')]
  end
  stray_in = lambda do |site|
    f = File.join(site, 'rhel-9-x86_64-stig', 'v0.0.1', 'sbom.cdx.json.gz')
    FileUtils.mkdir_p(File.dirname(f))
    File.binwrite(f, 'stale')
    f
  end
  # `it` blocks run after the control body, so each step keeps its own result variables.
  site, sitemap = fresh.call('stray-check')
  stray_in.call(site)
  out1, status1 = EV_RUN.call('--check', '--out', site, '--sitemap', sitemap)
  describe 'build-evidence-pages.py --check with a stale SBOM in the output' do
    it('exits 1') { expect(status1).to eq(1) }
    it("names it as stale (output: #{out1.strip[0, 300]})") { expect(out1).to match(%r{v0\.0\.1/sbom\.cdx\.json\.gz \(stale: no record\)}) }
  end
  site, sitemap = fresh.call('stray-write')
  stray = stray_in.call(site)
  out2, status2 = EV_RUN.call('--out', site, '--sitemap', sitemap)
  gone2 = !File.exist?(stray)
  describe 'build-evidence-pages.py (write) with a stale SBOM in the output' do
    it("exits 0 (output: #{out2.strip[0, 300]})") { expect(status2).to eq(0) }
    it('removes it') { expect(gone2).to eq(true) }
  end
  site, sitemap = fresh.call('sitemap-check')
  File.write(sitemap, File.read(sitemap).sub(%r{\n  <url>\n    <loc>https://stigready\.com/applied/evidence/rhel-9-x86_64-stig/</loc>.*?</url>}m, ''))
  out3, status3 = EV_RUN.call('--check', '--out', site, '--sitemap', sitemap)
  describe 'build-evidence-pages.py --check with a page missing from sitemap.xml' do
    it('exits 1') { expect(status3).to eq(1) }
    it("names it (output: #{out3.strip[0, 300]})") { expect(out3).to include('sitemap.xml: missing https://stigready.com/applied/evidence/rhel-9-x86_64-stig/') }
  end
end

control 'web-evidence-pages-say-what-was-assessed' do
  impact 1.0
  title 'Evidence pages name each STIG honestly and never print a CVE count Trivy could not assess'
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
      deferred = EV_DEFERRED.call(EV_RECORD_OF.fetch(rel, {}))
      it('counts OS and language packages separately') { expect(body).to include('counted separately') } unless deferred
      it('never says the counts are OS packages only') { expect(body).not_to include('in the installed OS packages') }
      it('shows commands as code, not literal backticks') { expect(body).not_to include('`') }
      # the shipped scans ran with severity CRITICAL,HIGH,MEDIUM; no column for a severity never scanned.
      it('shows no Low column') { expect(body).not_to include('<th>Low</th>') }
      it('says Low was not scanned for') { expect(body).to match(/Low( and Unrated)? severity CVEs were not scanned for and are not counted/) } unless deferred
      # an exemption with no STIG ID says so instead of a dash.
      it('never shows a bare dash for a STIG ID') { expect(body).not_to include('<td>—</td>') }
      # A scan with no lang-pkgs result did not assess the Go binaries (amazon-ssm-agent is in every SBOM).
      it('says language packages were not assessed when it shows no language counts') do
        expect(body.include?('<h3>Language packages (Go binaries)</h3>') ||
               body.include?('Go binaries): not assessed by this scan.')).to eq(true)
      end
      it('states no cause for an unassessed OS') { expect(body).not_to include('vulnerability data does not cover') }
    end
  end
  # stigready-web#99 review (image-security, deferred to the scan-gap issue): a page whose scan counted Go binaries but whose signed SBOM
  # omits amazon-ssm-agent says so, or a CVE tool fed that SBOM misses the agent's CVEs. Read from the SBOM download itself.
  EV_PAGES.each do |rel, body|
    sbom = File.join(EV_ROOT, File.dirname(rel), 'sbom.cdx.json.gz')
    next unless File.file?(sbom)
    names = JSON.parse(Zlib::GzipReader.open(sbom, &:read))['components'].to_a.map { |x| x['name'] }
    rec = EV_RECORD_OF.fetch(rel)
    want = rec.dig('cve', 'classes').key?('lang-pkgs') && !names.include?('amazon-ssm-agent')
    describe "#{rel} SBOM note" do
      it("#{want ? 'says' : 'does not say'} the SBOM omits amazon-ssm-agent") do
        expect(body.include?('This SBOM does not list the amazon-ssm-agent package')).to eq(want)
      end
      # a deferred record counted nothing, so its note must not point at counts "under CVE scan above" (#6047 H1)
      it('claims no Go counts it does not show') { expect(body).not_to include('counted under CVE scan above') } if EV_DEFERRED.call(rec)
    end
  end
  # stigready#6049 (#6047 review H1): a record whose CVE matching did not run shows no CVE table, Go binaries included.
  deferred_pages = EV_PAGES.select { |rel, _| EV_DEFERRED.call(EV_RECORD_OF.fetch(rel, {})) }
  describe 'deferred-scan records found' do
    it('covers the 6 live RHEL 10 versions') { expect(deferred_pages.size).to eq(6) }
  end
  deferred_pages.each do |rel, body|
    describe "#{rel} (CVE matching deferred)" do
      it('shows no CVE count table') { expect(body).not_to include('<td>CVEs found') }
      it('shows no Go-binary counts') { expect(body).not_to include('<h3>Language packages (Go binaries)</h3>') }
      it('says CVE matching was not run') { expect(body).to include('CVE matching was not run') }
      it('says the Go binaries were not assessed') { expect(body).to include('Go binaries): not assessed by this scan.') }
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
    it('names Rocky and Alma STIGs as the RHEL STIG, without a leading "with"') do
      expect(EV_INDEX).to include('<td>DISA RHEL 9 STIG</td>')
      expect(EV_INDEX).not_to include('<td>with ')
    end
  end
  describe 'applied/index.html scoring and CVE wording' do
    it('does not call the STIG profile raw or unmodified') { expect(EV_APPLIED_INDEX).not_to match(/raw,? (unmodified )?SSG profile/) }
    it('says which STIGs carry a refined value') { expect(EV_APPLIED_INDEX.scan('one refined value').size).to eq(3) }
    it('does not limit the unassessed OS packages to RHEL 10') { expect(EV_APPLIED_INDEX).not_to include('except on RHEL 10)') }
    # stigready/stigready#5909 legal W1: the listings' words. RHEL 10 has no CVE scan (0092); Rocky and AlmaLinux 10 OS packages
    # are not assessed (0176). The "CVE counts (...)" line describes the pages.
    # #6047 review H1: RHEL 10 pages show no CVE counts at all (stigready#6049), so the line says "none for RHEL 10".
    it('says the RHEL 10 pages show no CVE counts where it lists page contents') { expect(EV_APPLIED_INDEX.scan('CVE counts (none for RHEL 10; OS packages except on Rocky Linux 10 and AlmaLinux 10;').size).to eq(1) }
    it('states the CVE scan scope, with the Go-binary clause (#5904), 3 times') { expect(EV_APPLIED_INDEX.scan(EV_CVE_SW).size).to eq(3) }
    it('says the evidence pages show Go-binary counts only where assessed') { expect(EV_APPLIED_INDEX).to include("the AWS Systems Manager agent's Go binaries only where they were assessed)") }
    it('no longer says "not fully assessed"') { expect(EV_APPLIED_INDEX).not_to include('not fully assessed') }
  end
end
