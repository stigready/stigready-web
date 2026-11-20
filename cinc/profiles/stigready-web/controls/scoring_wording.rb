# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready#5901 (marketplace-legal, stigready/stigready#5909 review C2): how the site states what the score was measured
# against, and the STIG name of each product. "Unmodified" is true only for CIS on RHEL and Ubuntu and for Ubuntu STIG: Rocky
# Linux and AlmaLinux scans use the SSG RHEL datastream with an applicability-only change (decision 0050), and RHEL, Rocky and
# AlmaLinux STIG scans set one refined value. DISA publishes no Rocky, AlmaLinux or (in our content) RHEL 10 STIG.
require 'json'

ROOT_SW = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
PAGES_SW = (%w[index.html applied/index.html] + Dir.glob(File.join(ROOT_SW, 'blog', '*.html')).map { |f| f.delete_prefix("#{ROOT_SW}/") })
  .to_h { |rel| [rel, File.read(File.join(ROOT_SW, rel))] }
SCOPE_SW = 'Unmodified for CIS on RHEL and Ubuntu, and for Ubuntu STIG. Rocky Linux and AlmaLinux scans use the SSG RHEL ' \
           'datastream with an applicability-only change. RHEL, Rocky Linux and AlmaLinux STIG scans set one refined value ' \
           "(the image's own local accounts), shown on each"
OLD_SW = [/raw,? (unmodified )?SSG profile/, /raw SSG profile/, 'unmodified for CIS and Ubuntu STIG',
          'DISA STIG (FIPS mode) for RHEL 8, 9 and 10',
          # #5909 legal W1: the listings' CVE words (0092: no RHEL 10 scan; 0176: Rocky/Alma 10 OS packages not assessed)
          'OS packages are not fully assessed on RHEL 10', 'CVE scan (not RHEL 10)', 'except RHEL 10 has a CVE scan',
          # #5909 legal W2: the product class is "STIG", not "DISA STIG" (Rocky, Alma and RHEL 10 STIGs are not DISA's)
          /\bor DISA STIG remediat/, 'Full DISA STIG or CIS',
          # stigready/stigready#5904 (review/marketing on #5915, image-security on #5909): the CVE scan claim without the Go-binary
          # scope. 46 of the 56 versions live on 2026-11-17 have no Go-binary result; their SSM agent carries fixable HIGH Go CVEs.
          'AlmaLinux 10, OS packages not assessed)']
CVE_SW = 'CVE scan (except RHEL 10; on Rocky Linux 10 and AlmaLinux 10, OS packages not assessed; on most current versions, ' \
         "language packages such as the AWS Systems Manager agent's Go binaries not assessed)"
# "most current versions" is true while more than half of the evidence records (config/applied-evidence.json, one per live
# version) have no Go-binary (lang-pkgs) result. When that stops being true the control fails and the clause must be redone.
EV_CELLS_SW = JSON.parse(File.read(File.join(ROOT_SW, 'config', 'applied-evidence.json')))['cells']

control 'web-scoring-wording-01' do
  impact 1.0
  title 'Site pages state the scoring scope per #5901 C2 and name each STIG per OS (stigready#5901)'
  desc 'No page says "raw"/"raw, unmodified SSG profile", the superseded "unmodified for CIS and Ubuntu STIG", or calls every
        STIG product "DISA STIG". Every page that says "Unmodified for CIS" says it in the full C2 form; /applied/ and the home
        page carry it where they describe scoring. catalog.json names no Rocky, AlmaLinux or RHEL 10 STIG product "DISA STIG".
        Each pattern is checked against a fixture it must catch.'

  OLD_SW.each do |pat|
    describe "superseded wording #{pat.inspect}" do
      it('is caught by its own fixture') do
        fixture = pat.is_a?(Regexp) ? 'scored against the raw, unmodified SSG profile in-build; raw SSG profile; CIS or DISA STIG remediation' : "x #{pat} y"
        expect(fixture.match?(pat.is_a?(Regexp) ? pat : Regexp.new(Regexp.escape(pat)))).to eq(true)
      end
      re = pat.is_a?(Regexp) ? pat : Regexp.new(Regexp.escape(pat))
      PAGES_SW.each { |rel, body| it("does not appear on #{rel}") { expect(body.match?(re)).to eq(false) } }
    end
  end
  PAGES_SW.each do |rel, body|
    next unless body.include?('Unmodified for CIS')
    describe(rel) do
      it('states the C2 scope in full every time') do
        expect(body.scan('Unmodified for CIS').size).to eq(body.gsub(%r{<a [^>]*>(evidence page)</a>}, '\1').scan(SCOPE_SW).size)
      end
    end
  end
  describe 'pages that describe scoring' do
    it('/applied/ states the C2 scope 3 times') { expect(PAGES_SW['applied/index.html'].scan(SCOPE_SW).size).to eq(3) }
    it('the home page states it 4 times') do
      expect(PAGES_SW['index.html'].gsub(%r{<a [^>]*>(evidence page)</a>}, '\1').scan(SCOPE_SW).size).to eq(4)
    end
  end
  describe 'CVE scan scope in the listings\' words (#5909 W1)' do
    it('/applied/ states it 3 times') { expect(PAGES_SW['applied/index.html'].scan(CVE_SW).size).to eq(3) }
    it('the home page states it 4 times (JSON-LD, Evidence card, pricing bullet, FAQ)') { expect(PAGES_SW['index.html'].scan(CVE_SW).size).to eq(4) }
    %w[blog/base-vs-applied.html blog/openscap-evidence-bundles.html blog/graviton-arm64-hardened-amis.html].each do |rel|
      it("#{rel} states it once") { expect(PAGES_SW.fetch(rel).scan(CVE_SW).size).to eq(1) }
    end
    PAGES_SW.each do |rel, body|
      it("#{rel} never names the evidence-bundle CVE scan without the Go-binary scope") do
        expect(body.scan(/CVE scan \(except RHEL 10/).size).to eq(body.scan(CVE_SW).size)
      end
    end
  end
  describe 'the Go-binary clause matches the live evidence (#5904)' do
    unscanned = EV_CELLS_SW.count { |c| !(c.dig('cve', 'classes') || {}).key?('lang-pkgs') }
    it("most current versions have no Go-binary result (#{unscanned} of #{EV_CELLS_SW.size})") do
      expect(EV_CELLS_SW.size).to be >= 1
      expect(unscanned * 2).to be > EV_CELLS_SW.size
    end
  end
  describe 'catalog.json STIG names' do
    rows = JSON.parse(File.read(File.join(ROOT_SW, 'catalog.json')))['products'].select { |p| p['profile'] == 'stig' }
    it('covers the STIG rows') { expect(rows.size).to be >= 18 }
    rows.each do |p|
      want = case p['os_key']
             when 'rhel-8', 'rhel-9', 'ubuntu-24.04' then 'DISA STIG'
             when /^(rocky|alma)-([89])$/ then "DISA RHEL #{Regexp.last_match(2)} STIG"
             when 'rhel-10', 'rocky-10' then 'RHEL 10 STIG (Red Hat SSG content)'
             end
      it("#{p['os_key']} #{p['arch']} is named #{want.inspect}") { expect(p['benchmark']).to eq(want) }
    end
  end
end
