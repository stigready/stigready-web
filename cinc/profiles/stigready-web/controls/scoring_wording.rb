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
OLD_SW = [/raw,? (unmodified )?SSG profile/, /raw SSG profile/, 'unmodified for CIS and Ubuntu STIG', 'except RHEL 10 has a CVE scan',
          'DISA STIG (FIPS mode) for RHEL 8, 9 and 10']

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
        fixture = pat.is_a?(Regexp) ? 'scored against the raw, unmodified SSG profile in-build; raw SSG profile' : "x #{pat} y"
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
