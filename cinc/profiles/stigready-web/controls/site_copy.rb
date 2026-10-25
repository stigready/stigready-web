# Site copy invariants (decision 0003: CINC asserts).
# - Decision 0094 (claude-agents#153): no page uses "CIS Hardened AMI/Image(s)" as a label for our images (CIS
#   Hardened Images is CIS's own product), and every page carries the non-affiliation and trademark sentences.
# - claude-agents#154: one availability story. catalog.json is the source (publish-catalog.py marks a row available
#   only while the Marketplace reconcile reports its listing Public on the current AMI). While any row is available
#   no page may say the listings are still rolling out or that listing URLs are not published, and both catalog
#   tables render each row's availability.
require 'json'

COPY_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
COPY_PAGES = Dir.chdir(COPY_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }
COPY_BODIES = COPY_PAGES.to_h { |rel| [rel, File.binread(File.join(COPY_ROOT, rel)).force_encoding('UTF-8').scrub('')] }
COPY_CATALOG = JSON.parse(File.read(File.join(COPY_ROOT, 'catalog.json')))
COPY_AVAILABLE = COPY_CATALOG.fetch('products', []).count { |p| p['availability'] == 'available' }

# "CIS hardened AMI", "CIS Hardened Image(s)", any case or spacing (markup entities aside).
CIS_PRODUCT_LABEL = /\bCIS\s+hardened\s+(?:AMIs?|images?)\b/i
NON_AFFILIATION = 'Not affiliated with or endorsed by DISA, DoD, NIST, CIS, Red Hat, or Canonical.'
CIS_TRADEMARK = 'CIS® and CIS Benchmarks™ are trademarks of the Center for Internet Security, Inc.'
# Phrases that say no listing is live, or that listing URLs are withheld.
NOT_LIVE_PHRASES = [
  /listings?\s+(?:are\s+)?(?:rolling|roll)\s+out/i,
  /until\s+public\s+subscribe/i,
  /do\s+not\s+publish\s+per-SKU/i,
  /per-SKU\s+listing\s+URLs/i,
  /Marketplace\s+is\s+coming\s+soon/i
].freeze

control 'web-copy-pages-found' do
  impact 1.0
  title 'The site-copy controls see the pages and the catalog'
  describe 'tracked .html pages' do
    subject { COPY_PAGES }
    it { should include 'index.html' }
    it { should include 'applied/index.html' }
  end
  describe 'catalog.json products' do
    subject { COPY_CATALOG.fetch('products', []) }
    it { should_not be_empty }
  end
end

control 'web-no-cis-product-name' do
  impact 1.0
  title 'No page labels our images with the CIS Hardened Images product name (decision 0094)'
  desc 'Say "hardened to the CIS Benchmark" or "CIS Benchmark L1/L2 AMI" instead.'
  COPY_PAGES.each do |rel|
    describe "#{rel} uses of the CIS Hardened product name" do
      subject { COPY_BODIES[rel].scan(CIS_PRODUCT_LABEL) }
      it { should be_empty }
    end
  end
end

control 'web-non-affiliation-on-every-page' do
  impact 1.0
  title 'Every page carries the non-affiliation and CIS trademark sentences (decision 0094 point 3)'
  COPY_PAGES.each do |rel|
    describe "#{rel} non-affiliation and trademark sentences" do
      subject { COPY_BODIES[rel] }
      it { should include NON_AFFILIATION }
      it { should include CIS_TRADEMARK }
    end
  end
end

control 'web-one-availability-story' do
  impact 1.0
  title 'Page copy agrees with catalog.json availability, and both catalog tables show it per row (claude-agents#154)'
  if COPY_AVAILABLE.positive?
    COPY_PAGES.each do |rel|
      describe "#{rel} 'not live yet' wording while #{COPY_AVAILABLE} catalog rows are available" do
        subject { NOT_LIVE_PHRASES.flat_map { |re| COPY_BODIES[rel].scan(re) } }
        it { should be_empty }
      end
    end
  end
  index = COPY_BODIES.fetch('index.html', '')
  %w[renderBase renderApplied].each do |fn|
    body = index[/function #{fn}\(\)\s*\{.*?\n    \}\n/m].to_s
    describe "index.html #{fn}() renders availability for each row" do
      subject { body }
      it { should include 'availabilityCell(p)' }
    end
  end
end
