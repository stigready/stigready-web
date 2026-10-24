# claude-agents#152: every page loads its scripts from this site (pinned under assets/vendor/) and no stylesheet from a
# third party but Google Fonts, never the Tailwind Play CDN, never an @latest URL, and carries a Content-Security-Policy
# meta tag. Ported from validate-site.py check 8
# (decision 0003: CINC asserts, Python never does).

WEB_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
# The published pages: every tracked .html file (git ls-files, as validate-site.py walks the tree).
WEB_PAGES = Dir.chdir(WEB_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }
# The one third-party script the site allows (Google Analytics); anything else is self-hosted.
ALLOWED_SCRIPT_HOSTS = ['https://www.googletagmanager.com/gtag/js'].freeze
# The one third-party stylesheet the site allows (Google Fonts, as the CSP's style-src names it).
ALLOWED_STYLESHEET_HOSTS = ['https://fonts.googleapis.com/css2'].freeze
# A <script> or <link> start tag. A quoted attribute value may hold '>', so the tag ends at the first unquoted one.
WEB_TAG = /<(script|link)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/i
# One attribute: double-quoted, single-quoted or unquoted value, or a bare name (stigready-web#67: the former
# src="..." pattern let <script src='https://evil.example/x.js'> and src=https://... through).
WEB_ATTR = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/

# A module, not top-level defs: a control block cannot see methods defined at the top of its file.
module WebAssets
  module_function

  def attrs(text)
    text.scan(WEB_ATTR).to_h { |name, dq, sq, uq| [name.downcase, (dq || sq || uq || '').strip] }
  end

  # The URLs a page loads code or styles from: <script src> and <link rel=stylesheet href>.
  def loads(body)
    scripts = []
    sheets = []
    body.scan(WEB_TAG) do |tag, text|
      a = attrs(text)
      if tag.casecmp?('script')
        scripts << a['src'] if a.key?('src')
      elsif a['rel'].to_s.downcase.split.include?('stylesheet') && a.key?('href')
        sheets << a['href']
      end
    end
    [scripts, sheets]
  end

  def external?(url)
    url.downcase.start_with?('http://', 'https://', '//')
  end
end

WEB_BODIES = WEB_PAGES.to_h { |rel| [rel, File.binread(File.join(WEB_ROOT, rel)).force_encoding('UTF-8').scrub('')] }

control 'web-pages-found' do
  impact 1.0
  title 'The pinned-asset controls see the site pages'
  desc 'A control over zero pages asserts nothing (git ls-files must list the .html files).'
  describe 'tracked .html pages' do
    subject { WEB_PAGES }
    it { should include 'index.html' }
  end
end

control 'web-no-third-party-scripts' do
  impact 1.0
  title 'No Play CDN, @latest, unpinned third-party script or third-party stylesheet on any page'
  WEB_PAGES.each do |rel|
    body = WEB_BODIES[rel]
    scripts, sheets = WebAssets.loads(body)
    third_party = scripts.select { |src| WebAssets.external?(src) && !src.start_with?(*ALLOWED_SCRIPT_HOSTS) }
    third_party_css = sheets.select { |href| WebAssets.external?(href) && !href.start_with?(*ALLOWED_STYLESHEET_HOSTS) }
    describe "#{rel} third-party script src (self-host under assets/vendor/, pinned)" do
      subject { third_party }
      it { should be_empty }
    end
    describe "#{rel} third-party stylesheet href (self-host under assets/, or build into site.css)" do
      subject { third_party_css }
      it { should be_empty }
    end
    describe "#{rel} (Tailwind Play CDN: link /assets/css/site.css from scripts/build-css.sh)" do
      subject { body }
      it { should_not include 'cdn.tailwindcss.com' }
    end
    describe "#{rel} (an @latest asset URL: pin the version)" do
      subject { body }
      it { should_not include '@latest' }
    end
  end
end

control 'web-csp-on-every-page' do
  impact 1.0
  title 'Every page carries a Content-Security-Policy meta tag'
  WEB_PAGES.each do |rel|
    describe "#{rel} Content-Security-Policy meta tag" do
      subject { WEB_BODIES[rel] }
      it { should include 'http-equiv="Content-Security-Policy"' }
    end
  end
end
