# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# claude-agents#152: every page loads its scripts from this site (pinned under assets/vendor/) and no stylesheet from a
# third party but Google Fonts, never the Tailwind Play CDN, never an @latest URL, and carries a Content-Security-Policy
# meta tag whose script-src and style-src admit no other third party (stigready-web#67). Ported from validate-site.py
# check 8 (decision 0003: CINC asserts, Python never does).
require 'digest'

WEB_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
# The published pages: every tracked .html file (git ls-files, as validate-site.py walks the tree).
WEB_PAGES = Dir.chdir(WEB_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }
# The one third-party script the site allows (Google Analytics); anything else is self-hosted.
ALLOWED_SCRIPT_HOSTS = ['https://www.googletagmanager.com/gtag/js'].freeze
# The one third-party stylesheet the site allows (Google Fonts, as the CSP's style-src names it).
ALLOWED_STYLESHEET_HOSTS = ['https://fonts.googleapis.com/css2'].freeze
# stigready-web#67: the only sources a page's CSP may give script-src and style-src. Keywords are matched as written
# (lower case). script-src has no 'unsafe-inline': each inline script is admitted by its 'sha256-...' hash
# (CSP_HASH_SOURCE, checked against the page by web-csp-inline-scripts-hashed). style-src keeps 'unsafe-inline' for
# now (inline style attributes). The hosts are exactly ALLOWED_SCRIPT_HOSTS and ALLOWED_STYLESHEET_HOSTS. Anything
# else fails, including *, data:, blob:, a scheme alone (https:) and any other host.
CSP_SCRIPT_SOURCES = ["'self'", 'https://www.googletagmanager.com/gtag/js'].freeze
CSP_HASH_SOURCE = %r{\A'sha256-[A-Za-z0-9+/]+=*'\z}
CSP_STYLE_SOURCES = ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'].freeze
# A <meta> start tag (same quoting rule as WEB_TAG).
WEB_META = /<meta\b((?:[^>"']|"[^"]*"|'[^']*')*)>/i
# A <script> or <link> start tag. A quoted attribute value may hold '>', so the tag ends at the first unquoted one.
WEB_TAG = /<(script|link)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/i
# One attribute: double-quoted, single-quoted or unquoted value, or a bare name (stigready-web#67: the former
# src="..." pattern let <script src='https://evil.example/x.js'> and src=https://... through).
WEB_ATTR = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/
# A whole <script> element: its start-tag attributes and its text.
WEB_SCRIPT_ELEMENT = %r{<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</script\s*>}im
# Any start tag: name and attribute text.
WEB_START_TAG = /<([a-z][a-z0-9-]*)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/i

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

  # Each Content-Security-Policy meta tag's policy as {directive => [sources]}. A browser enforces every such tag, so
  # each is checked on its own. Directive names are case-insensitive; the first occurrence of a directive wins, as in
  # the CSP spec.
  def csp_policies(body)
    body.scan(WEB_META).filter_map do |(text)|
      a = attrs(text)
      next unless a['http-equiv'].to_s.casecmp?('content-security-policy')

      a['content'].to_s.split(';').each_with_object({}) do |part, policy|
        name, *sources = part.strip.split(/\s+/)
        policy[name.downcase] ||= sources unless name.nil?
      end
    end
  end

  # The sources in a directive that are not in the allowed list (a missing directive has none). With hashes: true a
  # 'sha256-...' source is allowed too (script-src).
  def disallowed(sources, allowed, hashes: false)
    Array(sources).reject { |src| allowed.include?(src) || (hashes && CSP_HASH_SOURCE.match?(src)) }
  end

  # The CSP source for each inline executable <script> on a page: no src attribute and not a JSON type. A browser
  # hashes the element's text exactly as written between the tags (scripts/csp-script-hashes.py writes the same).
  def inline_script_hashes(body)
    body.scan(WEB_SCRIPT_ELEMENT).filter_map do |text, content|
      a = attrs(text)
      next if a.key?('src') || a['type'].to_s.downcase.match?(%r{\Aapplication/(?:ld\+)?json\z})

      "'sha256-#{[Digest::SHA256.digest(content.encode('UTF-8'))].pack('m0')}'"
    end.uniq
  end

  # Inline event-handler attributes (onclick=...) on any start tag: CSP without 'unsafe-inline' blocks them.
  def event_handlers(body)
    body.scan(WEB_START_TAG).flat_map do |name, text|
      next [] if name.casecmp?('script')

      text.scan(WEB_ATTR).map(&:first).select { |n| n.downcase.match?(/\Aon[a-z]+\z/) }.map { |n| "<#{name} #{n}>" }
    end
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
  title 'Every page carries a Content-Security-Policy meta tag whose script-src and style-src admit no third party'
  desc 'stigready-web#67 (review/security on #62): assert what the policy says, not only that the tag is present. ' \
       'script-src must be stated, with no third-party host but the allowed analytics one, no * and no data:; ' \
       'style-src may add only fonts.googleapis.com. This closes the parser evasions the src/href controls miss, ' \
       'because the browser enforces the policy whatever the markup looks like.'
  WEB_PAGES.each do |rel|
    policies = WebAssets.csp_policies(WEB_BODIES[rel])
    describe "#{rel} Content-Security-Policy meta tags" do
      subject { policies }
      it { should_not be_empty }
    end
    policies.each_with_index do |policy, i|
      describe "#{rel} CSP #{i + 1} script-src (stated, not left to default-src)" do
        subject { policy }
        it { should include 'script-src' }
      end
      describe "#{rel} CSP #{i + 1} script-src sources not allowed (no 'unsafe-inline', third party, * or data:)" do
        subject { WebAssets.disallowed(policy['script-src'], CSP_SCRIPT_SOURCES, hashes: true) }
        it { should be_empty }
      end
      describe "#{rel} CSP #{i + 1} style-src sources not allowed (only fonts.googleapis.com is added)" do
        subject { WebAssets.disallowed(policy.fetch('style-src', policy['default-src']), CSP_STYLE_SOURCES) }
        it { should be_empty }
      end
    end
  end
end

control 'web-csp-inline-scripts-hashed' do
  impact 1.0
  title "Inline scripts run by hash, not 'unsafe-inline': each page's script-src lists exactly its inline scripts"
  desc "stigready-web#67 (review/security on #62): with 'unsafe-inline' an injected inline script would run. Each " \
       "inline <script>'s sha256 must be in that page's script-src, no listed hash may be stale, and no element may " \
       'carry an inline event handler (the browser blocks them). After editing an inline script run ' \
       'scripts/csp-script-hashes.py --write.'
  WEB_PAGES.each do |rel|
    body = WEB_BODIES[rel]
    want = WebAssets.inline_script_hashes(body)
    WebAssets.csp_policies(body).each_with_index do |policy, i|
      listed = Array(policy['script-src']).select { |src| CSP_HASH_SOURCE.match?(src) }
      describe "#{rel} CSP #{i + 1} script-src 'unsafe-inline'" do
        subject { Array(policy['script-src']) }
        it { should_not include "'unsafe-inline'" }
      end
      describe "#{rel} CSP #{i + 1} inline scripts whose hash script-src does not list" do
        subject { want - listed }
        it { should be_empty }
      end
      describe "#{rel} CSP #{i + 1} script-src hashes that match no inline script on the page" do
        subject { listed - want }
        it { should be_empty }
      end
    end
    describe "#{rel} inline event-handler attributes" do
      subject { WebAssets.event_handlers(body) }
      it { should be_empty }
    end
  end
end
