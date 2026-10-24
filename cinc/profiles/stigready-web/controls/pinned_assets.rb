# claude-agents#152: every page loads its scripts from this site (pinned under assets/vendor/), never the Tailwind
# Play CDN, never an @latest URL, and carries a Content-Security-Policy meta tag. Ported from validate-site.py check 8
# (decision 0003: CINC asserts, Python never does).

WEB_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
# The published pages: every tracked .html file (git ls-files, as validate-site.py walks the tree).
WEB_PAGES = Dir.chdir(WEB_ROOT) { IO.popen(%w[git ls-files -z -- *.html], &:read).split("\0").sort }
# The one third-party script the site allows (Google Analytics); anything else is self-hosted.
ALLOWED_SCRIPT_HOSTS = ['https://www.googletagmanager.com/gtag/js'].freeze
SCRIPT_SRC = /<script\b[^>]*\bsrc="([^"]+)"/i

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
  title 'No Play CDN, @latest or unpinned third-party script on any page'
  WEB_PAGES.each do |rel|
    body = WEB_BODIES[rel]
    third_party = body.scan(SCRIPT_SRC).flatten.select do |src|
      src.start_with?('http://', 'https://', '//') && !src.start_with?(*ALLOWED_SCRIPT_HOSTS)
    end
    describe "#{rel} third-party script src (self-host under assets/vendor/, pinned)" do
      subject { third_party }
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
