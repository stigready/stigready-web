# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready-web#85: gitleaks generic-api-key reads "class_tokens_sha256": "<64 hex>" on line 6 of
# assets/css/site.css.stamp.json as an API key (the key contains "token"). The value is the SHA-256 of the class tokens
# on the public pages (scripts/css_stamp.py, recomputed by web-site-css-fresh), not a secret. It is accepted by its
# exact .gitleaksignore fingerprint (file:rule:line, cairn-scan's --no-git scan). This control keeps the ignore file to
# that one entry and fails if line 6 of the stamp stops being that digest, so the entry cannot come to cover anything
# else without changing this control in review.

SUP_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
SUP_IGNORE = File.join(SUP_ROOT, '.gitleaksignore')
SUP_STAMP = File.join(SUP_ROOT, 'assets', 'css', 'site.css.stamp.json')
SUP_ALLOWED = ['assets/css/site.css.stamp.json:generic-api-key:6'].freeze

control 'web-scan-suppressions' do
  impact 1.0
  title '.gitleaksignore holds only the CSS stamp digest fingerprint, and that line is still the digest'
  desc 'The only accepted gitleaks finding is generic-api-key on assets/css/site.css.stamp.json:6, the
        class_tokens_sha256 digest (stigready-web#85). No other fingerprint, file, rule or line is ignored.'

  entries = File.file?(SUP_IGNORE) ? File.readlines(SUP_IGNORE, chomp: true).map(&:strip).reject { |l| l.empty? || l.start_with?('#') } : []
  line6 = File.file?(SUP_STAMP) ? File.readlines(SUP_STAMP, chomp: true)[5].to_s : ''

  describe '.gitleaksignore entries' do
    it("are exactly #{SUP_ALLOWED.inspect}") { expect(entries).to eq(SUP_ALLOWED) }
  end

  describe 'line 6 of assets/css/site.css.stamp.json' do
    it('is the class_tokens_sha256 digest: 64 lowercase hex, nothing else') do
      expect(line6).to match(/\A  "class_tokens_sha256": "[0-9a-f]{64}",\z/)
    end
  end
end
