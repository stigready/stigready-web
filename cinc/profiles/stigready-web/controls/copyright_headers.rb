# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: LicenseRef-StigReady-Proprietary
# Copyright-header guard (owner, 2026-10-26: "we need to get everything copyrighted"). Every tracked source file
# carries "SPDX-FileCopyrightText: <year> StigReady" and an SPDX-License-Identifier allowed in .spdx-headers, unless
# .spdx-headers excludes it as generated or third-party; and no tracked file names an organisation this org's files
# must never name. The assertion runs scripts/check-spdx-headers.py, which also writes the header (--fix).
# The negative case proves the guard fails: a scratch repository with one unheadered file must be rejected.
require 'open3'
require 'tmpdir'
require 'fileutils'

CR_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
CR_SCRIPT = File.join(CR_ROOT, 'scripts', 'check-spdx-headers.py')
CR_OUT, CR_STATUS = Open3.capture2e('python3', CR_SCRIPT, '--root', CR_ROOT)

CR_NEG_OUT, CR_NEG_RC = Dir.mktmpdir('spdx-guard') do |dir|
  FileUtils.cp(File.join(CR_ROOT, '.spdx-headers'), dir)
  File.write(File.join(dir, 'new_tool.sh'), "#!/bin/sh\necho no header\n")
  Open3.capture2e('git', '-C', dir, 'init', '-q')
  Open3.capture2e('git', '-C', dir, 'add', '-A')
  out, st = Open3.capture2e('python3', CR_SCRIPT, '--root', dir)
  [out, st.exitstatus]
end

control 'web-copyright-headers' do
  impact 1.0
  title 'Every source file carries the StigReady SPDX copyright header, and no file names a forbidden organisation'
  desc 'scripts/check-spdx-headers.py output:', CR_OUT
  describe 'check-spdx-headers exit status' do
    subject { CR_STATUS.exitstatus }
    it { should eq 0 }
  end
end

control 'web-copyright-headers-guard-fails' do
  impact 1.0
  title 'The copyright-header guard rejects a new source file without the header'
  describe 'check-spdx-headers on a scratch repository with one unheadered file' do
    subject { CR_NEG_RC }
    it { should eq 1 }
  end
  describe 'its report' do
    subject { CR_NEG_OUT }
    it { should match(/new_tool\.sh/) }
  end
end
