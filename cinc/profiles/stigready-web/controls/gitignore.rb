# SPDX-FileCopyrightText: 2026 StigReady
# SPDX-License-Identifier: MIT
# stigready-web#84: .gitignore listed `.ci-venv/`, and a pattern with a trailing slash matches only a directory, so a
# local `.ci-venv` symlink to a venv elsewhere was committed (#81's first commit). A scratch repository holding this
# repo's .gitignore gets `.ci-venv` once as a directory and once as a symlink; git must ignore both.
require 'open3'
require 'tmpdir'
require 'fileutils'

GI_ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))
GI_FILE = File.join(GI_ROOT, '.gitignore')

def gi_ignored?(kind)
  Dir.mktmpdir('gitignore') do |dir|
    FileUtils.cp(GI_FILE, File.join(dir, '.gitignore')) if File.file?(GI_FILE)
    Open3.capture2e('git', '-C', dir, 'init', '-q')
    if kind == :symlink
      FileUtils.mkdir_p(File.join(dir, 'elsewhere'))
      File.symlink('elsewhere', File.join(dir, '.ci-venv'))
    else
      FileUtils.mkdir_p(File.join(dir, '.ci-venv', 'bin'))
    end
    _out, st = Open3.capture2e('git', '-C', dir, 'check-ignore', '-q', '--', '.ci-venv')
    st.exitstatus == 0
  end
end

GI_DIRECTORY_IGNORED = gi_ignored?(:directory)
GI_SYMLINK_IGNORED = gi_ignored?(:symlink)

control 'web-gitignore-ci-venv' do
  impact 1.0
  title '.gitignore ignores the validate virtualenv whether .ci-venv is a directory or a symlink (stigready-web#84)'
  describe '.ci-venv as a directory' do
    subject { GI_DIRECTORY_IGNORED }
    it { should eq true }
  end
  describe '.ci-venv as a symlink' do
    subject { GI_SYMLINK_IGNORED }
    it { should eq true }
  end
end
