class Macroscope < Formula
  desc "Local-first macOS evidence and remediation engine for humans and AI agents"
  homepage "https://github.com/manthedan/macroscope"
  url "https://github.com/manthedan/macroscope/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "4c7ee40606974b6fa8b0c248d2bb14d692a625ad90c84874b2910d331c3303f4"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system bin/"macroscope", "--version"
  end
end
