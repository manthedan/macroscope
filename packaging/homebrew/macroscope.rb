class Macroscope < Formula
  desc "Local-first macOS developer environment auditor"
  homepage "https://github.com/manthedan/macroscope"
  url "https://github.com/manthedan/macroscope/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "426231c7aa743a4245ef7f2d0629faf1c0405379ec12c824e04c7d875768cae6"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/macroscope", "--version"
  end
end
