class Macroscope < Formula
  desc "Local-first macOS developer environment auditor"
  homepage "https://github.com/manthedan/macroscope"
  url "https://github.com/manthedan/macroscope/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "fbdeffbc6229a253766be25012c34dbb7bc7a007e84f4d5e5a9f4656aa69d312"
  license "MIT"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system bin/"macroscope", "--version"
  end
end
