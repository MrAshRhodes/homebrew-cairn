cask "cairn" do
  version "0.1.0"
  sha256 "78009970464f5ce81441dffca80dbf9872cee261d0c1c9b8e07c140267f16cee"

  url "https://github.com/MrAshRhodes/cairn/releases/download/v#{version}/Cairn-#{version}-universal.zip"
  name "Cairn"
  desc "Experimental local-first browser with Spaces, vertical tabs and Boosts"
  homepage "https://github.com/MrAshRhodes/cairn"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on macos: :sonoma

  app "Cairn.app"

  zap trash: [
    "~/Library/Application Support/Cairn",
    "~/Library/Caches/io.github.mrashrhodes.cairn",
    "~/Library/HTTPStorages/io.github.mrashrhodes.cairn",
    "~/Library/Preferences/io.github.mrashrhodes.cairn.plist",
    "~/Library/Saved Application State/io.github.mrashrhodes.cairn.savedState",
    "~/Library/WebKit/io.github.mrashrhodes.cairn",
  ]

  caveats <<~EOS
    Cairn is ad-hoc signed and is not notarized by Apple, so macOS Gatekeeper
    blocks it the first time you open it. To approve it, open Cairn once, then
    go to System Settings > Privacy & Security, scroll to the Security section
    and click "Open Anyway" for Cairn.

    Cairn is an experimental developer preview.
  EOS
end
