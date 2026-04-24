class Raven < Formula
  desc "AI-native security scanner with 1900+ rules and 10 LLM providers"
  homepage "https://github.com/raven-security/raven"
  url "https://github.com/raven-security/raven/archive/refs/tags/v2.5.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"
  head "https://github.com/raven-security/raven.git", branch: "master"

  depends_on "go" => :build
  depends_on "tree-sitter" => :build

  def install
    ENV["CGO_ENABLED"] = "1"
    system "go", "build", *std_go_args(ldflags: "-w -s"), "."

    # Install rules
    pkgshare.install "rules"
    pkgshare.install Dir["editor"]
    pkgshare.install Dir["hooks"]

    # Bash completion
    bash_completion.install "completions/raven.bash" if File.exist?("completions/raven.bash")
    zsh_completion.install "completions/_raven" if File.exist?("completions/_raven")
    fish_completion.install "completions/raven.fish" if File.exist?("completions/raven.fish")
  end

  def caveats
    <<~EOS
      Raven has been installed! 🦅

      To get started:
        raven scan                    # Scan current directory
        raven scan --help             # See all options

      For AI-powered fixes, set an API key:
        export OPENROUTER_API_KEY=your-key
        raven fix-ai

      Pre-commit hook:
        raven install-hook            # Install Git pre-commit hook

      Editor integrations:
        VS Code:   editor/vscode/
        Neovim:    editor/nvim/raven.lua
        Zed:       editor/zed/settings.json
        Emacs:     editor/emacs/raven.el
    EOS
  end

  test do
    # Test version
    assert_match "raven version", shell_output("#{bin}/raven version 2>&1 || true")

    # Test basic scan
    (testpath/"test.js").write "eval(userInput);"
    output = shell_output("#{bin}/raven scan test.js 2>&1 || true")
    assert_match "eval", output
  end
end
