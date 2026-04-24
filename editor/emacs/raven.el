;;; raven.el --- Raven Security Scanner LSP integration for Emacs  -*- lexical-binding: t; -*-

;; Author: Raven Security
;; Version: 2.5.0
;; Package-Requires: ((lsp-mode "8.0.0") (emacs "27.1"))
;; Keywords: security, lsp, languages
;; URL: https://github.com/raven-security/raven

;;; Commentary:

;; This package provides LSP integration for the Raven security scanner.
;; It enables real-time security diagnostics, hover information, and
;; code actions (inline fixes) directly in Emacs.

;; Usage:
;;   (require 'raven)
;;   (add-hook 'go-mode-hook #'raven-lsp-setup)
;;   (add-hook 'python-mode-hook #'raven-lsp-setup)
;;   (add-hook 'js-mode-hook #'raven-lsp-setup)

;;; Code:

(require 'lsp-mode)
(require 'lsp-modeline)

(defgroup raven nil
  "Raven security scanner integration."
  :group 'tools
  :prefix "raven-")

(defcustom raven-command "raven"
  "Path to the raven executable."
  :type 'string
  :group 'raven)

(defcustom raven-lsp-args '("lsp")
  "Arguments to pass to raven for LSP mode."
  :type '(repeat string)
  :group 'raven)

(defcustom raven-enabled-filetypes
  '(go-mode
    js-mode js2-mode rjsx-mode typescript-mode tsx-mode
    python-mode pyvenv-mode
    java-mode
    php-mode
    c-mode c++-mode csharp-mode
    rust-mode
    ruby-mode enh-ruby-mode
    kotlin-mode
    swift-mode
    dart-mode
    elixir-mode
    scala-mode
    lua-mode
    solidity-mode
    sh-mode bash-ts-mode
    dockerfile-mode dockerfile-ts-mode
    terraform-mode hcl-mode
    yaml-mode yaml-ts-mode
    json-mode json-ts-mode)
  "Major modes where Raven LSP should be enabled."
  :type '(repeat symbol)
  :group 'raven)

(defvar raven--server-id 'raven-lsp
  "The LSP server ID for Raven.")

;;;###autoload
(defun raven-lsp-setup ()
  "Setup Raven LSP for the current buffer."
  (when (and (buffer-file-name)
             (raven--should-enable-p major-mode))
    (lsp)))

(defun raven--should-enable-p (mode)
  "Check if Raven should be enabled for MODE."
  (memq mode raven-enabled-filetypes))

;; Register Raven LSP client
(with-eval-after-load 'lsp-mode
  (add-to-list 'lsp-language-id-configuration '(go-mode . "go"))
  (add-to-list 'lsp-language-id-configuration '(js-mode . "javascript"))
  (add-to-list 'lsp-language-id-configuration '(js2-mode . "javascript"))
  (add-to-list 'lsp-language-id-configuration '(rjsx-mode . "javascriptreact"))
  (add-to-list 'lsp-language-id-configuration '(typescript-mode . "typescript"))
  (add-to-list 'lsp-language-id-configuration '(tsx-mode . "typescriptreact"))
  (add-to-list 'lsp-language-id-configuration '(python-mode . "python"))
  (add-to-list 'lsp-language-id-configuration '(java-mode . "java"))
  (add-to-list 'lsp-language-id-configuration '(php-mode . "php"))
  (add-to-list 'lsp-language-id-configuration '(c-mode . "c"))
  (add-to-list 'lsp-language-id-configuration '(c++-mode . "cpp"))
  (add-to-list 'lsp-language-id-configuration '(csharp-mode . "csharp"))
  (add-to-list 'lsp-language-id-configuration '(rust-mode . "rust"))
  (add-to-list 'lsp-language-id-configuration '(ruby-mode . "ruby"))
  (add-to-list 'lsp-language-id-configuration '(enh-ruby-mode . "ruby"))
  (add-to-list 'lsp-language-id-configuration '(kotlin-mode . "kotlin"))
  (add-to-list 'lsp-language-id-configuration '(swift-mode . "swift"))
  (add-to-list 'lsp-language-id-configuration '(dart-mode . "dart"))
  (add-to-list 'lsp-language-id-configuration '(elixir-mode . "elixir"))
  (add-to-list 'lsp-language-id-configuration '(scala-mode . "scala"))
  (add-to-list 'lsp-language-id-configuration '(lua-mode . "lua"))
  (add-to-list 'lsp-language-id-configuration '(solidity-mode . "solidity"))
  (add-to-list 'lsp-language-id-configuration '(sh-mode . "bash"))
  (add-to-list 'lsp-language-id-configuration '(bash-ts-mode . "bash"))
  (add-to-list 'lsp-language-id-configuration '(dockerfile-mode . "dockerfile"))
  (add-to-list 'lsp-language-id-configuration '(dockerfile-ts-mode . "dockerfile"))
  (add-to-list 'lsp-language-id-configuration '(terraform-mode . "terraform"))
  (add-to-list 'lsp-language-id-configuration '(hcl-mode . "terraform"))
  (add-to-list 'lsp-language-id-configuration '(yaml-mode . "yaml"))
  (add-to-list 'lsp-language-id-configuration '(yaml-ts-mode . "yaml"))
  (add-to-list 'lsp-language-id-configuration '(json-mode . "json"))
  (add-to-list 'lsp-language-id-configuration '(json-ts-mode . "json"))

  (lsp-register-client
   (make-lsp-client :new-connection (lsp-stdio-connection
                                     (lambda () (cons raven-command raven-lsp-args)))
                    :activation-fn (lsp-activate-on "go" "javascript" "javascriptreact"
                                                      "typescript" "typescriptreact"
                                                      "python" "java" "php"
                                                      "c" "cpp" "csharp" "rust" "ruby"
                                                      "kotlin" "swift" "dart" "elixir"
                                                      "scala" "lua" "solidity" "bash"
                                                      "dockerfile" "terraform" "yaml" "json")
                    :server-id 'raven-lsp
                    :priority -1  ;; Lower priority so language-specific LSPs take precedence
                    :add-on? t    ;; Run alongside other LSP servers
                    :initialization-options
                    (lambda ()
                      `(:raven (:enabled t
                                :command ,raven-command)))))

  ;; Register code action handlers
  (lsp-define-conditional-key lsp-command-map (kbd "C-c r a") "raven.fix"
    '(lsp-raven-fix))
  (lsp-define-conditional-key lsp-command-map (kbd "C-c r s") "raven.scan"
    '(lsp-raven-scan))
  (lsp-define-conditional-key lsp-command-map (kbd "C-c r b") "raven.baseline"
    '(lsp-raven-baseline)))

;;;###autoload
(defun lsp-raven-fix ()
  "Apply Raven's AI-powered fix for the current finding."
  (interactive)
  (lsp-execute-code-action-by-kind "quickfix.raven"))

;;;###autoload
(defun lsp-raven-scan ()
  "Run a Raven security scan on the current file."
  (interactive)
  (let ((default-directory (or (lsp-workspace-root) default-directory)))
    (compile (format "%s scan %s" raven-command (buffer-file-name)))))

;;;###autoload
(defun lsp-raven-baseline ()
  "Compare current scan against baseline."
  (interactive)
  (let ((default-directory (or (lsp-workspace-root) default-directory)))
    (compile (format "%s scan --baseline .raven-baseline.json" raven-command))))

;;;###autoload
(defun lsp-raven-ignore ()
  "Add a #raven-ignore annotation for the current finding."
  (interactive)
  (let ((code-action (lsp-code-actions-at-point
                       (list :diagnostics (lsp-cur-line-diagnostics)
                             :only ["source.raven.ignore"]))))
    (when code-action
      (lsp-execute-code-action (cl-first code-action)))))

;; Modeline integration
(defun raven-modeline ()
  "Return a string for the modeline showing Raven security status."
  (when-let* ((workspace (lsp-find-workspace 'raven-lsp (buffer-file-name)))
              (status (lsp--workspace-status workspace)))
    (format " 🔒%s" status)))

;; Flycheck integration (if used instead of flymake)
(with-eval-after-load 'flycheck
  (flycheck-define-checker raven
    "A security checker using Raven."
    :command ("raven" "scan" "--format" "json" source)
    :error-parser flycheck-parse-json
    :modes raven-enabled-filetypes
    :predicate (lambda () (buffer-file-name))))

(provide 'raven)
;;; raven.el ends here
