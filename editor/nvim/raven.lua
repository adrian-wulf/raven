-- Raven LSP configuration for Neovim
-- Add this to your Neovim config (init.lua or lspconfig setup)

local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Define Raven LSP if not already defined
if not configs.raven then
  configs.raven = {
    default_config = {
      cmd = { 'raven', 'lsp' },
      filetypes = {
        'go', 'javascript', 'typescript', 'javascriptreact', 'typescriptreact',
        'python', 'java', 'php', 'c', 'cpp', 'cs', 'rust', 'ruby',
        'kotlin', 'swift', 'dart', 'elixir', 'scala', 'lua',
        'solidity', 'sh', 'bash', 'dockerfile', 'terraform', 'yaml', 'json',
      },
      root_dir = lspconfig.util.root_pattern('.git', 'go.mod', 'package.json', 'requirements.txt', 'Gemfile', 'pom.xml', 'Cargo.toml', 'composer.json', 'Podfile', 'pubspec.yaml'),
      settings = {},
    },
  }
end

-- Setup Raven LSP
lspconfig.raven.setup({
  on_attach = function(client, bufnr)
    -- Enable code action lightbulb
    vim.api.nvim_create_autocmd({ 'CursorHold', 'CursorHoldI' }, {
      buffer = bufnr,
      callback = function()
        vim.lsp.buf.code_action({
          context = { only = { 'quickfix', 'source.fixAll' } },
          range = { start = { vim.fn.line('.'), 0 }, ['end'] = { vim.fn.line('.'), 0 } },
        })
      end,
    })

    -- Keymaps
    local opts = { buffer = bufnr, silent = true }
    vim.keymap.set('n', '<leader>ra', vim.lsp.buf.code_action, opts)          -- Code action / inline fix
    vim.keymap.set('n', '<leader>rf', ':lua vim.lsp.buf.code_action({ context = { only = { "source.fixAll.raven" } } })<CR>', opts)
    vim.keymap.set('n', '<leader>rs', ':lua vim.lsp.buf.code_action({ context = { only = { "source.scan.raven" } } })<CR>', opts)
    vim.keymap.set('n', 'K', vim.lsp.buf.hover, opts)                         -- Hover info
    vim.keymap.set('n', '<leader>rn', vim.lsp.buf.rename, opts)              -- Rename
  end,
  capabilities = vim.lsp.protocol.make_client_capabilities(),
})

-- Optional: Auto-fix on save
vim.api.nvim_create_autocmd('BufWritePost', {
  pattern = { '*.go', '*.js', '*.ts', '*.py', '*.java', '*.php', '*.rs', '*.rb', '*.c', '*.cpp', '*.cs', '*.kt', '*.swift', '*.dart', '*.ex', '*.scala', '*.lua', '*.sol', '*.sh', '*.tf', '*.yaml', '*.json' },
  callback = function(args)
    vim.lsp.buf.code_action({
      context = { only = { 'source.fixAll.raven' }, diagnostics = {} },
      apply = true,
    })
  end,
})
