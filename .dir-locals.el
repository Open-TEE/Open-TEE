;;; Directory Local Variables for Open-TEE -*- lexical-binding: t; -*-
;;; For more information see (info "(emacs) Directory Variables")

((nil
  ;; Project root marker
  . ((projectile-project-root . ".")
     (project-vc-ignores . ("build/" ".devenv/"))))

 (c-mode
  . ((mode . c)
     ;; C style settings
     (c-basic-offset . 8)
     (tab-width . 8)
     (indent-tabs-mode . t)
     ;; Use Linux kernel style (matches project style)
     (c-file-style . "linux")
     ;; LSP/eglot configuration - use compile_commands.json
     (eglot-workspace-configuration
      . (:clangd (:compilationDatabasePath "build")))
     ;; For lsp-mode users
     (lsp-clients-clangd-args . ("--compile-commands-dir=build"
                                 "--background-index"
                                 "--clang-tidy"
                                 "--header-insertion=never"))
     ;; Flycheck clang checker
     (flycheck-clang-include-path . ("."
                                     "libtee/include"
                                     "emulator/include"
                                     "build"))
     ;; compile command using CMake preset
     (compile-command . "cmake --build --preset dev")))

 (c++-mode
  . ((c-basic-offset . 8)
     (tab-width . 8)
     (indent-tabs-mode . t)
     (c-file-style . "linux")))

 ;; CMake files
 (cmake-mode
  . ((cmake-tab-width . 4)
     (indent-tabs-mode . nil))))
