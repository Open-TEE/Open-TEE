# SPDX-FileCopyrightText: 2023 Technology Innovation Institute (TII)
# SPDX-FileCopyrightText: 2020-2023 Eelco Dolstra and the flake-compat contributors
#
# SPDX-License-Identifier: MIT
# This file originates from:
# https://github.com/nix-community/flake-compat
# This file provides backward compatibility to nix < 2.4 clients
(import ./default.nix {}).shell
