# SPDX-FileCopyrightText: 2026 Florian Mücke
# SPDX-License-Identifier: GPL-3.0-or-later
# https://github.com/fmuecke/egress-gate

.\out\egress-gate.exe start     # first run creates out\egress-gate.json; edit it, then start again

& "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" `
    --user-data-dir="$env:TEMP\edge-sandbox" `
    --proxy-server="http://127.0.0.1:8080" `
    --no-first-run
	
# --user-data-dir is required. If Edge is already running, it hands the new 
# window to the existing process and ignores --proxy-server. A separate 
# profile forces a new process and keeps your normal browsing out of the proxy.