# Lokaler vendor-cache

`fetch-vendor.sh <amd64|arm64>` legt hier die gepinnten camoufox-,
uBlock-origin- und python-runtime-artefakte ab. binärdateien werden nicht als
quelltext gepflegt. `make-release.sh` verweigert einen build, wenn der cache
fehlt oder nicht zu `browser-assets.lock` und `requirements.lock` passt.
