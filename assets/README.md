# Upstream runtime assets

No driver or Mac application archive is redistributed by this repository.
Run `.venv/bin/python tools/fetch_assets.py` after setup. It downloads the unchanged
v2.6.4 Mac companion and NVIDIA package directly from
https://github.com/nullmoth/nvidia-macos-driver/releases/tag/v2.6.4 and checks
pinned SHA256 values before publication to this local directory. These assets
retain their original terms and notices. Generated Apple recovery images are
never committed or included in this repository.
