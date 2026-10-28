# Builds dist\FC6CoopPatcher.exe, a single-file windowed build of src\fc6_coop_patcher.py
python -m pip install --upgrade pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name FC6CoopPatcher `
    --paths src --distpath dist --workpath build --specpath build src\fc6_coop_patcher.py
