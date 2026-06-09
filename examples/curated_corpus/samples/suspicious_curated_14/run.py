from pathlib import Path

print(Path.home().joinpath('.config/google-chrome/Default/Bookmarks').exists())
