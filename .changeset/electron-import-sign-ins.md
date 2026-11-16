---
"domicile": minor
"@domicile-desktop/engine": minor
"@domicile-desktop/electron-host": minor
---

An Electron app's first run on the engine brings its sign-ins over from its own Electron: its site storage and cookies are copied into its partition before its first window, so it opens signed in. The app's own profile is left as it was.
