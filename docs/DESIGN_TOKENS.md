# Design Tokens

Shared design vocabulary for the desktop (Qt 6 Widgets) and Android
(Jetpack Compose) apps. Both must stay in sync:

- Desktop themes: `gui/dark.qss`, `gui/light.qss`
- Android theme: `app/src/main/java/com/securepasswd/mgmt/ui/theme/` (`Color.kt`, `Theme.kt`)

## Brand palettes

### Dark — Nord

| Token | Hex | Desktop usage | Compose role |
|---|---|---|---|
| `background` | `#2E3440` | `QMainWindow`/`QDialog` bg | `background` |
| `surface` | `#3B4252` | lists, inputs, toolbar, cards | `surface` |
| `surfaceHover` | `#434C5E` | item hover | `surfaceVariant` |
| `outline` | `#4C566A` | borders, pressed button bg | `outline` |
| `onSurface` | `#D8DEE9` | text | `onBackground`/`onSurface` |
| `primary` | `#88C0D0` | progress accent, focus ring, checked | `primary` |
| `primaryHover` | `#5E81AC` | button hover | `secondary` |
| `primaryActive` | `#81A1C1` | button pressed | `tertiary` |
| `success` | `#A3BE8C` | success card border | — |
| `error` | `#BF616A` | error card border | — |
| `textDisabled` | `#7B88A1` | disabled controls | — |

### Light — Snow Storm + app-icon accent

| Token | Hex | Desktop usage | Compose role |
|---|---|---|---|
| `background` | `#ECEFF4` | window bg | `background` |
| `surface` | `#FFFFFF` | lists, inputs, cards | `surface` |
| `surfaceHover` | `#E5E9F0` | item hover | `surfaceVariant` |
| `outline` | `#D8DEE9` | borders | `outline` |
| `onSurface` | `#434343` | text | `onBackground`/`onSurface` |
| `primary` | `#d97dbc` | buttons, selection, progress | `primary` |
| `primaryHover` | `#c77575` | button hover | `secondary` |
| `primaryActive` | `#8b8484` | button pressed | `tertiary` |
| `textDisabled` | `#A5A9B0` | disabled controls | — |

## Shape scale

| Token | Radius | Desktop | Compose (`Shapes`) |
|---|---|---|---|
| `shape.small` | 4–6px | list items, small controls | `extraSmall`/`small` |
| `shape.medium` | 8px | buttons, inputs, menus | `small`/`medium` |
| `shape.large` | 12px | cards (`#statusCard`, `#summaryCard`) | `medium` |

## Palette registry

Three palettes ship on both platforms; each provides a dark and a light
variant. The user's palette choice is remembered; **dark/light still
follows the OS** unless explicitly toggled.

| Palette id | Dark | Light |
|---|---|---|
| `nord` (default) | Nord | Snow Storm + app-icon accent |
| `dracula` | Dracula | Dracula Paper |
| `solarized` | Solarized Dark | Solarized Light |

Desktop: selection lives in the toolbar palette menu, persisted as
`QSettings("palette")`; token sets in `gui/themes.cpp`, substitution
template in `gui/theme_template.qss`.
Android: selection lives in the vault overflow menu ("Color Palette"),
persisted as the `palette` shared-preferences key; schemes in
`ui/theme/Theme.kt`.

## Sync port preference

The desktop sync dialog exposes a validated port field (1–65535,
default 33261, persisted as `QSettings("sync_port")`). The listener
re-binds while no client is connected; when the port is busy a random
port is used for that session. The Android app needs no setting — the
port always arrives inside the `vsync2:` QR payload.

## Behavior

- **Theme default:** follow the OS color scheme on both platforms. The
  desktop toolbar theme button opens a tri-state menu (**Follow System /
  Light / Dark**, persisted as `QSettings("ui_mode")`); Android's vault
  theme button **cycles** system → light → dark → system (persisted as the
  `ui_mode` shared-pref; the legacy `dark_theme` boolean migrates once).
  The legacy binary "theme" toggle is retired — an override is no longer a
  one-way trap.
- **Dark theme = Nord** on both platforms; light theme uses the app-icon
  pink accent on both.

## Shared copy (user-visible strings)

- Feature name: **“Vault Sync”** (window titles, top bars, error messages).
- Status vocabulary, in order: *Connected → Authenticating → Authenticated /
  Exchanging vaults → Merging → Vault Sync complete.*
- Result summary format (single line, `·` separators):
  `Added X · Updated Y · Deleted Z · Conflicts W`
