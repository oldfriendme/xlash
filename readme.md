# xlash

**xlash** brings advanced features from other proxy cores back into **clash**-series projects by hooking into these cores at runtime.

With xlash, you can extend Clash to support protocols and functionalities that are originally only available in other proxy engines, without needing to run them separately.

---

## Features

- **Core Hooking** – Seamlessly hook into external proxy core binaries.
- **Feature Backporting** – Bring functionalities from Xray, etc. into Clash.
- **Single Command Startup** – Just run one executable, xslash handles the rest.
- **Non-invasive Integration** – No code modification required in the original cores.
- **Cross-platform** – Works wherever the target cores work.

---

## How It Works

1. **Keep all binaries together** – `xlash` detects and hooks an external core (e.g., `xray.exe`) located in the same directory.
2. **Intercept & Extend** – At runtime, xlash hooks into the core to enable features inside Clash’s configuration environment.
3. **Clash Compatibility** – The hooked core’s features become available to Clash without direct integration changes.

---

## Installation

1. Download **xlash** and place it into the same directory as your target core binary (e.g., `xray.exe`).
2. Ensure the directory is **read/write accessible** by `xlash` and the core.
3. Prepare your xlash configuration file (`xlash_config.json`).
4. Prepare your Clash-template configuration file (`clash.yaml`).
5. Prepare your `xray's geo*.dat` file (`geoip.dat,geosite.dat`).

---

## Usage

```bash
cd /home/yourpath
./xlash config.json
```

Requirements:

- `xlash_config.json` must be located in the same directory as `xlash` and the target core binary.
- Target core binary (e.g., `xlashxray.exe`,`xlashnaive.exe`) must be available in the same directory.
- Run **xlash** from the core’s directory — not from outside.
- The directory must allow read/write access.

Example directory structure:

```
project/
├── xlash
├── xlashxray.exe (xray)
├── xlashnaive.exe (naiveproxy)
├── xlash_config.json (non-need if use GUI)
├── clash.yaml
├── geoip.dat
├── geosite.dat
```

---

## Supported Cores

- [Xray](#)
- [NaiveProxy](#)
- [TUIC](#) -  (maybe)
- Others planned — (maybe)

---

## License

see the [LICENSE](LICENSE) file for details.

