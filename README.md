# inskam-n3-pro-re

Safe local reverse-engineering toolkit for the INSKAM N3 Pro / UseeEar WiFi endoscope.

## Files

- `cam_tui.py` — curses-based control/monitor tool with conservative defaults.
- `test_cam_tui.py` — offline unit tests for packet build/decode logic.

## Run

```bash
python3 cam_tui.py --ip 192.168.1.1 --wifi UseeEar-37f1e
```

## Test

```bash
python3 -m unittest -v test_cam_tui.py
```

## Safety

- Dangerous scan is disabled unless `--enable-dangerous` is supplied.
- Default behavior uses only confirmed commands and low-rate maintenance traffic.
