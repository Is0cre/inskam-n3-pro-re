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


<img width="1152" height="1536" alt="3" src="https://github.com/user-attachments/assets/08d69e25-19f4-4e90-aaff-7d76df62767d" />
<img width="1152" height="1536" alt="2" src="https://github.com/user-attachments/assets/87c6f005-7f04-4be8-b84c-ea80595d3b47" />
<img width="1536" height="1152" alt="1" src="https://github.com/user-attachments/assets/6f5f814b-b557-44ba-b3d6-8cfaa154cf17" />
